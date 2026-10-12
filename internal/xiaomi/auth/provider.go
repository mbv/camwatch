package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"camwatch/internal/domain"
)

// Provider implements ports.AuthProvider.
type Provider struct {
	mu          sync.Mutex
	sid         string
	sessionFile string
	username    string
	password    string
	userIDHint  string
	passToken   string
	cloud        *Cloud
}

func NewProvider(sid, sessionFile, username, password, userID, passToken string) *Provider {
	if sid == "" {
		sid = "xiaomiio"
	}
	return &Provider{
		sid:         sid,
		sessionFile: sessionFile,
		username:    username,
		password:    password,
		userIDHint:  userID,
		passToken:   passToken,
	}
}

func (p *Provider) Cloud() *Cloud {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cloud
}

func (p *Provider) LoadSession(ctx context.Context) (domain.TokenBundle, error) {
	_ = ctx
	b, err := os.ReadFile(p.sessionFile)
	if err != nil {
		return domain.TokenBundle{}, err
	}
	var t domain.TokenBundle
	if err := json.Unmarshal(b, &t); err != nil {
		return domain.TokenBundle{}, err
	}
	return t, nil
}

func (p *Provider) SaveSession(ctx context.Context, t domain.TokenBundle) error {
	_ = ctx
	dir := filepath.Dir(p.sessionFile)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	t.UpdatedAt = time.Now().UTC()
	b, err := json.MarshalIndent(t, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p.sessionFile, b, 0o600)
}

// newCloud builds a Cloud that reuses the persisted device id, so passport
// sees the same "device" across logins and passToken stays valid for it.
func (p *Provider) newCloud(ctx context.Context) *Cloud {
	c := NewCloud(p.sid)
	if t, err := p.LoadSession(ctx); err == nil {
		c.SetDeviceID(t.DeviceID)
	}
	return c
}

func (p *Provider) Login(ctx context.Context, user, pass string) (domain.TokenBundle, error) {
	c := p.newCloud(ctx)
	if err := c.Login(user, pass); err != nil {
		return domain.TokenBundle{}, err
	}
	t := BundleFromCloud(c)
	p.mu.Lock()
	p.cloud = c
	p.mu.Unlock()
	_ = p.SaveSession(ctx, t)
	return t, nil
}

func (p *Provider) Refresh(ctx context.Context, t domain.TokenBundle) (domain.TokenBundle, error) {
	c := NewCloud(p.sid)
	c.SetDeviceID(t.DeviceID)
	if t.PassToken != "" && t.UserID != "" && !strings.HasPrefix(strings.TrimSpace(t.PassToken), "{") {
		if err := c.LoginWithToken(t.UserID, t.PassToken); err != nil {
			return domain.TokenBundle{}, err
		}
	} else {
		raw, err := json.Marshal(map[string]string{
			"userId":       t.UserID,
			"cUserId":      t.CUserID,
			"serviceToken": t.ServiceToken,
			"ssecurity":    t.Ssecurity,
		})
		if err != nil {
			return domain.TokenBundle{}, err
		}
		if err := c.LoginWithSession(t.UserID, string(raw)); err != nil {
			return domain.TokenBundle{}, err
		}
	}
	out := BundleFromCloud(c)
	if out.PassToken == "" {
		out.PassToken = t.PassToken
	}
	p.mu.Lock()
	p.cloud = c
	p.mu.Unlock()
	_ = p.SaveSession(ctx, out)
	return out, nil
}

// Invalidate drops the cached in-memory cloud so the next EnsureValid
// re-derives credentials from disk (LoadSession) or pass_token/username
// instead of returning the process's original in-memory snapshot forever.
// EnsureValid never expires or revalidates that snapshot on its own (there is
// no TTL check), so without calling this first, an eventlist-auth-failure
// retry hands Refresh the exact bundle that just failed — even if an operator
// has since refreshed data/session.json on disk per the documented
// re-auth workflow (README: extract-session-from-har.py), the running
// process would never notice without a restart.
func (p *Provider) Invalidate() {
	p.mu.Lock()
	p.cloud = nil
	p.mu.Unlock()
}

func (p *Provider) EnsureValid(ctx context.Context) (domain.TokenBundle, error) {
	p.mu.Lock()
	if p.cloud != nil {
		t := BundleFromCloud(p.cloud)
		p.mu.Unlock()
		return t, nil
	}
	p.mu.Unlock()

	if t, err := p.LoadSession(ctx); err == nil && t.ServiceToken != "" && t.Ssecurity != "" {
		c := NewCloud(p.sid)
		if err := ApplyBundle(c, t); err != nil {
			return domain.TokenBundle{}, err
		}
		p.mu.Lock()
		p.cloud = c
		p.mu.Unlock()
		return BundleFromCloud(c), nil
	}
	if p.userIDHint != "" && p.passToken != "" {
		return p.Refresh(ctx, domain.TokenBundle{UserID: p.userIDHint, PassToken: p.passToken})
	}
	if p.username != "" && p.password != "" {
		return p.Login(ctx, p.username, p.password)
	}
	return domain.TokenBundle{}, fmt.Errorf("auth: no session or credentials")
}

func BundleFromCloud(c *Cloud) domain.TokenBundle {
	sec := ""
	if len(c.Ssecurity()) > 0 {
		sec = base64.StdEncoding.EncodeToString(c.Ssecurity())
	}
	uid, pass := c.UserToken()
	cookies := c.Cookies()
	return domain.TokenBundle{
		UserID:       uid,
		PassToken:    pass,
		ServiceToken: cookieValue(cookies, "serviceToken"),
		CUserID:      cookieValue(cookies, "cUserId"),
		Ssecurity:    sec,
		Cookies:      cookies,
		SID:          c.SID(),
		DeviceID:     c.DeviceID(),
		UpdatedAt:    time.Now().UTC(),
	}
}

func ApplyBundle(c *Cloud, t domain.TokenBundle) error {
	sec, err := base64.StdEncoding.DecodeString(t.Ssecurity)
	if err != nil {
		return err
	}
	c.SetDeviceID(t.DeviceID)
	c.userID = t.UserID
	c.passToken = t.PassToken
	c.ssecurity = sec
	if t.Cookies != "" {
		c.cookies = t.Cookies
	} else {
		c.cookies = fmt.Sprintf("userId=%s; cUserId=%s; serviceToken=%s", t.UserID, t.CUserID, t.ServiceToken)
	}
	return nil
}

func cookieValue(cookies, name string) string {
	for _, part := range strings.Split(cookies, ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, name+"=") {
			return strings.TrimPrefix(part, name+"=")
		}
	}
	return ""
}
