package auth

import (
	"context"
	"errors"
	"fmt"

	"camwatch/internal/domain"
)

// Prompter answers the challenges passport may raise during a password login.
type Prompter interface {
	// Captcha receives the captcha image (JPEG/PNG) and returns the typed code.
	Captcha(img []byte) (string, error)
	// Code receives where the verification ticket was sent and returns it.
	Code(maskedPhone, maskedEmail string) (string, error)
}

// maxChallenges bounds captcha/verify rounds so a wrong answer cannot loop forever.
const maxChallenges = 5

// LoginInteractive performs a full password login, answering captcha and
// phone/e-mail verification through pr, then persists the session (including
// passToken and deviceId) so later 401s are repaired by Refresh without a human.
func (p *Provider) LoginInteractive(ctx context.Context, user, pass string, pr Prompter) (domain.TokenBundle, error) {
	c := p.newCloud(ctx)
	err := c.Login(user, pass)
	for i := 0; err != nil; i++ {
		var le *LoginError
		if !errors.As(err, &le) {
			return domain.TokenBundle{}, err
		}
		if i >= maxChallenges {
			return domain.TokenBundle{}, fmt.Errorf("xiaomi: too many login challenges")
		}
		switch {
		case len(le.Captcha) > 0:
			code, perr := pr.Captcha(le.Captcha)
			if perr != nil {
				return domain.TokenBundle{}, perr
			}
			err = c.LoginWithCaptcha(code)
		case le.VerifyPhone != "" || le.VerifyEmail != "":
			code, perr := pr.Code(le.VerifyPhone, le.VerifyEmail)
			if perr != nil {
				return domain.TokenBundle{}, perr
			}
			err = c.LoginWithVerify(code)
		default:
			return domain.TokenBundle{}, errors.New("xiaomi: unrecognised login challenge")
		}
	}
	t := BundleFromCloud(c)
	if t.ServiceToken == "" || t.Ssecurity == "" {
		return domain.TokenBundle{}, errors.New("xiaomi: login finished without serviceToken/ssecurity")
	}
	p.mu.Lock()
	p.cloud = c
	p.mu.Unlock()
	if err := p.SaveSession(ctx, t); err != nil {
		return t, fmt.Errorf("save session: %w", err)
	}
	return t, nil
}
