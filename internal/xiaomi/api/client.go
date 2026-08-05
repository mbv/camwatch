package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"camwatch/internal/domain"
	"camwatch/internal/xiaomi/auth"
	xcrypto "camwatch/internal/xiaomi/crypto"
)

// Client talks to Mi Home + smartcamera business APIs.
type Client struct {
	Auth *auth.Provider
}

func New(a *auth.Provider) *Client { return &Client{Auth: a} }

func BaseURL(region string) string {
	switch region {
	case "de", "i2", "ru", "sg", "us":
		return "https://" + region + ".api.io.mi.com/app"
	}
	return "https://api.io.mi.com/app"
}

func CameraAPIHost(region string) string {
	if region == "" {
		region = "de"
	}
	return "https://" + region + ".app.business.smartcamera.api.io.mi.com"
}

func (c *Client) cloud() (*auth.Cloud, error) {
	cl := c.Auth.Cloud()
	if cl == nil {
		return nil, fmt.Errorf("api: auth cloud not ready; call EnsureValid first")
	}
	return cl, nil
}

// MissGetVendor POSTs /v2/device/miss_get_vendor and returns raw result JSON.
func (c *Client) MissGetVendor(ctx context.Context, region, did, supportVendors, appPubHex, callerUUID string) ([]byte, error) {
	_ = ctx
	cl, err := c.cloud()
	if err != nil {
		return nil, err
	}
	params := fmt.Sprintf(
		`{"app_pubkey":"%s","did":"%s","support_vendors":"%s","caller_uuid":"%s","obsolete_tutk":"0"}`,
		appPubHex, did, supportVendors, callerUUID,
	)
	return cl.Request(BaseURL(region), "/v2/device/miss_get_vendor", params, nil)
}

func (c *Client) WakeUp(ctx context.Context, did, region string) error {
	_ = ctx
	cl, err := c.cloud()
	if err != nil {
		return err
	}
	const params = `{"id":1,"method":"wakeup","params":{"video":"1"}}`
	_, err = cl.Request(BaseURL(region), "/home/rpc/"+did, params, nil)
	return err
}

// EventList GETs /common/app/get/eventlist (RC4 query) and parses thirdPartPlayUnits.
func (c *Client) EventList(ctx context.Context, q domain.EventQuery) ([]domain.Event, error) {
	cl, err := c.cloud()
	if err != nil {
		return nil, err
	}
	if q.Limit <= 0 {
		q.Limit = 20
	}
	if q.EventType == "" {
		q.EventType = "Default"
	}
	if q.EndMs <= 0 {
		q.EndMs = time.Now().UnixMilli()
	}
	if q.BeginMs <= 0 {
		q.BeginMs = q.EndMs - 7*24*time.Hour.Milliseconds()
	}
	paramsObj := map[string]any{
		"model":      q.Model,
		"eventType":  q.EventType,
		"limit":      q.Limit,
		"beginTime":  q.BeginMs,
		"endTime":    q.EndMs,
		"sortType":   "DESC",
		"needMerge":  true,
		"doorBell":   false,
		"region":     "US",
		"did":        q.DID,
	}
	raw, _ := json.Marshal(paramsObj)
	apiPath := "/common/app/get/eventlist"
	form, signed, err := xcrypto.EncryptForm("GET", apiPath, string(raw), cl.Ssecurity())
	if err != nil {
		return nil, err
	}
	form.Set("ssecurity", base64.StdEncoding.EncodeToString(cl.Ssecurity()))

	u := CameraAPIHost(q.Region) + apiPath + "?" + form.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Cookie", cl.Cookies())
	res, err := cl.Client().Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("eventlist: %s: %s", res.Status, truncate(string(body), 200))
	}
	pt, err := xcrypto.DecryptBody(signed, string(body))
	if err != nil {
		return nil, err
	}
	var wrap struct {
		Code    int             `json:"code"`
		Message string          `json:"message"`
		Data    json.RawMessage `json:"data"`
		Result  json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(pt, &wrap); err != nil {
		return nil, fmt.Errorf("eventlist json: %w (pt=%s)", err, truncate(string(pt), 120))
	}
	if wrap.Code != 0 {
		return nil, fmt.Errorf("eventlist: code=%d message=%s", wrap.Code, wrap.Message)
	}
	dataRaw := wrap.Data
	if len(dataRaw) == 0 {
		dataRaw = wrap.Result
	}
	var data struct {
		Units []unit `json:"thirdPartPlayUnits"`
	}
	if err := json.Unmarshal(dataRaw, &data); err != nil {
		// data may be a JSON string
		var s string
		if json.Unmarshal(dataRaw, &s) == nil {
			_ = json.Unmarshal([]byte(s), &data)
		} else {
			return nil, fmt.Errorf("eventlist data: %w", err)
		}
	}
	out := make([]domain.Event, 0, len(data.Units))
	for _, u := range data.Units {
		out = append(out, domain.Event{
			DID:               q.DID,
			Model:             q.Model,
			Region:            q.Region,
			EventType:         u.EventType,
			FileID:            u.FileID,
			ImgStoreID:        u.ImgStoreID,
			CreateTimeMs:      u.CreateTime,
			IsCloud:           u.IsCloud,
			OnlyShowImgNoPlay: u.OnlyShowImgNoPlay,
		})
	}
	return out, nil
}

type unit struct {
	EventType         string `json:"eventType"`
	FileID            string `json:"fileId"`
	ImgStoreID        string `json:"imgStoreId"`
	CreateTime        int64  `json:"createTime"`
	IsCloud           bool   `json:"isCloud"`
	OnlyShowImgNoPlay bool   `json:"onlyShowImgNoPlay"`
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
