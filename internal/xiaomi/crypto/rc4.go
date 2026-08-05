package crypto

import (
	"crypto/rand"
	"crypto/rc4"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net/url"
	"time"
)

func GenNonce() []byte {
	ts := time.Now().Unix() / 60
	nonce := make([]byte, 12)
	_, _ = rand.Read(nonce[:8])
	binary.BigEndian.PutUint32(nonce[8:], uint32(ts))
	return nonce
}

func SignedNonce(ssecurity, nonce []byte) []byte {
	h := sha256.New()
	h.Write(ssecurity)
	h.Write(nonce)
	return h.Sum(nil)
}

// Crypt is RC4 with 1024-byte keystream discard (Mi Home API).
func Crypt(key, plaintext []byte) ([]byte, error) {
	c, err := rc4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	tmp := make([]byte, 1024)
	c.XORKeyStream(tmp, tmp)
	out := make([]byte, len(plaintext))
	c.XORKeyStream(out, plaintext)
	return out, nil
}

func Signature64(method, path string, values url.Values, signedNonce []byte) string {
	s := method + "&" + path + "&data=" + values.Get("data")
	if values.Has("rc4_hash__") {
		s += "&rc4_hash__=" + values.Get("rc4_hash__")
	}
	s += "&" + base64.StdEncoding.EncodeToString(signedNonce)
	h := sha1.New()
	h.Write([]byte(s))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// EncryptForm builds signed+encrypted form values for Mi Home RC4 APIs.
func EncryptForm(method, apiPath, paramsJSON string, ssecurity []byte) (url.Values, []byte, error) {
	form := url.Values{"data": {paramsJSON}}
	nonce := GenNonce()
	signed := SignedNonce(ssecurity, nonce)
	form.Set("rc4_hash__", Signature64(method, apiPath, form, signed))
	for _, v := range form {
		ct, err := Crypt(signed, []byte(v[0]))
		if err != nil {
			return nil, nil, err
		}
		v[0] = base64.StdEncoding.EncodeToString(ct)
	}
	form.Set("signature", Signature64(method, apiPath, form, signed))
	form.Set("_nonce", base64.StdEncoding.EncodeToString(nonce))
	return form, signed, nil
}

func DecryptBody(signedNonce []byte, bodyB64 string) ([]byte, error) {
	ct, err := base64.StdEncoding.DecodeString(bodyB64)
	if err != nil {
		return nil, fmt.Errorf("xiaomi: body b64: %w", err)
	}
	return Crypt(signedNonce, ct)
}
