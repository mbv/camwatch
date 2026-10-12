package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/term"

	"camwatch/internal/config"
	"camwatch/internal/xiaomi/auth"
)

// runLogin implements `camwatch login`: password login with captcha / 2FA,
// writing xiaomi.session_file (serviceToken, ssecurity, passToken, deviceId).
func runLogin(args []string) int {
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	cfgPath := fs.String("config", "configs/camwatch.yaml", "path to config yaml")
	user := fs.String("user", "", "Xiaomi account (default: xiaomi.username, else prompt)")
	_ = fs.Parse(args)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		return 1
	}
	in := bufio.NewReader(os.Stdin)

	u := firstNonEmpty(*user, cfg.Xiaomi.Username, os.Getenv("CAMWATCH_XIAOMI_USER"))
	if u == "" {
		u = prompt(in, "Xiaomi account (e-mail/phone/id): ")
	}
	pw := firstNonEmpty(os.Getenv("CAMWATCH_XIAOMI_PASSWORD"), cfg.Xiaomi.Password)
	if pw == "" {
		fmt.Fprint(os.Stderr, "Password: ")
		b, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			fmt.Fprintln(os.Stderr, "read password:", err)
			return 1
		}
		pw = string(b)
	}

	p := auth.NewProvider(cfg.Xiaomi.SID, cfg.Xiaomi.SessionFile, u, pw, "", "")
	t, err := p.LoginInteractive(context.Background(), u, pw, &cliPrompter{in: in, dir: filepath.Dir(cfg.Xiaomi.SessionFile)})
	if err != nil {
		fmt.Fprintln(os.Stderr, "login failed:", err)
		return 1
	}
	fmt.Printf("logged in: userId=%s passToken=%v session=%s\n", t.UserID, t.PassToken != "", cfg.Xiaomi.SessionFile)
	return 0
}

type cliPrompter struct {
	in  *bufio.Reader
	dir string
}

func (c *cliPrompter) Captcha(img []byte) (string, error) {
	path := filepath.Join(c.dir, "captcha.jpg")
	if err := os.WriteFile(path, img, 0o600); err != nil {
		return "", err
	}
	fmt.Printf("Captcha required; image saved to %s\n", path)
	return prompt(c.in, "Captcha text: "), nil
}

func (c *cliPrompter) Code(phone, email string) (string, error) {
	dest := firstNonEmpty(phone, email)
	fmt.Printf("Verification code sent to %s\n", dest)
	return prompt(c.in, "Code: "), nil
}

func prompt(in *bufio.Reader, label string) string {
	fmt.Fprint(os.Stderr, label)
	s, _ := in.ReadString('\n')
	return strings.TrimSpace(s)
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}
