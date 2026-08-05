package fs

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"camwatch/internal/domain"
)

type ClipStore struct {
	Dir string
}

func New(dir string) *ClipStore { return &ClipStore{Dir: dir} }

func (c *ClipStore) EnsureDir() error {
	return os.MkdirAll(c.Dir, 0o755)
}

func (c *ClipStore) PathFor(ev domain.Event) string {
	ts := time.Unix(ev.SessionUnix(), 0).UTC().Format("20060102T150405Z")
	name := fmt.Sprintf("%s_%s_%s.mp4", ev.DID, ts, sanitize(ev.EventType))
	if ev.FileID != "" {
		name = fmt.Sprintf("%s_%s.mp4", ev.DID, sanitize(ev.FileID))
	}
	return filepath.Join(c.Dir, name)
}

func sanitize(s string) string {
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
			b = append(b, c)
		case c == ':' || c == '/':
			b = append(b, '_')
		default:
			b = append(b, '_')
		}
	}
	if len(b) == 0 {
		return "clip"
	}
	return string(b)
}
