package orchestrator

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"sync"
	"testing"
	"time"

	"camwatch/internal/domain"
	"camwatch/internal/ports"
)

type fakeAuth struct {
	mu          sync.Mutex
	invalidates int
	refreshes   int
	refreshErr  error
}

func (a *fakeAuth) EnsureValid(context.Context) (domain.TokenBundle, error) {
	return domain.TokenBundle{ServiceToken: "t"}, nil
}
func (a *fakeAuth) Login(context.Context, string, string) (domain.TokenBundle, error) {
	return domain.TokenBundle{}, nil
}
func (a *fakeAuth) Refresh(context.Context, domain.TokenBundle) (domain.TokenBundle, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.refreshes++
	if a.refreshErr != nil {
		return domain.TokenBundle{}, a.refreshErr
	}
	return domain.TokenBundle{ServiceToken: "fresh"}, nil
}
func (a *fakeAuth) LoadSession(context.Context) (domain.TokenBundle, error) {
	return domain.TokenBundle{}, fs.ErrNotExist
}
func (a *fakeAuth) SaveSession(context.Context, domain.TokenBundle) error { return nil }
func (a *fakeAuth) Invalidate() {
	a.mu.Lock()
	a.invalidates++
	a.mu.Unlock()
}

type fakeConn struct{}

func (fakeConn) DownloadPlayback(context.Context, *domain.PlaybackRequest) (io.ReadCloser, error) {
	return nil, errors.New("unused")
}
func (fakeConn) OpenLive(context.Context) (io.ReadCloser, error) { return nil, errors.New("unused") }
func (fakeConn) Alive() bool                                      { return false }
func (fakeConn) Close() error                                     { return nil }

// fakeStream fails with 401 until it sees the "fresh" token.
type fakeStream struct {
	mu    sync.Mutex
	calls int
	seen  []string
}

func (s *fakeStream) Open(_ context.Context, _ domain.Device, t domain.TokenBundle) (ports.P2PConn, error) {
	s.mu.Lock()
	s.calls++
	s.seen = append(s.seen, t.ServiceToken)
	s.mu.Unlock()
	if t.ServiceToken != "fresh" {
		return nil, errors.New("miss_get_vendor: 401 Unauthorized")
	}
	return fakeConn{}, nil
}

type fakeRecorder struct{ calls int }

func (r *fakeRecorder) CaptureEvent(context.Context, ports.P2PConn, domain.Event, domain.ClipWindow) (domain.Clip, error) {
	r.calls++
	return domain.Clip{Path: "/tmp/x.mp4", Bytes: 1}, nil
}

type memStore struct {
	mu   sync.Mutex
	seen map[string]bool
}

func (m *memStore) Seen(_ context.Context, k string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.seen[k], nil
}
func (m *memStore) Mark(_ context.Context, k string, _ domain.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.seen == nil {
		m.seen = map[string]bool{}
	}
	m.seen[k] = true
	return nil
}

type nopNotifier struct{}

func (nopNotifier) NotifyEvent(context.Context, domain.Event, domain.Clip, []byte) error { return nil }

func newTestOrch(a ports.AuthProvider, c ports.CameraCloudAPI, s ports.StreamSession, r ports.Recorder) *Orchestrator {
	return New(Config{Devices: []domain.Device{{DID: "d1"}}}, a, c, s, r, nopNotifier{}, &memStore{}, nil)
}

func TestRequestClipRefreshesAuthOn401(t *testing.T) {
	auth := &fakeAuth{}
	stream := &fakeStream{}
	rec := &fakeRecorder{}
	o := newTestOrch(auth, nil, stream, rec)

	clip, err := o.RequestClip(context.Background(), domain.Device{DID: "d1"}, domain.Event{FileID: "f1"}, domain.ClipWindow{})
	if err != nil {
		t.Fatalf("expected success after refresh, got %v", err)
	}
	if clip.Path == "" || rec.calls != 1 {
		t.Fatalf("clip=%+v recorder calls=%d", clip, rec.calls)
	}
	if auth.invalidates != 1 || auth.refreshes != 1 {
		t.Fatalf("invalidates=%d refreshes=%d, want 1/1", auth.invalidates, auth.refreshes)
	}
	if stream.calls != 2 || stream.seen[1] != "fresh" {
		t.Fatalf("stream calls=%d seen=%v", stream.calls, stream.seen)
	}
}

func TestRequestClip401RefreshFailsNoRetry(t *testing.T) {
	auth := &fakeAuth{refreshErr: errors.New("passToken dead")}
	stream := &fakeStream{}
	o := newTestOrch(auth, nil, stream, &fakeRecorder{})

	_, err := o.RequestClip(context.Background(), domain.Device{DID: "d1"}, domain.Event{FileID: "f1"}, domain.ClipWindow{})
	if err == nil || !isAuthErr(err) {
		t.Fatalf("want original 401 error, got %v", err)
	}
	if stream.calls != 1 {
		t.Fatalf("must not retry when refresh fails; stream calls=%d", stream.calls)
	}
}

type fakeCloud struct{ events []domain.Event }

func (c fakeCloud) EventList(context.Context, domain.EventQuery) ([]domain.Event, error) {
	return c.events, nil
}
func (c fakeCloud) WakeUp(context.Context, string, string) error { return nil }

func TestPollOnceSpawnsOneCapturePerCamera(t *testing.T) {
	var evs []domain.Event
	old := time.Now().Add(-3 * time.Hour).UnixMilli()
	for _, id := range []string{"a", "b", "c", "d", "e"} {
		evs = append(evs, domain.Event{FileID: id, EventType: "PeopleMotion", CreateTimeMs: old})
	}
	stream := &fakeStream{}
	o := newTestOrch(&fakeAuth{}, fakeCloud{evs}, stream, &fakeRecorder{})

	o.pollOnce(context.Background())
	time.Sleep(300 * time.Millisecond) // let the spawned goroutine finish

	o.mu.Lock()
	defer o.mu.Unlock()
	// One event claimed and attempted; the other four untouched (no ErrBusy churn).
	if stream.calls == 0 {
		t.Fatal("expected one capture attempt")
	}
	if len(o.claimed) > 1 {
		t.Fatalf("claimed %d events in one poll, want <=1: %v", len(o.claimed), o.claimed)
	}
}
