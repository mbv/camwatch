package live

import "context"

// Noop is used when telegram.live is disabled.
type Noop struct{}

func (Noop) StartCall(ctx context.Context, chatID string, sourceURL string) error {
	_ = ctx
	_ = chatID
	_ = sourceURL
	return ErrLiveDisabled
}

func (Noop) StartTest(ctx context.Context, chatID string) error {
	_ = ctx
	_ = chatID
	return ErrLiveDisabled
}

func (Noop) Stop(ctx context.Context) error {
	_ = ctx
	return nil
}

func (Noop) Close() error { return nil }
