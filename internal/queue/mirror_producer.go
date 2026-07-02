package queue

import (
	"context"
	"errors"
	"fmt"
)

// MirrorProducerConfig configures a producer that writes to a primary queue and
// mirrors successful primary publishes to a shadow queue.
type MirrorProducerConfig struct {
	RequireShadow bool
}

type mirrorProducer struct {
	primary       Producer
	shadow        Producer
	requireShadow bool
}

func NewMirrorProducer(primary, shadow Producer, cfg MirrorProducerConfig) (Producer, error) {
	if primary == nil {
		return nil, errors.New("mirror producer requires primary producer")
	}
	if shadow == nil {
		return nil, errors.New("mirror producer requires shadow producer")
	}
	return &mirrorProducer{
		primary:       primary,
		shadow:        shadow,
		requireShadow: cfg.RequireShadow,
	}, nil
}

func (p *mirrorProducer) Publish(ctx context.Context, topic string, payload []byte) error {
	primaryPayload := append([]byte(nil), payload...)
	shadowPayload := append([]byte(nil), payload...)
	if err := p.primary.Publish(ctx, topic, primaryPayload); err != nil {
		return fmt.Errorf("primary producer publish: %w", err)
	}
	if err := p.shadow.Publish(ctx, topic, shadowPayload); err != nil && p.requireShadow {
		return fmt.Errorf("shadow producer publish: %w", err)
	}
	return nil
}

func (p *mirrorProducer) Close() error {
	return errors.Join(p.primary.Close(), p.shadow.Close())
}
