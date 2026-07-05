package queue

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// MirrorProducerConfig configures a producer that writes to a primary queue and
// mirrors successful primary publishes to a shadow queue.
type MirrorProducerConfig struct {
	RequireShadow      bool
	ShadowTimeout      time.Duration
	ShadowErrorHandler func(topic string, err error)
}

type mirrorProducer struct {
	primary            Producer
	shadow             Producer
	requireShadow      bool
	shadowTimeout      time.Duration
	shadowErrorHandler func(topic string, err error)
	shadowMu           sync.Mutex
	shadowClosed       bool
}

func NewMirrorProducer(primary, shadow Producer, cfg MirrorProducerConfig) (Producer, error) {
	if primary == nil {
		return nil, errors.New("mirror producer requires primary producer")
	}
	if shadow == nil {
		return nil, errors.New("mirror producer requires shadow producer")
	}
	return &mirrorProducer{
		primary:            primary,
		shadow:             shadow,
		requireShadow:      cfg.RequireShadow,
		shadowTimeout:      cfg.ShadowTimeout,
		shadowErrorHandler: cfg.ShadowErrorHandler,
	}, nil
}

func (p *mirrorProducer) Publish(ctx context.Context, topic string, payload []byte) error {
	primaryPayload := append([]byte(nil), payload...)
	shadowPayload := append([]byte(nil), payload...)
	if err := p.primary.Publish(ctx, topic, primaryPayload); err != nil {
		return fmt.Errorf("primary producer publish: %w", err)
	}
	if p.requireShadow {
		if err := p.shadow.Publish(ctx, topic, shadowPayload); err != nil {
			return fmt.Errorf("shadow producer publish: %w", err)
		}
		return nil
	}
	p.publishOptionalShadow(ctx, topic, shadowPayload)
	return nil
}

func (p *mirrorProducer) PublishToGroup(ctx context.Context, topic string, consumerGroup string, payload []byte) error {
	primaryPayload := append([]byte(nil), payload...)
	shadowPayload := append([]byte(nil), payload...)
	if err := publishTargetedOrBroadcast(ctx, p.primary, topic, consumerGroup, primaryPayload); err != nil {
		return fmt.Errorf("primary producer publish: %w", err)
	}
	if p.requireShadow {
		if err := publishTargetedOrBroadcast(ctx, p.shadow, topic, consumerGroup, shadowPayload); err != nil {
			return fmt.Errorf("shadow producer publish: %w", err)
		}
		return nil
	}
	p.publishOptionalTargetedShadow(ctx, topic, consumerGroup, shadowPayload)
	return nil
}

func publishTargetedOrBroadcast(ctx context.Context, producer Producer, topic string, consumerGroup string, payload []byte) error {
	if targeted, ok := producer.(TargetedProducer); ok {
		return targeted.PublishToGroup(ctx, topic, consumerGroup, payload)
	}
	return producer.Publish(ctx, topic, payload)
}

func (p *mirrorProducer) publishOptionalShadow(ctx context.Context, topic string, payload []byte) {
	if p.shadowTimeout <= 0 {
		if err := p.shadow.Publish(ctx, topic, payload); err != nil {
			p.handleOptionalShadowError(topic, err)
		}
		return
	}

	p.shadowMu.Lock()
	shadowClosed := p.shadowClosed
	p.shadowMu.Unlock()
	if shadowClosed {
		return
	}

	shadowCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), p.shadowTimeout)
	defer cancel()

	resultCh := make(chan error, 1)
	go func() {
		resultCh <- p.shadow.Publish(shadowCtx, topic, payload)
	}()

	select {
	case err := <-resultCh:
		if err != nil {
			p.handleOptionalShadowError(topic, err)
		}
		if errors.Is(shadowCtx.Err(), context.DeadlineExceeded) {
			p.closeOptionalShadow()
		}
	case <-shadowCtx.Done():
		p.handleOptionalShadowError(topic, shadowCtx.Err())
		p.closeOptionalShadow()
	}
}

func (p *mirrorProducer) publishOptionalTargetedShadow(ctx context.Context, topic string, consumerGroup string, payload []byte) {
	if p.shadowTimeout <= 0 {
		if err := publishTargetedOrBroadcast(ctx, p.shadow, topic, consumerGroup, payload); err != nil {
			p.handleOptionalShadowError(topic, err)
		}
		return
	}

	p.shadowMu.Lock()
	shadowClosed := p.shadowClosed
	p.shadowMu.Unlock()
	if shadowClosed {
		return
	}

	shadowCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), p.shadowTimeout)
	defer cancel()

	resultCh := make(chan error, 1)
	go func() {
		resultCh <- publishTargetedOrBroadcast(shadowCtx, p.shadow, topic, consumerGroup, payload)
	}()

	select {
	case err := <-resultCh:
		if err != nil {
			p.handleOptionalShadowError(topic, err)
		}
		if errors.Is(shadowCtx.Err(), context.DeadlineExceeded) {
			p.closeOptionalShadow()
		}
	case <-shadowCtx.Done():
		p.handleOptionalShadowError(topic, shadowCtx.Err())
		p.closeOptionalShadow()
	}
}

func (p *mirrorProducer) handleOptionalShadowError(topic string, err error) {
	if p.shadowErrorHandler != nil {
		p.shadowErrorHandler(topic, err)
	}
}

func (p *mirrorProducer) closeOptionalShadow() {
	p.shadowMu.Lock()
	if p.shadowClosed {
		p.shadowMu.Unlock()
		return
	}
	p.shadowClosed = true
	shadow := p.shadow
	p.shadowMu.Unlock()

	go func() {
		_ = shadow.Close()
	}()
}

func (p *mirrorProducer) Close() error {
	p.shadowMu.Lock()
	shadowClosed := p.shadowClosed
	if !shadowClosed {
		p.shadowClosed = true
	}
	shadow := p.shadow
	p.shadowMu.Unlock()
	if shadowClosed {
		return p.primary.Close()
	}
	return errors.Join(p.primary.Close(), shadow.Close())
}
