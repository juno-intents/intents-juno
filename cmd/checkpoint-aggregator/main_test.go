package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/juno-intents/intents-juno/internal/checkpoint"
)

type stubCheckpointProducer struct {
	topic    string
	payloads [][]byte
	err      error
}

func (p *stubCheckpointProducer) Publish(_ context.Context, topic string, payload []byte) error {
	p.topic = topic
	p.payloads = append(p.payloads, append([]byte(nil), payload...))
	return p.err
}

func (p *stubCheckpointProducer) Close() error {
	return nil
}

func TestPublishCheckpointPackage_MarksEmittedAfterPublish(t *testing.T) {
	t.Parallel()

	cp := checkpoint.Checkpoint{
		Height:           123,
		BlockHash:        common.HexToHash("0x64afe1a0c6c050e37d936aa20cb82b08bb8815baed208e7634d6df26fc37b091"),
		FinalOrchardRoot: common.HexToHash("0xd6c66cad06fe14fdb6ce9297d80d32f24d7428996d0045cbf90cc345c677ba16"),
		BaseChainID:      8453,
		BridgeContract:   common.HexToAddress("0x000000000000000000000000000000000000bEEF"),
	}
	digest := checkpoint.Digest(cp)
	now := time.Unix(1_700_000_000, 0).UTC()

	store := checkpoint.NewMemoryPackageStore()
	persist, err := checkpoint.NewPackagePersistence(checkpoint.PackagePersistenceConfig{
		PackageStore: store,
		Now:          func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewPackagePersistence: %v", err)
	}

	agg, err := checkpoint.NewAggregator(checkpoint.AggregatorConfig{
		BaseChainID:    cp.BaseChainID,
		BridgeContract: cp.BridgeContract,
		Operators:      []common.Address{common.HexToAddress("0x1111111111111111111111111111111111111111")},
		Threshold:      1,
		Now:            func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewAggregator: %v", err)
	}
	if err := agg.RestorePendingPackage(checkpoint.CheckpointPackageV1{
		Digest:          digest,
		Checkpoint:      cp,
		OperatorSetHash: common.HexToHash("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		CreatedAt:       now,
	}); err != nil {
		t.Fatalf("RestorePendingPackage: %v", err)
	}

	producer := &stubCheckpointProducer{}
	pkg := checkpoint.CheckpointPackageV1{
		Digest:          digest,
		Checkpoint:      cp,
		OperatorSetHash: common.HexToHash("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		CreatedAt:       now,
	}
	if err := publishCheckpointPackage(context.Background(), persist, agg, producer, "checkpoints.packages.v1", pkg); err != nil {
		t.Fatalf("publishCheckpointPackage: %v", err)
	}

	rec, err := store.Get(context.Background(), digest)
	if err != nil {
		t.Fatalf("store.Get: %v", err)
	}
	if rec.State != checkpoint.PackageStateEmitted {
		t.Fatalf("state: got %s want %s", rec.State, checkpoint.PackageStateEmitted)
	}
	if len(producer.payloads) != 1 {
		t.Fatalf("publish calls: got %d want 1", len(producer.payloads))
	}
}

func TestReplayOpenCheckpointPackages_ReemitsPersistedPackages(t *testing.T) {
	t.Parallel()

	cp := checkpoint.Checkpoint{
		Height:           123,
		BlockHash:        common.HexToHash("0x64afe1a0c6c050e37d936aa20cb82b08bb8815baed208e7634d6df26fc37b091"),
		FinalOrchardRoot: common.HexToHash("0xd6c66cad06fe14fdb6ce9297d80d32f24d7428996d0045cbf90cc345c677ba16"),
		BaseChainID:      8453,
		BridgeContract:   common.HexToAddress("0x000000000000000000000000000000000000bEEF"),
	}
	digest := checkpoint.Digest(cp)
	now := time.Unix(1_700_000_000, 0).UTC()

	store := checkpoint.NewMemoryPackageStore()
	persist, err := checkpoint.NewPackagePersistence(checkpoint.PackagePersistenceConfig{
		PackageStore: store,
		Now:          func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewPackagePersistence: %v", err)
	}

	payload, err := json.Marshal(checkpointPackageV1{
		Version:         "checkpoints.package.v1",
		Digest:          digest,
		Checkpoint:      cp,
		OperatorSetHash: common.HexToHash("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		CreatedAt:       now,
	})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if _, err := persist.Persist(context.Background(), checkpoint.PackageEnvelope{
		Digest:          digest,
		Checkpoint:      cp,
		OperatorSetHash: common.HexToHash("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		Payload:         payload,
	}); err != nil {
		t.Fatalf("Persist: %v", err)
	}

	agg, err := checkpoint.NewAggregator(checkpoint.AggregatorConfig{
		BaseChainID:    cp.BaseChainID,
		BridgeContract: cp.BridgeContract,
		Operators:      []common.Address{common.HexToAddress("0x1111111111111111111111111111111111111111")},
		Threshold:      1,
		Now:            func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewAggregator: %v", err)
	}
	producer := &stubCheckpointProducer{}

	if err := replayOpenCheckpointPackages(context.Background(), persist, agg, producer, "checkpoints.packages.v1", slog.Default()); err != nil {
		t.Fatalf("replayOpenCheckpointPackages: %v", err)
	}

	rec, err := store.Get(context.Background(), digest)
	if err != nil {
		t.Fatalf("store.Get: %v", err)
	}
	if rec.State != checkpoint.PackageStateEmitted {
		t.Fatalf("state: got %s want %s", rec.State, checkpoint.PackageStateEmitted)
	}
	if len(producer.payloads) != 1 {
		t.Fatalf("publish calls: got %d want 1", len(producer.payloads))
	}
}

func TestPublishCheckpointPackage_LeavesPackageOpenOnPublishFailure(t *testing.T) {
	t.Parallel()

	cp := checkpoint.Checkpoint{
		Height:           123,
		BlockHash:        common.HexToHash("0x64afe1a0c6c050e37d936aa20cb82b08bb8815baed208e7634d6df26fc37b091"),
		FinalOrchardRoot: common.HexToHash("0xd6c66cad06fe14fdb6ce9297d80d32f24d7428996d0045cbf90cc345c677ba16"),
		BaseChainID:      8453,
		BridgeContract:   common.HexToAddress("0x000000000000000000000000000000000000bEEF"),
	}
	digest := checkpoint.Digest(cp)
	now := time.Unix(1_700_000_000, 0).UTC()

	store := checkpoint.NewMemoryPackageStore()
	persist, err := checkpoint.NewPackagePersistence(checkpoint.PackagePersistenceConfig{
		PackageStore: store,
		Now:          func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewPackagePersistence: %v", err)
	}

	agg, err := checkpoint.NewAggregator(checkpoint.AggregatorConfig{
		BaseChainID:    cp.BaseChainID,
		BridgeContract: cp.BridgeContract,
		Operators:      []common.Address{common.HexToAddress("0x1111111111111111111111111111111111111111")},
		Threshold:      1,
		Now:            func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewAggregator: %v", err)
	}

	pkg := checkpoint.CheckpointPackageV1{
		Digest:          digest,
		Checkpoint:      cp,
		OperatorSetHash: common.HexToHash("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		CreatedAt:       now,
	}
	producer := &stubCheckpointProducer{err: errors.New("publish failed")}

	if err := publishCheckpointPackage(context.Background(), persist, agg, producer, "checkpoints.packages.v1", pkg); err == nil {
		t.Fatalf("expected publish error")
	}

	rec, err := store.Get(context.Background(), digest)
	if err != nil {
		t.Fatalf("store.Get: %v", err)
	}
	if rec.State != checkpoint.PackageStateOpen {
		t.Fatalf("state: got %s want %s", rec.State, checkpoint.PackageStateOpen)
	}
}
