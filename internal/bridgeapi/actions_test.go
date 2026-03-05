package bridgeapi

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/juno-intents/intents-juno/internal/proverinput"
)

type fakePublisher struct {
	topic   string
	payload []byte
}

func (f *fakePublisher) Publish(_ context.Context, topic string, payload []byte) error {
	f.topic = topic
	f.payload = append([]byte(nil), payload...)
	return nil
}

func TestQueueActionService_SubmitDeposit(t *testing.T) {
	t.Parallel()

	witness := make([]byte, proverinput.DepositWitnessItemLen)
	binary.LittleEndian.PutUint32(witness[0:4], 3)
	cmBytes, _ := hex.DecodeString(strings.Repeat("aa", 32))
	copy(witness[1092:1124], cmBytes)
	pub := &fakePublisher{}
	svc, err := NewQueueActionService(QueueActionServiceConfig{
		BaseChainID:  84532,
		BridgeAddr:   common.HexToAddress("0x1111111111111111111111111111111111111111"),
		DepositTopic: "deposits.event.v1",
		Producer:     pub,
	})
	if err != nil {
		t.Fatalf("NewQueueActionService: %v", err)
	}

	payload, err := svc.SubmitDeposit(context.Background(), DepositSubmitInput{
		BaseRecipient:    common.HexToAddress("0x2222222222222222222222222222222222222222"),
		Amount:           100000,
		Nonce:            7,
		ProofWitnessItem: witness,
	})
	if err != nil {
		t.Fatalf("SubmitDeposit: %v", err)
	}
	if payload.DepositID == "" {
		t.Fatalf("missing deposit id")
	}
	if pub.topic != "deposits.event.v1" {
		t.Fatalf("topic: got=%s", pub.topic)
	}
	if len(pub.payload) == 0 {
		t.Fatalf("expected published payload")
	}
}

