package bridgeapi

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/juno-intents/intents-juno/internal/proverinput"
	"github.com/juno-intents/intents-juno/internal/withdrawrequest"
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
		BaseChainID:   84532,
		BridgeAddr:    common.HexToAddress("0x1111111111111111111111111111111111111111"),
		DepositTopic:  "deposits.event.v1",
		WithdrawTopic: "withdrawals.requested.v1",
		Producer:      pub,
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

func TestQueueActionService_RequestWithdrawalUsesInjectedFn(t *testing.T) {
	t.Parallel()

	pub := &fakePublisher{}
	svc, err := NewQueueActionService(QueueActionServiceConfig{
		BaseChainID:   84532,
		BridgeAddr:    common.HexToAddress("0x1111111111111111111111111111111111111111"),
		DepositTopic:  "deposits.event.v1",
		WithdrawTopic: "withdrawals.requested.v1",
		Producer:      pub,
		RequestWithdrawFn: func(_ context.Context, _ withdrawrequest.Config, req withdrawrequest.Request) (withdrawrequest.Payload, error) {
			return withdrawrequest.Payload{
				Version:      "withdrawals.requested.v1",
				WithdrawalID: "0x" + strings.Repeat("11", 32),
				Requester:    "0x" + strings.Repeat("22", 20),
				Amount:       req.Amount,
				RecipientUA:  "0x" + hex.EncodeToString(req.RecipientUA),
				Expiry:       123,
				FeeBps:       50,
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewQueueActionService: %v", err)
	}

	payload, err := svc.RequestWithdrawal(context.Background(), WithdrawalRequestInput{
		Amount:      1000,
		RecipientUA: []byte{1, 2, 3},
	})
	if err != nil {
		t.Fatalf("RequestWithdrawal: %v", err)
	}
	if payload.WithdrawalID == "" {
		t.Fatalf("missing withdrawal id")
	}
	if pub.topic != "withdrawals.requested.v1" {
		t.Fatalf("topic: got=%s", pub.topic)
	}
	if len(pub.payload) == 0 {
		t.Fatalf("expected published payload")
	}
}
