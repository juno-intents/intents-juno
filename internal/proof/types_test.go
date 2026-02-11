package proof

import (
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

func TestDecodeJobRequest(t *testing.T) {
	t.Parallel()

	deadline := time.Date(2026, 2, 12, 12, 0, 0, 0, time.UTC)
	payload := []byte(`{
		"job_id":"0x5a6a8f35ea6fbce9ebc657de70e77bb9b7f2030569f9c6fbf46ba783f913be98",
		"pipeline":"withdraw",
		"image_id":"0x000000000000000000000000000000000000000000000000000000000000aa02",
		"journal":"0x010203",
		"private_input":"0x0405",
		"deadline":"` + deadline.Format(time.RFC3339) + `",
		"priority":2
	}`)

	job, err := DecodeJobRequest(payload)
	if err != nil {
		t.Fatalf("DecodeJobRequest: %v", err)
	}
	if got, want := job.Pipeline, "withdraw"; got != want {
		t.Fatalf("pipeline: got %q want %q", got, want)
	}
	if got, want := job.Priority, 2; got != want {
		t.Fatalf("priority: got %d want %d", got, want)
	}
	if got, want := job.Deadline.UTC(), deadline; !got.Equal(want) {
		t.Fatalf("deadline: got %s want %s", got, want)
	}
	if got, want := job.ImageID, common.HexToHash("0x000000000000000000000000000000000000000000000000000000000000aa02"); got != want {
		t.Fatalf("image_id: got %s want %s", got, want)
	}
	if got, want := hex.EncodeToString(job.Journal), "010203"; got != want {
		t.Fatalf("journal: got %s want %s", got, want)
	}
	if got, want := hex.EncodeToString(job.PrivateInput), "0405"; got != want {
		t.Fatalf("private input: got %s want %s", got, want)
	}
}

func TestDecodeJobRequest_Invalid(t *testing.T) {
	t.Parallel()

	_, err := DecodeJobRequest([]byte(`{"job_id":"0x01","pipeline":"","image_id":"0x0","journal":"0x","private_input":"0x","deadline":"bad","priority":-1}`))
	if !errors.Is(err, ErrInvalidJob) {
		t.Fatalf("expected ErrInvalidJob, got %v", err)
	}
}

