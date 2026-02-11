package secrets

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

type fakeAWSClient struct {
	out *secretsmanager.GetSecretValueOutput
	err error
}

func (c *fakeAWSClient) GetSecretValue(_ context.Context, _ *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	if c.err != nil {
		return nil, c.err
	}
	return c.out, nil
}

func TestEnvProvider(t *testing.T) {
	const key = "PROOF_KEY_TEST_ENV"
	t.Setenv(key, "  super-secret  ")
	p := NewEnv()
	got, err := p.Get(context.Background(), key)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != "super-secret" {
		t.Fatalf("value mismatch: got %q", got)
	}

	if _, err := p.Get(context.Background(), "MISSING_ENV_KEY_XYZ"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestAWSProvider(t *testing.T) {
	t.Parallel()

	p, err := NewAWSWithClient(&fakeAWSClient{
		out: &secretsmanager.GetSecretValueOutput{
			SecretString: strPtr(" secret "),
		},
	})
	if err != nil {
		t.Fatalf("NewAWSWithClient: %v", err)
	}
	got, err := p.Get(context.Background(), "arn:aws:secretsmanager:us-east-1:123:secret:test")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != "secret" {
		t.Fatalf("secret mismatch: got %q", got)
	}
}

func strPtr(v string) *string { return &v }
