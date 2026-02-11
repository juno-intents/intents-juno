package secrets

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

var (
	ErrInvalidConfig = errors.New("secrets: invalid config")
	ErrNotFound      = errors.New("secrets: not found")
)

type Provider interface {
	Get(ctx context.Context, key string) (string, error)
}

type awsClient interface {
	GetSecretValue(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
}

type AWSProvider struct {
	client awsClient
}

func NewAWS(ctx context.Context) (*AWSProvider, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: load aws config: %v", ErrInvalidConfig, err)
	}
	return NewAWSWithClient(secretsmanager.NewFromConfig(cfg))
}

func NewAWSWithClient(client awsClient) (*AWSProvider, error) {
	if client == nil {
		return nil, fmt.Errorf("%w: nil secretsmanager client", ErrInvalidConfig)
	}
	return &AWSProvider{client: client}, nil
}

func (p *AWSProvider) Get(ctx context.Context, key string) (string, error) {
	if p == nil || p.client == nil {
		return "", fmt.Errorf("%w: nil aws provider", ErrInvalidConfig)
	}
	key = strings.TrimSpace(key)
	if key == "" {
		return "", fmt.Errorf("%w: empty secret key", ErrInvalidConfig)
	}
	out, err := p.client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: &key,
	})
	if err != nil {
		return "", fmt.Errorf("secrets: get secret %q: %w", key, err)
	}
	if out.SecretString != nil && strings.TrimSpace(*out.SecretString) != "" {
		return strings.TrimSpace(*out.SecretString), nil
	}
	if out.SecretBinary != nil && len(out.SecretBinary) > 0 {
		return string(out.SecretBinary), nil
	}
	return "", fmt.Errorf("%w: secret %q has no value", ErrNotFound, key)
}

type EnvProvider struct{}

func NewEnv() *EnvProvider {
	return &EnvProvider{}
}

func (p *EnvProvider) Get(_ context.Context, key string) (string, error) {
	if p == nil {
		return "", fmt.Errorf("%w: nil env provider", ErrInvalidConfig)
	}
	key = strings.TrimSpace(key)
	if key == "" {
		return "", fmt.Errorf("%w: empty env key", ErrInvalidConfig)
	}
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return "", fmt.Errorf("%w: env %s is empty", ErrNotFound, key)
	}
	return v, nil
}
