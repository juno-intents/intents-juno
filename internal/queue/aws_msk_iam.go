package queue

import (
	"context"
	"errors"
	"sort"

	mskiam "github.com/aws/aws-msk-iam-sasl-signer-go/signer"
	"github.com/segmentio/kafka-go/sasl"
)

type tokenProviderFunc func(context.Context, string) (string, error)

type awsMSKIAMMechanism struct {
	region        string
	tokenProvider tokenProviderFunc
}

func newAWSMSKIAMMechanism(region string) sasl.Mechanism {
	return awsMSKIAMMechanism{
		region: region,
		tokenProvider: func(ctx context.Context, region string) (string, error) {
			token, _, err := mskiam.GenerateAuthToken(ctx, region)
			if err != nil {
				return "", err
			}
			return token, nil
		},
	}
}

func (m awsMSKIAMMechanism) Name() string { return "OAUTHBEARER" }

func (m awsMSKIAMMechanism) Start(ctx context.Context) (sasl.StateMachine, []byte, error) {
	token, err := m.tokenProvider(ctx, m.region)
	if err != nil {
		return nil, nil, err
	}
	if token == "" {
		return nil, nil, errors.New("aws-msk-iam token must be non-empty")
	}
	return awsMSKIAMSession{}, oauthInitialResponse(token, nil), nil
}

type awsMSKIAMSession struct{}

func (awsMSKIAMSession) Next(_ context.Context, challenge []byte) (bool, []byte, error) {
	if len(challenge) != 0 {
		return false, nil, errors.New("unexpected data in oauth response")
	}
	return true, nil, nil
}

func oauthInitialResponse(token string, extensions map[string]string) []byte {
	type kv struct {
		k string
		v string
	}

	kvs := make([]kv, 0, len(extensions))
	for k, v := range extensions {
		if k == "" {
			continue
		}
		kvs = append(kvs, kv{k: k, v: v})
	}
	sort.Slice(kvs, func(i, j int) bool { return kvs[i].k < kvs[j].k })

	init := []byte("n,,\x01auth=Bearer ")
	init = append(init, token...)
	init = append(init, '\x01')
	for _, kv := range kvs {
		init = append(init, kv.k...)
		init = append(init, '=')
		init = append(init, kv.v...)
		init = append(init, '\x01')
	}
	init = append(init, '\x01')
	return init
}
