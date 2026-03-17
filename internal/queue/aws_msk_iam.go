package queue

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/segmentio/kafka-go/sasl"
	awsmskiamv2 "github.com/segmentio/kafka-go/sasl/aws_msk_iam_v2"
)

type awsMSKIAMConfigLoader func(context.Context, string) (aws.Config, error)

var loadAWSMSKIAMConfig awsMSKIAMConfigLoader = func(ctx context.Context, region string) (aws.Config, error) {
	return awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
}

func newAWSMSKIAMMechanism(region string) (sasl.Mechanism, error) {
	cfg, err := loadAWSMSKIAMConfig(context.Background(), region)
	if err != nil {
		return nil, err
	}
	return awsmskiamv2.NewMechanism(cfg), nil
}
