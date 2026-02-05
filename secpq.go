package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/smithy-go"
	"github.com/xitongsys/parquet-go-source/local"
	"github.com/xitongsys/parquet-go/parquet"
	"github.com/xitongsys/parquet-go/writer"
)

type SecretRecord struct {
	Name             string             `parquet:"name=name, type=BYTE_ARRAY, convertedtype=UTF8, encoding=PLAIN_DICTIONARY"`
	Description      *string            `parquet:"name=description, type=BYTE_ARRAY, convertedtype=UTF8, encoding=PLAIN_DICTIONARY"`
	CreatedDate      *int32             `parquet:"name=created_date, type=INT32, convertedtype=DATE"`
	LastAccessedDate *int32             `parquet:"name=last_accessed_date, type=INT32, convertedtype=DATE"`
	Tags             map[string]string  `parquet:"name=tags, type=MAP, convertedtype=MAP, keytype=BYTE_ARRAY, keyconvertedtype=UTF8, valuetype=BYTE_ARRAY, valueconvertedtype=UTF8"`
}

func main() {
	profile := flag.String("profile", "", "AWS SSO profile name")
	region := flag.String("region", "", "AWS region")
	output := flag.String("output", "secrets.parquet", "Output parquet file path")
	flag.Parse()

	ctx := context.Background()

	cfg, err := loadAWSConfig(ctx, *profile, *region)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading AWS config: %v\n", err)
		os.Exit(1)
	}

	client := secretsmanager.NewFromConfig(cfg)

	secrets, err := listSecrets(ctx, client)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error listing secrets: %v\n", err)
		os.Exit(1)
	}

	if len(secrets) == 0 {
		fmt.Fprintln(os.Stderr, "No secrets found")
		os.Exit(0)
	}

	if err := writeParquet(*output, secrets); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing parquet: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "Wrote %d secrets to %s\n", len(secrets), *output)
}

func loadAWSConfig(ctx context.Context, profile, region string) (aws.Config, error) {
	var opts []func(*config.LoadOptions) error

	if profile != "" {
		opts = append(opts, config.WithSharedConfigProfile(profile))
	}

	if region != "" {
		opts = append(opts, config.WithRegion(region))
	}

	return config.LoadDefaultConfig(ctx, opts...)
}

func listSecrets(ctx context.Context, client *secretsmanager.Client) ([]SecretRecord, error) {
	var secrets []SecretRecord

	paginator := secretsmanager.NewListSecretsPaginator(client, &secretsmanager.ListSecretsInput{})

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if isNotAuthorizedError(err) {
				fmt.Fprintf(os.Stderr, "Warning: Not authorized to list secrets, skipping...\n")
				return secrets, nil
			}
			return nil, fmt.Errorf("failed to list secrets: %w", err)
		}

		for _, secret := range page.SecretList {
			record := SecretRecord{
				Name: aws.ToString(secret.Name),
			}

			if secret.Description != nil && *secret.Description != "" {
				record.Description = secret.Description
			}

			if secret.CreatedDate != nil {
				// Convert to days since Unix epoch for DATE type
				days := int32(secret.CreatedDate.Unix() / 86400)
				record.CreatedDate = &days
			}

			if secret.LastAccessedDate != nil {
				// Convert to days since Unix epoch for DATE type
				days := int32(secret.LastAccessedDate.Unix() / 86400)
				record.LastAccessedDate = &days
			}

			if len(secret.Tags) > 0 {
				record.Tags = make(map[string]string)
				for _, tag := range secret.Tags {
					key := aws.ToString(tag.Key)
					value := aws.ToString(tag.Value)
					record.Tags[key] = value
				}
			}

			secrets = append(secrets, record)
		}
	}

	return secrets, nil
}

func writeParquet(filename string, secrets []SecretRecord) error {
	fw, err := local.NewLocalFileWriter(filename)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer fw.Close()

	pw, err := writer.NewParquetWriter(fw, new(SecretRecord), 4)
	if err != nil {
		return fmt.Errorf("failed to create parquet writer: %w", err)
	}

	pw.RowGroupSize = 128 * 1024 * 1024 // 128MB
	pw.CompressionType = parquet.CompressionCodec_SNAPPY

	for _, record := range secrets {
		if err := pw.Write(record); err != nil {
			return fmt.Errorf("failed to write record: %w", err)
		}
	}

	if err := pw.WriteStop(); err != nil {
		return fmt.Errorf("failed to finalize parquet: %w", err)
	}

	return nil
}

func isNotAuthorizedError(err error) bool {
	var apiErr smithy.APIError
	if ok := errors.As(err, &apiErr); ok {
		code := apiErr.ErrorCode()
		return code == "AccessDeniedException" ||
			code == "UnauthorizedOperation" ||
			code == "UnauthorizedException" ||
			strings.Contains(code, "NotAuthorized")
	}
	return false
}
