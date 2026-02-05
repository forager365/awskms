package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/smithy-go"
	"github.com/parquet-go/parquet-go"
)

type SecretRecord struct {
	Name             string            `parquet:"name"`
	Description      *string           `parquet:"description,optional"`
	CreatedDate      *time.Time        `parquet:"created_date,optional,timestamp(millisecond)"`
	LastAccessedDate *parquet.Date     `parquet:"last_accessed_date,optional"`
	Tags             map[string]string `parquet:"tags,optional"`
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
				record.CreatedDate = secret.CreatedDate
			}

			if secret.LastAccessedDate != nil {
				// Convert to parquet.Date (days since Unix epoch)
				days := int32(secret.LastAccessedDate.Unix() / 86400)
				date := parquet.Date(days)
				record.LastAccessedDate = &date
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
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer file.Close()

	writer := parquet.NewGenericWriter[SecretRecord](file)

	if _, err := writer.Write(secrets); err != nil {
		return fmt.Errorf("failed to write records: %w", err)
	}

	if err := writer.Close(); err != nil {
		return fmt.Errorf("failed to close writer: %w", err)
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

// Keep JSON output as alternative (for debugging)
func writeJSON(secrets []SecretRecord) {
	encoder := json.NewEncoder(os.Stdout)
	for _, secret := range secrets {
		encoder.Encode(secret)
	}
}
