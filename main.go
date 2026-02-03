module kms-keys

go 1.21

require (
	github.com/aws/aws-sdk-go-v2 v1.32.6
	github.com/aws/aws-sdk-go-v2/config v1.28.6
	github.com/aws/aws-sdk-go-v2/service/kms v1.37.7
)
package main

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

type KeyInfo struct {
	KeyID        string
	Status       string
	CreationDate time.Time
	KeyType      string
	Tags         map[string]string
}

func main() {
	ctx := context.Background()

	// Load AWS configuration
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading AWS config: %v\n", err)
		os.Exit(1)
	}

	// Create KMS client
	client := kms.NewFromConfig(cfg)

	// List all keys
	keys, err := listAllKeys(ctx, client)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error listing keys: %v\n", err)
		os.Exit(1)
	}

	// Collect key information
	var enabledKeys []KeyInfo
	var notAuthorizedKeys []KeyInfo
	allTagKeys := make(map[string]bool)

	for _, key := range keys {
		keyInfo := getKeyInfo(ctx, client, *key.KeyId)

		if keyInfo.Status == "Not Authorized" {
			notAuthorizedKeys = append(notAuthorizedKeys, keyInfo)
		} else if keyInfo.Status == "Enabled" {
			enabledKeys = append(enabledKeys, keyInfo)
			for tagKey := range keyInfo.Tags {
				allTagKeys[tagKey] = true
			}
		}
	}

	// Sort tag keys for consistent column order
	var sortedTagKeys []string
	for tagKey := range allTagKeys {
		sortedTagKeys = append(sortedTagKeys, tagKey)
	}
	sort.Strings(sortedTagKeys)

	// Print Enabled Keys
	if len(enabledKeys) > 0 {
		fmt.Println("=== ENABLED KEYS ===")
		fmt.Println()
		printEnabledKeysTable(enabledKeys, sortedTagKeys)
	}

	// Print Not Authorized Keys
	if len(notAuthorizedKeys) > 0 {
		fmt.Println()
		fmt.Println("=== NOT AUTHORIZED KEYS ===")
		fmt.Println()
		printNotAuthorizedKeysTable(notAuthorizedKeys)
	}

	// Summary
	fmt.Println()
	fmt.Printf("Total Customer Managed Keys: %d\n", len(keys))
	fmt.Printf("  Enabled: %d\n", len(enabledKeys))
	fmt.Printf("  Not Authorized: %d\n", len(notAuthorizedKeys))
}

func listAllKeys(ctx context.Context, client *kms.Client) ([]types.KeyListEntry, error) {
	var allKeys []types.KeyListEntry
	var marker *string

	for {
		input := &kms.ListKeysInput{
			Marker: marker,
		}

		output, err := client.ListKeys(ctx, input)
		if err != nil {
			return nil, err
		}

		// Filter for customer managed keys only
		for _, key := range output.Keys {
			// Check if it's a customer managed key
			describeInput := &kms.DescribeKeyInput{
				KeyId: key.KeyId,
			}
			describeOutput, err := client.DescribeKey(ctx, describeInput)
			if err != nil {
				// If we can't describe it, still include it (might be not authorized)
				allKeys = append(allKeys, key)
				continue
			}

			// Only include customer managed keys (not AWS managed)
			if describeOutput.KeyMetadata.KeyManager == types.KeyManagerTypeCustomer {
				allKeys = append(allKeys, key)
			}
		}

		if !output.Truncated {
			break
		}
		marker = output.NextMarker
	}

	return allKeys, nil
}

func getKeyInfo(ctx context.Context, client *kms.Client, keyID string) KeyInfo {
	info := KeyInfo{
		KeyID: keyID,
		Tags:  make(map[string]string),
	}

	// Get key metadata
	describeInput := &kms.DescribeKeyInput{
		KeyId: &keyID,
	}

	describeOutput, err := client.DescribeKey(ctx, describeInput)
	if err != nil {
		// Check if it's an access denied error
		if strings.Contains(err.Error(), "AccessDenied") || strings.Contains(err.Error(), "not authorized") {
			info.Status = "Not Authorized"
			return info
		}
		info.Status = fmt.Sprintf("Error: %v", err)
		return info
	}

	// Set status
	info.Status = string(describeOutput.KeyMetadata.KeyState)

	// Set creation date
	if describeOutput.KeyMetadata.CreationDate != nil {
		info.CreationDate = *describeOutput.KeyMetadata.CreationDate
	}

	// Set key type (spec)
	info.KeyType = string(describeOutput.KeyMetadata.KeySpec)

	// Only get tags if the key is enabled
	if describeOutput.KeyMetadata.KeyState == types.KeyStateEnabled {
		tagsInput := &kms.ListResourceTagsInput{
			KeyId: &keyID,
		}

		tagsOutput, err := client.ListResourceTags(ctx, tagsInput)
		if err == nil {
			for _, tag := range tagsOutput.Tags {
				info.Tags[*tag.TagKey] = *tag.TagValue
			}
		}
	}

	return info
}

func printEnabledKeysTable(keys []KeyInfo, tagKeys []string) {
	// Build header
	headers := []string{"Key ID", "Status", "Creation Date", "Key Type"}
	headers = append(headers, tagKeys...)

	// Calculate column widths
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = len(h)
	}

	// Date format for display
	dateFormat := "2006-01-02 15:04:05"

	// Calculate max widths from data
	for _, key := range keys {
		if len(key.KeyID) > widths[0] {
			widths[0] = len(key.KeyID)
		}
		if len(key.Status) > widths[1] {
			widths[1] = len(key.Status)
		}
		dateStr := key.CreationDate.Format(dateFormat)
		if len(dateStr) > widths[2] {
			widths[2] = len(dateStr)
		}
		if len(key.KeyType) > widths[3] {
			widths[3] = len(key.KeyType)
		}
		for i, tagKey := range tagKeys {
			tagValue := key.Tags[tagKey]
			if len(tagValue) > widths[i+4] {
				widths[i+4] = len(tagValue)
			}
		}
	}

	// Print header
	printRow(headers, widths)
	printSeparator(widths)

	// Print data rows
	for _, key := range keys {
		row := []string{
			key.KeyID,
			key.Status,
			key.CreationDate.Format(dateFormat),
			key.KeyType,
		}
		for _, tagKey := range tagKeys {
			tagValue := key.Tags[tagKey]
			if tagValue == "" {
				tagValue = "-"
			}
			row = append(row, tagValue)
		}
		printRow(row, widths)
	}
}

func printNotAuthorizedKeysTable(keys []KeyInfo) {
	headers := []string{"Key ID", "Status"}

	// Calculate column widths
	widths := []int{len(headers[0]), len(headers[1])}

	for _, key := range keys {
		if len(key.KeyID) > widths[0] {
			widths[0] = len(key.KeyID)
		}
		if len(key.Status) > widths[1] {
			widths[1] = len(key.Status)
		}
	}

	// Print header
	printRow(headers, widths)
	printSeparator(widths)

	// Print data rows
	for _, key := range keys {
		row := []string{key.KeyID, key.Status}
		printRow(row, widths)
	}
}

func printRow(values []string, widths []int) {
	for i, v := range values {
		fmt.Printf("| %-*s ", widths[i], v)
	}
	fmt.Println("|")
}

func printSeparator(widths []int) {
	for _, w := range widths {
		fmt.Printf("+-%s-", strings.Repeat("-", w))
	}
	fmt.Println("+")
}
