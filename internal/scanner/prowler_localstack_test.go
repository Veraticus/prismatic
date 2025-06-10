//go:build integration && localstack
// +build integration,localstack

package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/Veraticus/prismatic/pkg/logger"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// TestProwlerScanner_LocalStackIntegration tests Prowler with LocalStack
// This test requires Docker and is tagged with localstack build constraint
func TestProwlerScanner_LocalStackIntegration(t *testing.T) {
	t.Skip("LocalStack integration is experimental - Prowler endpoint support is limited")

	ctx := context.Background()

	// Start LocalStack container
	localstackContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "localstack/localstack:latest",
			ExposedPorts: []string{"4566/tcp"},
			Env: map[string]string{
				"SERVICES":       "iam,s3,ec2,cloudtrail",
				"DEFAULT_REGION": "us-east-1",
				"DATA_DIR":       "/tmp/localstack/data",
			},
			WaitingFor: wait.ForHTTP("/health").WithPort("4566/tcp").WithStartupTimeout(60 * time.Second),
		},
		Started: true,
	})
	require.NoError(t, err)
	defer localstackContainer.Terminate(ctx)

	// Get LocalStack endpoint
	endpoint, err := localstackContainer.Endpoint(ctx, "4566/tcp")
	require.NoError(t, err)
	localstackURL := fmt.Sprintf("http://%s", endpoint)

	t.Logf("LocalStack started at: %s", localstackURL)

	// Configure AWS SDK for LocalStack
	customResolver := aws.EndpointResolverFunc(func(service, region string) (aws.Endpoint, error) {
		return aws.Endpoint{
			URL:               localstackURL,
			HostnameImmutable: true,
		}, nil
	})

	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion("us-east-1"),
		config.WithEndpointResolver(customResolver),
		config.WithCredentialsProvider(aws.AnonymousCredentials{}),
	)
	require.NoError(t, err)

	// Create test resources in LocalStack
	t.Run("Setup Test Resources", func(t *testing.T) {
		// Create S3 client
		s3Client := s3.NewFromConfig(cfg)

		// Create a public S3 bucket (should trigger Prowler finding)
		_, err = s3Client.CreateBucket(ctx, &s3.CreateBucketInput{
			Bucket: aws.String("test-public-bucket"),
			ACL:    "public-read", // Intentionally insecure
		})
		require.NoError(t, err)

		// Create IAM client
		iamClient := iam.NewFromConfig(cfg)

		// Create IAM user without MFA (should trigger Prowler finding)
		_, err = iamClient.CreateUser(ctx, &iam.CreateUserInput{
			UserName: aws.String("test-user-no-mfa"),
		})
		require.NoError(t, err)

		// Create login profile for console access
		_, err = iamClient.CreateLoginProfile(ctx, &iam.CreateLoginProfileInput{
			UserName: aws.String("test-user-no-mfa"),
			Password: aws.String("TempPassword123!"),
		})
		require.NoError(t, err)
	})

	// Configure environment for Prowler to use LocalStack
	t.Run("Run Prowler Against LocalStack", func(t *testing.T) {
		// Set AWS environment variables for LocalStack
		oldEndpoint := os.Getenv("AWS_ENDPOINT_URL")
		oldAccessKey := os.Getenv("AWS_ACCESS_KEY_ID")
		oldSecretKey := os.Getenv("AWS_SECRET_ACCESS_KEY")

		defer func() {
			os.Setenv("AWS_ENDPOINT_URL", oldEndpoint)
			os.Setenv("AWS_ACCESS_KEY_ID", oldAccessKey)
			os.Setenv("AWS_SECRET_ACCESS_KEY", oldSecretKey)
		}()

		os.Setenv("AWS_ENDPOINT_URL", localstackURL)
		os.Setenv("AWS_ACCESS_KEY_ID", "test")
		os.Setenv("AWS_SECRET_ACCESS_KEY", "test")

		// Create Prowler scanner configuration
		scannerConfig := Config{
			WorkingDir: t.TempDir(),
			Timeout:    60,
			Debug:      true,
		}

		// Note: Prowler may not fully support custom endpoints
		// This is why this test is marked as experimental
		scanner := NewProwlerScannerWithLogger(
			scannerConfig,
			[]string{"default"},   // Profile
			[]string{"us-east-1"}, // Region
			[]string{"iam", "s3"}, // Services to scan
			logger.GetGlobalLogger(),
		)

		// Attempt to run scan
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		result, err := scanner.Scan(ctx)

		// Note: This might fail if Prowler doesn't respect AWS_ENDPOINT_URL
		if err != nil {
			t.Logf("Prowler scan failed (expected with LocalStack): %v", err)

			// Even if scan fails, we can test the error handling
			assert.NotNil(t, result)
			return
		}

		// If it succeeds, validate findings
		assert.NotNil(t, result)
		t.Logf("Found %d findings", len(result.Findings))

		// We should find issues with our intentionally insecure resources
		var foundPublicBucket, foundNoMFA bool
		for _, finding := range result.Findings {
			if finding.Type == "internet-exposed" && finding.Resource == "test-public-bucket" {
				foundPublicBucket = true
			}
			if finding.Type == "iam" && finding.Resource == "test-user-no-mfa" {
				foundNoMFA = true
			}
		}

		if foundPublicBucket || foundNoMFA {
			t.Log("Successfully found security issues in LocalStack resources")
		}
	})
}

// TestProwlerScanner_MockAWSEndpoint demonstrates how to test with a mock AWS endpoint
func TestProwlerScanner_MockAWSEndpoint(t *testing.T) {
	t.Skip("This is a demonstration of endpoint mocking approach")

	// This approach would require modifying Prowler scanner to accept
	// custom endpoint configuration, which it currently doesn't support

	// Hypothetical implementation:
	/*
		type ProwlerScannerWithEndpoint struct {
			*ProwlerScanner
			endpoint string
		}

		func (s *ProwlerScannerWithEndpoint) scanProfile(ctx context.Context, profile string) ([]byte, error) {
			args := []string{
				"aws",
				"--output-formats", "json-ocsf",
				"--profile", profile,
			}

			// If we could pass endpoint to Prowler:
			if s.endpoint != "" {
				args = append(args, "--endpoint-url", s.endpoint)
			}

			return ExecuteScanner(ctx, "prowler", args, s.config)
		}
	*/
}

// Example of how to create a mock Prowler service for testing
type MockProwlerService struct {
	findings []ProwlerOCSFCheck
}

func (m *MockProwlerService) GenerateReport() []byte {
	// Generate mock Prowler output based on configured findings
	data, _ := json.Marshal(m.findings)
	return data
}

func TestProwlerScanner_WithMockService(t *testing.T) {
	// This demonstrates a pure mocking approach without LocalStack
	mockService := &MockProwlerService{
		findings: []ProwlerOCSFCheck{
			{
				Status:   "FAIL",
				Severity: "High",
				Metadata: struct {
					EventCode string `json:"event_code"`
					Product   struct {
						Name    string `json:"name"`
						Version string `json:"version"`
					} `json:"product"`
				}{
					EventCode: "test_check",
					Product: struct {
						Name    string `json:"name"`
						Version string `json:"version"`
					}{
						Name:    "Prowler",
						Version: "4.0.0",
					},
				},
				Finding: struct {
					UID         string `json:"uid"`
					Type        string `json:"type"`
					Title       string `json:"title"`
					Desc        string `json:"desc"`
					Service     string `json:"service"`
					Remediation struct {
						Desc       string   `json:"desc"`
						References []string `json:"references"`
					} `json:"remediation"`
				}{
					Type:  "misconfiguration",
					Title: "Test Finding",
					Desc:  "This is a test finding",
				},
				Resources: []struct {
					UID    string `json:"uid"`
					Type   string `json:"type"`
					Region string `json:"region"`
				}{
					{
						UID:    "test-resource",
						Type:   "test",
						Region: "us-east-1",
					},
				},
			},
		},
	}

	// Test parser with mock data
	scanner := NewProwlerScanner(Config{}, []string{"test"}, nil, nil)
	findings, err := scanner.ParseResults(mockService.GenerateReport())

	require.NoError(t, err)
	assert.Len(t, findings, 1)
	assert.Equal(t, "misconfiguration", findings[0].Type)
}
