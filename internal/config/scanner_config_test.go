package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfig_ScannerConfiguration(t *testing.T) {
	t.Run("Parse scanner configuration", func(t *testing.T) {
		yamlContent := `
client:
  name: TestClient
  environment: test

aws:
  profiles:
    - default

scanners:
  prowler:
    enabled: true
  trivy:
    enabled: false
  nuclei:
    enabled: true
`
		// Create temp file
		tmpDir := t.TempDir()
		configFile := filepath.Join(tmpDir, "test-config.yaml")
		require.NoError(t, os.WriteFile(configFile, []byte(yamlContent), 0600))

		// Load config
		cfg, err := LoadConfig(configFile)
		require.NoError(t, err)
		require.NotNil(t, cfg)

		// Verify scanner configuration
		assert.NotNil(t, cfg.Scanners)
		assert.Len(t, cfg.Scanners, 3)

		// Check individual scanner settings
		assert.True(t, cfg.Scanners["prowler"].Enabled)
		assert.False(t, cfg.Scanners["trivy"].Enabled)
		assert.True(t, cfg.Scanners["nuclei"].Enabled)
	})

	t.Run("No scanner configuration - defaults to nil", func(t *testing.T) {
		yamlContent := `
client:
  name: TestClient
  environment: test

aws:
  profiles:
    - default
`
		// Create temp file
		tmpDir := t.TempDir()
		configFile := filepath.Join(tmpDir, "test-config.yaml")
		require.NoError(t, os.WriteFile(configFile, []byte(yamlContent), 0600))

		// Load config
		cfg, err := LoadConfig(configFile)
		require.NoError(t, err)
		require.NotNil(t, cfg)

		// Scanner config should be nil (all enabled by default)
		assert.Nil(t, cfg.Scanners)
	})

	t.Run("Empty scanner configuration", func(t *testing.T) {
		yamlContent := `
client:
  name: TestClient
  environment: test

aws:
  profiles:
    - default

scanners: {}
`
		// Create temp file
		tmpDir := t.TempDir()
		configFile := filepath.Join(tmpDir, "test-config.yaml")
		require.NoError(t, os.WriteFile(configFile, []byte(yamlContent), 0600))

		// Load config
		cfg, err := LoadConfig(configFile)
		require.NoError(t, err)
		require.NotNil(t, cfg)

		// Scanner config should be empty map
		assert.NotNil(t, cfg.Scanners)
		assert.Len(t, cfg.Scanners, 0)
	})
}
