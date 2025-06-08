package pathutil

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidatePath(t *testing.T) {
	tests := []struct {
		name            string
		path            string
		errContains     string
		allowedBaseDirs []string
		wantErr         bool
	}{
		{
			name:    "valid relative path",
			path:    "configs/test.yaml",
			wantErr: false,
		},
		{
			name:        "path with directory traversal",
			path:        "../../../etc/passwd",
			wantErr:     true,
			errContains: "directory traversal",
		},
		{
			name:        "path with embedded traversal",
			path:        "configs/../../../etc/passwd",
			wantErr:     true,
			errContains: "directory traversal",
		},
		{
			name:            "path within allowed directory",
			path:            "data/scans/test.json",
			allowedBaseDirs: []string{".", "data"},
			wantErr:         false,
		},
		{
			name:            "path outside allowed directory",
			path:            "/etc/passwd",
			allowedBaseDirs: []string{"data"},
			wantErr:         true,
			errContains:     "not within allowed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ValidatePath(tt.path, tt.allowedBaseDirs...)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				require.NoError(t, err)
				assert.NotEmpty(t, got)
				// Result should be absolute
				assert.True(t, filepath.IsAbs(got))
			}
		})
	}
}

func TestValidateConfigPath(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		errContains string
		wantErr     bool
	}{
		{
			name:    "valid yaml config",
			path:    "configs/test.yaml",
			wantErr: false,
		},
		{
			name:    "valid yml config",
			path:    "configs/test.yml",
			wantErr: false,
		},
		{
			name:        "invalid extension",
			path:        "configs/test.json",
			wantErr:     true,
			errContains: "extension",
		},
		{
			name:        "path traversal attempt",
			path:        "../../../etc/passwd.yaml",
			wantErr:     true,
			errContains: "directory traversal",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ValidateConfigPath(tt.path)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				require.NoError(t, err)
				assert.NotEmpty(t, got)
			}
		})
	}
}

func TestValidateOutputPath(t *testing.T) {
	// Create a temp directory for testing
	tmpDir := t.TempDir()

	tests := []struct {
		setup       func()
		name        string
		path        string
		errContains string
		wantErr     bool
	}{
		{
			name:    "valid output path in existing directory",
			path:    filepath.Join(tmpDir, "output.html"),
			wantErr: false,
		},
		{
			name:        "output path in non-existent directory",
			path:        filepath.Join(tmpDir, "nonexistent", "output.html"),
			wantErr:     true,
			errContains: "parent directory does not exist",
		},
	}

	// Change to temp directory for test
	oldWd, err := os.Getwd()
	require.NoError(t, err)
	defer func() {
		_ = os.Chdir(oldWd)
	}()

	err = os.Chdir(tmpDir)
	require.NoError(t, err)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setup != nil {
				tt.setup()
			}

			got, err := ValidateOutputPath(tt.path)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				require.NoError(t, err)
				assert.NotEmpty(t, got)
			}
		})
	}
}

func TestJoinAndValidate(t *testing.T) {
	baseDir := "/tmp/test"

	tests := []struct {
		name        string
		baseDir     string
		errContains string
		elems       []string
		wantErr     bool
	}{
		{
			name:    "valid join",
			baseDir: baseDir,
			elems:   []string{"subdir", "file.txt"},
			wantErr: false,
		},
		{
			name:        "join with traversal",
			baseDir:     baseDir,
			elems:       []string{"subdir", "..", "..", "..", "etc", "passwd"},
			wantErr:     true,
			errContains: "directory traversal",
		},
		{
			name:    "empty elements",
			baseDir: baseDir,
			elems:   []string{},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := JoinAndValidate(tt.baseDir, tt.elems...)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				require.NoError(t, err)
				assert.NotEmpty(t, got)
			}
		})
	}
}

func TestIsWithinDirectory(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		dir     string
		want    bool
		wantErr bool
	}{
		{
			name: "path within directory",
			path: "/home/user/project/file.txt",
			dir:  "/home/user/project",
			want: true,
		},
		{
			name: "path outside directory",
			path: "/home/user/other/file.txt",
			dir:  "/home/user/project",
			want: false,
		},
		{
			name: "path is the directory",
			path: "/home/user/project",
			dir:  "/home/user/project",
			want: true,
		},
		{
			name: "relative paths",
			path: "data/file.txt",
			dir:  "data",
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := IsWithinDirectory(tt.path, tt.dir)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}
