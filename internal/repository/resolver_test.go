package repository

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/joshsymonds/prismatic/internal/config"
	"github.com/joshsymonds/prismatic/pkg/logger"
)

func TestIsLocalPath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{
			name:     "http URL",
			path:     "https://github.com/user/repo",
			expected: false,
		},
		{
			name:     "git URL",
			path:     "git@github.com:user/repo.git",
			expected: false,
		},
		{
			name:     "ssh URL",
			path:     "ssh://git@github.com/user/repo",
			expected: false,
		},
		{
			name:     "absolute path",
			path:     "/home/user/projects/repo",
			expected: true,
		},
		{
			name:     "relative path with ./",
			path:     "./local-repo",
			expected: true,
		},
		{
			name:     "relative path with ../",
			path:     "../other-repo",
			expected: true,
		},
		{
			name:     "existing directory",
			path:     ".",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isLocalPath(tt.path)
			if result != tt.expected {
				t.Errorf("isLocalPath(%q) = %v, want %v", tt.path, result, tt.expected)
			}
		})
	}
}

func TestGenerateRepoDir(t *testing.T) {
	baseDir := "/tmp/repos"

	tests := []struct {
		name string
		repo config.Repository
	}{
		{
			name: "simple name",
			repo: config.Repository{
				Name: "myrepo",
				Path: "https://github.com/user/myrepo",
			},
		},
		{
			name: "name with slashes",
			repo: config.Repository{
				Name: "org/repo",
				Path: "https://github.com/org/repo",
			},
		},
		{
			name: "name with spaces",
			repo: config.Repository{
				Name: "my repo",
				Path: "https://github.com/user/my-repo",
			},
		},
		{
			name: "same name different URLs",
			repo: config.Repository{
				Name: "repo",
				Path: "https://github.com/user1/repo",
			},
		},
	}

	seenPaths := make(map[string]bool)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := generateRepoDir(baseDir, tt.repo)

			// Should start with base directory
			if !strings.HasPrefix(result, baseDir) {
				t.Errorf("Path %q doesn't start with base directory %q", result, baseDir)
			}

			// Should contain the safe name
			safeName := filepath.Base(result)
			if safeName == "" || safeName == "." || safeName == "/" {
				t.Errorf("Invalid directory name: %q", safeName)
			}

			// Should be unique
			if seenPaths[result] {
				t.Errorf("Duplicate path generated: %q", result)
			}
			seenPaths[result] = true
		})
	}
}

func TestNewGitResolver(t *testing.T) {
	ctx := context.Background()

	t.Run("local path resolution", func(t *testing.T) {
		// Create a temporary directory
		tmpDir := t.TempDir()

		resolver := NewGitResolver(
			WithLogger(logger.NewMockLogger()),
		)

		repo := config.Repository{
			Name:   "test-repo",
			Path:   tmpDir,
			Branch: "main",
		}

		path, cleanup, err := resolver(ctx, repo)
		if err != nil {
			t.Fatalf("Failed to resolve local path: %v", err)
		}
		defer cleanup()

		// Should return the absolute path
		absPath, _ := filepath.Abs(tmpDir)
		if path != absPath {
			t.Errorf("Expected absolute path %q, got %q", absPath, path)
		}
	})

	t.Run("non-existent local path", func(t *testing.T) {
		resolver := NewGitResolver(
			WithLogger(logger.NewMockLogger()),
		)

		repo := config.Repository{
			Name:   "test-repo",
			Path:   "/non/existent/path",
			Branch: "main",
		}

		_, _, err := resolver(ctx, repo)
		if err == nil {
			t.Error("Expected error for non-existent path")
		}
	})

	t.Run("skip clone mode", func(t *testing.T) {
		resolver := NewGitResolver(
			WithSkipClone(true),
			WithLogger(logger.NewMockLogger()),
		)

		repo := config.Repository{
			Name:   "test-repo",
			Path:   "https://github.com/user/repo",
			Branch: "main",
		}

		_, _, err := resolver(ctx, repo)
		if err == nil {
			t.Error("Expected error when skip clone is enabled for remote URL")
		}
	})
}

func TestNewLocalResolver(t *testing.T) {
	ctx := context.Background()

	t.Run("existing directory", func(t *testing.T) {
		tmpDir := t.TempDir()

		resolver := NewLocalResolver(
			WithLogger(logger.NewMockLogger()),
		)

		repo := config.Repository{
			Name: "test-repo",
			Path: tmpDir,
		}

		path, cleanup, err := resolver(ctx, repo)
		if err != nil {
			t.Fatalf("Failed to resolve local path: %v", err)
		}
		defer cleanup()

		// Should return absolute path
		absPath, _ := filepath.Abs(tmpDir)
		if path != absPath {
			t.Errorf("Expected absolute path %q, got %q", absPath, path)
		}
	})

	t.Run("non-existent directory", func(t *testing.T) {
		resolver := NewLocalResolver(
			WithLogger(logger.NewMockLogger()),
		)

		repo := config.Repository{
			Name: "test-repo",
			Path: "/non/existent/path",
		}

		_, _, err := resolver(ctx, repo)
		if err == nil {
			t.Error("Expected error for non-existent directory")
		}
	})
}

func TestNewMockResolver(t *testing.T) {
	ctx := context.Background()

	t.Run("predefined paths", func(t *testing.T) {
		mockPaths := map[string]string{
			"repo1": "/mock/path/repo1",
			"repo2": "/mock/path/repo2",
		}

		resolver := NewMockResolver(mockPaths)

		repo := config.Repository{
			Name: "repo1",
			Path: "https://github.com/user/repo1",
		}

		path, cleanup, err := resolver(ctx, repo)
		if err != nil {
			t.Fatalf("Failed to resolve mock path: %v", err)
		}
		defer cleanup()

		if path != mockPaths["repo1"] {
			t.Errorf("Expected path %q, got %q", mockPaths["repo1"], path)
		}
	})

	t.Run("unknown repository creates temp dir", func(t *testing.T) {
		resolver := NewMockResolver(map[string]string{})

		repo := config.Repository{
			Name: "unknown-repo",
			Path: "https://github.com/user/unknown",
		}

		path, cleanup, err := resolver(ctx, repo)
		if err != nil {
			t.Fatalf("Failed to create temp directory: %v", err)
		}
		defer cleanup()

		// Should create a temporary directory
		if _, err := os.Stat(path); os.IsNotExist(err) {
			t.Errorf("Temporary directory was not created: %s", path)
		}

		// Cleanup should remove the directory
		cleanup()
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("Temporary directory was not cleaned up: %s", path)
		}
	})
}

func TestResolverOptions(t *testing.T) {
	t.Run("all options", func(t *testing.T) {
		opts := &resolverOptions{}

		WithBaseDir("/custom/base")(opts)
		WithGitPath("/usr/local/bin/git")(opts)
		WithSkipClone(true)(opts)
		WithKeepClones(true)(opts)
		WithSSHKeyPath("/home/user/.ssh/id_rsa")(opts)
		WithHTTPTimeout(600)(opts)

		if opts.baseDir != "/custom/base" {
			t.Errorf("baseDir = %q, want %q", opts.baseDir, "/custom/base")
		}
		if opts.gitPath != "/usr/local/bin/git" {
			t.Errorf("gitPath = %q, want %q", opts.gitPath, "/usr/local/bin/git")
		}
		if !opts.skipClone {
			t.Error("skipClone should be true")
		}
		if !opts.keepClones {
			t.Error("keepClones should be true")
		}
		if opts.sshKeyPath != "/home/user/.ssh/id_rsa" {
			t.Errorf("sshKeyPath = %q, want %q", opts.sshKeyPath, "/home/user/.ssh/id_rsa")
		}
		if opts.httpTimeout != 600 {
			t.Errorf("httpTimeout = %d, want %d", opts.httpTimeout, 600)
		}
	})
}

func TestMakeCleanup(t *testing.T) {
	t.Run("cleanup removes directory", func(t *testing.T) {
		tmpDir := t.TempDir()
		testFile := filepath.Join(tmpDir, "test.txt")

		// Create a test file
		if err := os.WriteFile(testFile, []byte("test"), 0600); err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}

		cleanup := makeCleanup(tmpDir, false, logger.NewMockLogger())

		// Directory should exist before cleanup
		if _, err := os.Stat(tmpDir); os.IsNotExist(err) {
			t.Error("Directory should exist before cleanup")
		}

		// Run cleanup
		cleanup()

		// Directory should be removed after cleanup
		if _, err := os.Stat(tmpDir); !os.IsNotExist(err) {
			t.Error("Directory should be removed after cleanup")
		}
	})

	t.Run("keep clones prevents deletion", func(t *testing.T) {
		tmpDir := t.TempDir()

		cleanup := makeCleanup(tmpDir, true, logger.NewMockLogger())

		// Run cleanup
		cleanup()

		// Directory should still exist
		if _, err := os.Stat(tmpDir); os.IsNotExist(err) {
			t.Error("Directory should not be removed when keepClones is true")
		}
	})
}
