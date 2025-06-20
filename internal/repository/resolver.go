// Package repository provides Git repository cloning and management functionality
// for scanners that need to analyze source code.
package repository

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/joshsymonds/prismatic/pkg/logger"
)

// Repository represents a code repository.
type Repository struct {
	Name   string `yaml:"name"`
	Path   string `yaml:"path"`
	Branch string `yaml:"branch"`
}

// Resolver is a function that resolves a repository to a local path
// It returns the local path, a cleanup function, and an error.
type Resolver func(ctx context.Context, repo Repository) (localPath string, cleanup func(), err error)

// ResolverOption configures the resolver.
type ResolverOption func(*resolverOptions)

type resolverOptions struct {
	logger      logger.Logger
	baseDir     string
	gitPath     string
	sshKeyPath  string
	httpTimeout int
	skipClone   bool
	keepClones  bool
}

// WithBaseDir sets the base directory for cloning repositories.
func WithBaseDir(dir string) ResolverOption {
	return func(o *resolverOptions) {
		o.baseDir = dir
	}
}

// WithLogger sets the logger for the resolver.
func WithLogger(l logger.Logger) ResolverOption {
	return func(o *resolverOptions) {
		o.logger = l
	}
}

// WithGitPath sets a custom path to the git executable.
func WithGitPath(path string) ResolverOption {
	return func(o *resolverOptions) {
		o.gitPath = path
	}
}

// WithSkipClone configures the resolver to only validate local paths without cloning.
func WithSkipClone(skip bool) ResolverOption {
	return func(o *resolverOptions) {
		o.skipClone = skip
	}
}

// WithKeepClones prevents cleanup from deleting cloned repositories.
func WithKeepClones(keep bool) ResolverOption {
	return func(o *resolverOptions) {
		o.keepClones = keep
	}
}

// WithSSHKeyPath sets the SSH key path for private repository access.
func WithSSHKeyPath(path string) ResolverOption {
	return func(o *resolverOptions) {
		o.sshKeyPath = path
	}
}

// WithHTTPTimeout sets the timeout for HTTP operations in seconds.
func WithHTTPTimeout(seconds int) ResolverOption {
	return func(o *resolverOptions) {
		o.httpTimeout = seconds
	}
}

// NewGitResolver creates a resolver that clones Git repositories.
func NewGitResolver(opts ...ResolverOption) Resolver {
	options := &resolverOptions{
		baseDir:     filepath.Join(os.TempDir(), "prismatic-repos"),
		logger:      &nopLogger{},
		gitPath:     "git",
		skipClone:   false,
		keepClones:  false,
		httpTimeout: 300, // 5 minutes default
	}

	for _, opt := range opts {
		opt(options)
	}

	return func(ctx context.Context, repo Repository) (string, func(), error) {
		// If it's already a local path, just validate it exists
		if isLocalPath(repo.Path) {
			absPath, err := filepath.Abs(repo.Path)
			if err != nil {
				return "", noop, fmt.Errorf("invalid local path: %w", err)
			}

			if _, err := os.Stat(absPath); err != nil {
				return "", noop, fmt.Errorf("local repository not found: %w", err)
			}

			options.logger.Info("Using local repository", "name", repo.Name, "path", absPath)
			return absPath, noop, nil
		}

		// Skip cloning if configured
		if options.skipClone {
			return "", noop, fmt.Errorf("repository %s requires cloning but skip-clone is enabled", repo.Name)
		}

		// Generate a unique directory name based on repo URL and branch
		repoDir := generateRepoDir(options.baseDir, repo)

		// Check if already cloned
		if _, err := os.Stat(filepath.Join(repoDir, ".git")); err == nil {
			options.logger.Info("Repository already cloned", "name", repo.Name, "path", repoDir)

			// Update to the correct branch
			if err := checkoutBranch(ctx, repoDir, repo.Branch, options); err != nil {
				return "", noop, fmt.Errorf("failed to checkout branch: %w", err)
			}

			return repoDir, makeCleanup(repoDir, options.keepClones, options.logger), nil
		}

		// Create base directory if needed
		if err := os.MkdirAll(options.baseDir, 0750); err != nil {
			return "", noop, fmt.Errorf("failed to create base directory: %w", err)
		}

		// Clone the repository
		options.logger.Info("Cloning repository", "name", repo.Name, "url", repo.Path)
		if err := cloneRepo(ctx, repo, repoDir, options); err != nil {
			// Clean up on failure
			if removeErr := os.RemoveAll(repoDir); removeErr != nil {
				options.logger.Error("Failed to clean up after clone failure", "path", repoDir, "error", removeErr)
			}
			return "", noop, fmt.Errorf("failed to clone repository: %w", err)
		}

		return repoDir, makeCleanup(repoDir, options.keepClones, options.logger), nil
	}
}

// NewLocalResolver creates a resolver that only works with local paths.
func NewLocalResolver(opts ...ResolverOption) Resolver {
	options := &resolverOptions{
		logger: &nopLogger{},
	}

	for _, opt := range opts {
		opt(options)
	}

	return func(_ context.Context, repo Repository) (string, func(), error) {
		absPath, err := filepath.Abs(repo.Path)
		if err != nil {
			return "", noop, fmt.Errorf("invalid path: %w", err)
		}

		if _, err := os.Stat(absPath); err != nil {
			return "", noop, fmt.Errorf("repository not found: %w", err)
		}

		options.logger.Info("Using local repository", "name", repo.Name, "path", absPath)
		return absPath, noop, nil
	}
}

// NewMockResolver creates a resolver for testing that returns temporary directories.
func NewMockResolver(paths map[string]string) Resolver {
	return func(_ context.Context, repo Repository) (string, func(), error) {
		if path, ok := paths[repo.Name]; ok {
			return path, noop, nil
		}

		// Create a temporary directory for unknown repos
		tmpDir, err := os.MkdirTemp("", fmt.Sprintf("mock-repo-%s-*", repo.Name))
		if err != nil {
			return "", noop, err
		}

		return tmpDir, func() {
			if err := os.RemoveAll(tmpDir); err != nil {
				// Log error but don't fail - this is cleanup
				fmt.Fprintf(os.Stderr, "Failed to remove temp dir %s: %v\n", tmpDir, err)
			}
		}, nil
	}
}

// Helper functions

func isLocalPath(path string) bool {
	// Check if it's a URL
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") ||
		strings.HasPrefix(path, "git@") || strings.HasPrefix(path, "ssh://") {
		return false
	}

	// Check if it looks like a local path
	if filepath.IsAbs(path) || strings.HasPrefix(path, "./") || strings.HasPrefix(path, "../") {
		return true
	}

	// Check if it exists as a local path
	if _, err := os.Stat(path); err == nil {
		return true
	}

	return false
}

func generateRepoDir(baseDir string, repo Repository) string {
	// Create a hash of the URL for uniqueness
	h := sha256.New()
	h.Write([]byte(repo.Path))
	hash := fmt.Sprintf("%x", h.Sum(nil))[:8]

	// Clean the repo name for filesystem
	safeName := strings.ReplaceAll(repo.Name, "/", "-")
	safeName = strings.ReplaceAll(safeName, " ", "-")

	return filepath.Join(baseDir, fmt.Sprintf("%s-%s", safeName, hash))
}

func cloneRepo(ctx context.Context, repo Repository, targetDir string, options *resolverOptions) error {
	args := []string{"clone"}

	// Add branch if specified
	if repo.Branch != "" && repo.Branch != "main" && repo.Branch != "master" {
		args = append(args, "--branch", repo.Branch)
	}

	// Add depth, URL and target directory
	args = append(args, "--depth", "1", repo.Path, targetDir)

	cmd := exec.CommandContext(ctx, options.gitPath, args...)

	// Set up environment
	env := os.Environ()
	if options.sshKeyPath != "" {
		// Use SSH key if provided
		env = append(env, fmt.Sprintf("GIT_SSH_COMMAND=ssh -i %s -o StrictHostKeyChecking=no", options.sshKeyPath))
	}
	if options.httpTimeout > 0 {
		env = append(env, fmt.Sprintf("GIT_HTTP_LOW_SPEED_TIME=%d", options.httpTimeout))
	}
	cmd.Env = env

	// Capture output for debugging
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("git clone failed: %w\nOutput: %s", err, string(output))
	}

	return nil
}

func checkoutBranch(ctx context.Context, repoDir, branch string, options *resolverOptions) error {
	if branch == "" {
		return nil
	}

	cmd := exec.CommandContext(ctx, options.gitPath, "checkout", branch)
	cmd.Dir = repoDir

	output, err := cmd.CombinedOutput()
	if err != nil {
		// Try to pull the latest changes
		pullCmd := exec.CommandContext(ctx, options.gitPath, "pull", "origin", branch)
		pullCmd.Dir = repoDir

		if pullOutput, pullErr := pullCmd.CombinedOutput(); pullErr != nil {
			return fmt.Errorf("git checkout failed: %w\nOutput: %s\nPull output: %s", err, string(output), string(pullOutput))
		}
	}

	return nil
}

func makeCleanup(dir string, keepClones bool, log logger.Logger) func() {
	return func() {
		if keepClones {
			log.Debug("Keeping cloned repository", "path", dir)
			return
		}

		log.Debug("Cleaning up repository", "path", dir)
		if err := os.RemoveAll(dir); err != nil {
			log.Error("Failed to clean up repository", "path", dir, "error", err)
		}
	}
}

func noop() {}

// nopLogger is a no-op logger implementation.
type nopLogger struct{}

func (n *nopLogger) Debug(_ string, _ ...any)         {}
func (n *nopLogger) Info(_ string, _ ...any)          {}
func (n *nopLogger) Warn(_ string, _ ...any)          {}
func (n *nopLogger) Error(_ string, _ ...any)         {}
func (n *nopLogger) With(_ ...any) logger.Logger      { return n }
func (n *nopLogger) WithGroup(_ string) logger.Logger { return n }
