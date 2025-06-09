package scanner

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// ExecuteScanner handles common command execution pattern for all scanners.
func ExecuteScanner(ctx context.Context, binary string, args []string, cfg Config) ([]byte, error) {
	cmd := exec.CommandContext(ctx, binary, args...)

	// Handle working directory (special case for scan output dirs)
	if cfg.WorkingDir != "" && !strings.Contains(cfg.WorkingDir, "data/scans") {
		cmd.Dir = cfg.WorkingDir
	}

	// Convert environment map to slice
	if cfg.Env != nil {
		env := os.Environ()
		for k, v := range cfg.Env {
			env = append(env, fmt.Sprintf("%s=%s", k, v))
		}
		cmd.Env = env
	}

	return cmd.Output()
}

// GetScannerVersion retrieves version with a parser function.
func GetScannerVersion(ctx context.Context, binary string, versionArg string, parser func([]byte) string) string {
	cmd := exec.CommandContext(ctx, binary, versionArg)
	output, err := cmd.Output()
	if err != nil {
		return "unknown"
	}
	return parser(output)
}

// HandleNonZeroExit interprets exit codes for scanners that return non-zero with findings.
func HandleNonZeroExit(err error, allowedCodes ...int) (bool, error) {
	if err == nil {
		return true, nil
	}

	if exitErr, ok := err.(*exec.ExitError); ok {
		for _, code := range allowedCodes {
			if exitErr.ExitCode() == code {
				return true, nil // Expected non-zero exit
			}
		}
	}
	return false, err
}
