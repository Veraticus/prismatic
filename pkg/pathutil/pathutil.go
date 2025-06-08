// Package pathutil provides utilities for safe path handling and validation.
package pathutil

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ValidatePath validates that a path is safe to use for file operations.
// It ensures the path doesn't contain directory traversal attempts and
// optionally checks if it's within allowed base directories.
func ValidatePath(path string, allowedBaseDirs ...string) (string, error) {
	// Clean the path to remove any ../ or ./ components
	cleanPath := filepath.Clean(path)

	// Convert to absolute path
	absPath, err := filepath.Abs(cleanPath)
	if err != nil {
		return "", fmt.Errorf("getting absolute path: %w", err)
	}

	// Check for suspicious patterns
	if strings.Contains(path, "..") {
		return "", fmt.Errorf("path contains directory traversal pattern: %s", path)
	}

	// If no allowed base directories specified, just return the cleaned absolute path
	if len(allowedBaseDirs) == 0 {
		return absPath, nil
	}

	// Check if path is within allowed base directories
	for _, baseDir := range allowedBaseDirs {
		absBase, err := filepath.Abs(baseDir)
		if err != nil {
			continue
		}

		// Ensure both paths end with separator for proper prefix matching
		if !strings.HasSuffix(absBase, string(filepath.Separator)) {
			absBase += string(filepath.Separator)
		}

		if strings.HasPrefix(absPath, absBase) || absPath == strings.TrimSuffix(absBase, string(filepath.Separator)) {
			return absPath, nil
		}
	}

	return "", fmt.Errorf("path %s is not within allowed directories", cleanPath)
}

// ValidateConfigPath validates a configuration file path.
// Config files are expected to be YAML files.
func ValidateConfigPath(path string) (string, error) {
	// Clean and get absolute path
	cleanPath := filepath.Clean(path)
	absPath, err := filepath.Abs(cleanPath)
	if err != nil {
		return "", fmt.Errorf("getting absolute path: %w", err)
	}

	// Check for directory traversal attempts
	if strings.Contains(path, "..") {
		return "", fmt.Errorf("path contains directory traversal pattern: %s", path)
	}

	// Check file extension
	ext := strings.ToLower(filepath.Ext(absPath))
	if ext != ".yaml" && ext != ".yml" {
		return "", fmt.Errorf("config file must have .yaml or .yml extension, got %s", ext)
	}

	return absPath, nil
}

// ValidateOutputPath validates an output file path for reports.
// It ensures the parent directory exists and the path is safe.
func ValidateOutputPath(path string) (string, error) {
	// Clean and get absolute path
	cleanPath := filepath.Clean(path)
	absPath, err := filepath.Abs(cleanPath)
	if err != nil {
		return "", fmt.Errorf("getting absolute path: %w", err)
	}

	// Check for directory traversal attempts
	if strings.Contains(path, "..") {
		return "", fmt.Errorf("path contains directory traversal pattern: %s", path)
	}

	// Check parent directory exists
	dir := filepath.Dir(absPath)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return "", fmt.Errorf("parent directory does not exist: %s", dir)
	}

	return absPath, nil
}

// ValidateDataPath validates a path within the data directory.
// This is used for scan results and other data files.
// If dataDir is empty, it just validates the path is safe.
func ValidateDataPath(path string, dataDir string) (string, error) {
	// Clean and get absolute path
	cleanPath := filepath.Clean(path)
	absPath, err := filepath.Abs(cleanPath)
	if err != nil {
		return "", fmt.Errorf("getting absolute path: %w", err)
	}

	// Check for directory traversal attempts
	if strings.Contains(path, "..") {
		return "", fmt.Errorf("path contains directory traversal pattern: %s", path)
	}

	// If no data directory specified, just return the clean absolute path
	if dataDir == "" {
		return absPath, nil
	}

	// Ensure data directory is absolute
	absDataDir, err := filepath.Abs(dataDir)
	if err != nil {
		return "", fmt.Errorf("getting absolute data directory: %w", err)
	}

	// Check if path is within data directory
	if !strings.HasSuffix(absDataDir, string(filepath.Separator)) {
		absDataDir += string(filepath.Separator)
	}

	if !strings.HasPrefix(absPath, absDataDir) && absPath != strings.TrimSuffix(absDataDir, string(filepath.Separator)) {
		return "", fmt.Errorf("path %s is not within data directory %s", cleanPath, dataDir)
	}

	return absPath, nil
}

// JoinAndValidate safely joins path components and validates the result.
func JoinAndValidate(baseDir string, elems ...string) (string, error) {
	// Check for directory traversal in elements
	for _, elem := range elems {
		if strings.Contains(elem, "..") {
			return "", fmt.Errorf("path element contains directory traversal: %s", elem)
		}
	}

	// Join the paths
	joined := filepath.Join(append([]string{baseDir}, elems...)...)

	// Get absolute paths for comparison
	absBase, err := filepath.Abs(baseDir)
	if err != nil {
		return "", fmt.Errorf("getting absolute base directory: %w", err)
	}

	absJoined, err := filepath.Abs(joined)
	if err != nil {
		return "", fmt.Errorf("getting absolute joined path: %w", err)
	}

	// Ensure joined path is within base directory
	if !strings.HasSuffix(absBase, string(filepath.Separator)) {
		absBase += string(filepath.Separator)
	}

	if !strings.HasPrefix(absJoined, absBase) && absJoined != strings.TrimSuffix(absBase, string(filepath.Separator)) {
		return "", fmt.Errorf("joined path %s is not within base directory %s", joined, baseDir)
	}

	return absJoined, nil
}

// IsWithinDirectory checks if a path is within a specific directory.
func IsWithinDirectory(path, dir string) (bool, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return false, err
	}

	absDir, err := filepath.Abs(dir)
	if err != nil {
		return false, err
	}

	// Ensure directory ends with separator
	if !strings.HasSuffix(absDir, string(filepath.Separator)) {
		absDir += string(filepath.Separator)
	}

	return strings.HasPrefix(absPath, absDir) || absPath == strings.TrimSuffix(absDir, string(filepath.Separator)), nil
}
