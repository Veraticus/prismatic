package scanner

import "errors"

// ErrNoTargets indicates a scanner has no targets configured and should be skipped.
var ErrNoTargets = errors.New("no targets configured")

// IsNoTargetsError checks if an error indicates no targets are configured.
func IsNoTargetsError(err error) bool {
	return errors.Is(err, ErrNoTargets)
}
