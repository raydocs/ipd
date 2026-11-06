//go:build !linux && !darwin

package nodes

import "context"

func runnerOwnershipAvailable() error                            { return ErrRunnerUnsupported }
func runnerOwnsListener(context.Context, int, int) (bool, error) { return false, ErrRunnerUnsupported }
