//go:build integration

package integration

import "testing"

func TestRolloutSharedState(t *testing.T) {
	requireCompose(t)
	t.Skip("multi-haproxy rollout topology not started in default compose")
}

func TestRolloutBackendSignals(t *testing.T) { TestRolloutSharedState(t) }
func TestRolloutOutages(t *testing.T)          { TestRolloutSharedState(t) }

func TestLoadReport(t *testing.T) {
	t.Skip("load report requires it-load harness")
}

