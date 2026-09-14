package main

import "testing"

func TestLocalImporterCandidateLimitIsSmallAndBounded(t *testing.T) {
	t.Setenv("IMPORTER_MAX_CANDIDATES", "")
	if got := localImporterCandidateLimit(); got != 12 {
		t.Fatalf("default probe limit = %d, want 12", got)
	}
	t.Setenv("IMPORTER_MAX_CANDIDATES", "999")
	if got := localImporterCandidateLimit(); got != 32 {
		t.Fatalf("capped probe limit = %d, want 32", got)
	}
	t.Setenv("IMPORTER_MAX_CANDIDATES", "not-a-number")
	if got := localImporterCandidateLimit(); got != 12 {
		t.Fatalf("invalid probe limit = %d, want 12", got)
	}
}
