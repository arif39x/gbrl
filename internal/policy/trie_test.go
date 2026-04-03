package policy_test

import (
	"testing"

	"github.com/local/gbrl/internal/policy"
)

func TestTrie_AllowedPaths(t *testing.T) {
	tr := policy.NewTrie()
	tr.Insert("/tmp/")
	tr.Insert("/proc/self/")

	allowed := []string{
		"/tmp/foo",
		"/tmp/bar/baz",
		"/proc/self/fd",
	}
	denied := []string{
		"/etc/passwd",
		"/home/user/.ssh/id_rsa",
		"/proc/1/maps", // different PID
	}

	for _, p := range allowed {
		if !tr.IsAllowed(p) {
			t.Errorf("expected %q to be allowed", p)
		}
	}
	for _, p := range denied {
		if tr.IsAllowed(p) {
			t.Errorf("expected %q to be denied", p)
		}
	}
}

func TestTrie_EmptyAllowsAll(t *testing.T) {
	tr := policy.NewTrie()
	if !tr.IsAllowed("/etc/passwd") {
		t.Error("empty trie should allow everything")
	}
}

func BenchmarkTrie_IsAllowed(b *testing.B) {
	tr := policy.NewTrie()
	tr.Insert("/tmp/")
	tr.Insert("/usr/lib/")
	tr.Insert("/proc/self/")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = tr.IsAllowed("/tmp/some/deep/path/file.txt")
	}
}
