package blocker

import (
	"os"
	"strings"
	"testing"
)

func TestNew(t *testing.T) {
	b := New()
	if b.BlockCount() != 0 || b.AllowCount() != 0 {
		t.Error("new blocker should be empty")
	}
}

func TestBlock_IsBlocked(t *testing.T) {
	b := New()
	b.Block("evil.example.com")
	if !b.IsBlocked("evil.example.com") {
		t.Error("blocked domain should be detected")
	}
}

func TestBlock_UnblockedDomain_NotDetected(t *testing.T) {
	b := New()
	if b.IsBlocked("google.com") {
		t.Error("unblocked domain should not be detected")
	}
}

func TestAllow_OverridesBlock(t *testing.T) {
	b := New()
	b.Block("cdn.example.com")
	b.Allow("cdn.example.com")
	if b.IsBlocked("cdn.example.com") {
		t.Error("allowed domain should override block")
	}
}

func TestUnblock_RemovesEntry(t *testing.T) {
	b := New()
	b.Block("temp.example.com")
	b.Unblock("temp.example.com")
	if b.IsBlocked("temp.example.com") {
		t.Error("unblocked domain should no longer be detected")
	}
}

func TestCaseInsensitive(t *testing.T) {
	b := New()
	b.Block("MALWARE.EXAMPLE.COM")
	if !b.IsBlocked("malware.example.com") {
		t.Error("lookup should be case-insensitive")
	}
}

func TestTrailingDotStripped(t *testing.T) {
	b := New()
	b.Block("fqdn.example.com.")
	if !b.IsBlocked("fqdn.example.com") {
		t.Error("trailing dot (FQDN) should be stripped before comparison")
	}
}

func TestSubdomainNotAutoBlocked(t *testing.T) {
	b := New()
	b.Block("evil.com")
	if b.IsBlocked("sub.evil.com") {
		t.Error("exact-match blocker should not block subdomains automatically")
	}
}

func TestBlockCount(t *testing.T) {
	b := New()
	b.Block("a.com")
	b.Block("b.com")
	b.Block("c.com")
	if b.BlockCount() != 3 {
		t.Errorf("expected 3 blocked domains, got %d", b.BlockCount())
	}
}

func TestAllowCount(t *testing.T) {
	b := New()
	b.Allow("safe.com")
	b.Allow("also-safe.com")
	if b.AllowCount() != 2 {
		t.Errorf("expected 2 allowed domains, got %d", b.AllowCount())
	}
}

func TestLoadReader_HostsFormat(t *testing.T) {
	input := "# blocklist\n0.0.0.0 malware1.example.com\n0.0.0.0 malware2.example.com\n127.0.0.1 tracker.example.com\n"
	b := New()
	n := b.LoadReader(strings.NewReader(input))
	if n != 3 {
		t.Errorf("expected 3 domains loaded, got %d", n)
	}
	if !b.IsBlocked("malware1.example.com") {
		t.Error("malware1 should be blocked")
	}
	if !b.IsBlocked("tracker.example.com") {
		t.Error("tracker should be blocked")
	}
}

func TestLoadReader_BareDomainFormat(t *testing.T) {
	input := "bare.example.com\nanother.example.com\n"
	b := New()
	n := b.LoadReader(strings.NewReader(input))
	if n != 2 {
		t.Errorf("expected 2 domains, got %d", n)
	}
	if !b.IsBlocked("bare.example.com") {
		t.Error("bare domain format should be supported")
	}
}

func TestLoadReader_SkipsComments(t *testing.T) {
	input := "# comment\n# another\ngood.example.com\n"
	b := New()
	n := b.LoadReader(strings.NewReader(input))
	if n != 1 {
		t.Errorf("expected 1 domain (comments skipped), got %d", n)
	}
}

func TestLoadReader_SkipsBlankLines(t *testing.T) {
	input := "\n\nfoo.example.com\n\n\nbar.example.com\n\n"
	b := New()
	n := b.LoadReader(strings.NewReader(input))
	if n != 2 {
		t.Errorf("expected 2 domains (blank lines skipped), got %d", n)
	}
}

func TestLoadReader_SkipsLocalhost(t *testing.T) {
	input := "0.0.0.0 localhost\n0.0.0.0 evil.com\n"
	b := New()
	b.LoadReader(strings.NewReader(input))
	if b.IsBlocked("localhost") {
		t.Error("localhost should never be blocked")
	}
}

func TestLoadReader_EmptyInput(t *testing.T) {
	b := New()
	n := b.LoadReader(strings.NewReader(""))
	if n != 0 {
		t.Errorf("empty input should add 0 domains, got %d", n)
	}
}

func TestLoadFile_NonExistent(t *testing.T) {
	b := New()
	_, err := b.LoadFile("/nonexistent/path/blocklist.txt")
	if err == nil {
		t.Error("expected error for non-existent file")
	}
}

func TestLoadDir_MultipleFiles(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir+"/malware.txt", "0.0.0.0 malware.bad\n0.0.0.0 botnet.bad\n")
	writeFile(t, dir+"/ads.txt", "0.0.0.0 ads.bad\n")

	b := New()
	total, err := b.LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if total != 3 {
		t.Errorf("expected 3 domains loaded from dir, got %d", total)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}
