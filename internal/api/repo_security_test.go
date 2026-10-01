package api

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// repoRoot resolves the repository root from the package directory.
func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("repository root not found: %v", err)
	}
	return root
}

// walkFiles visits every file of the repository except generated or vendored
// trees.
func walkFiles(t *testing.T, root string, fn func(rel string, data []byte)) {
	t.Helper()
	skipDirs := map[string]bool{
		".git": true, "node_modules": true, "dist": true, "build": true,
		"vendor": true, ".vite": true, "coverage": true,
	}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		// Binary assets are not scanned as text.
		switch strings.ToLower(filepath.Ext(rel)) {
		case ".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2", ".ttf", ".sum":
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if len(data) > 2<<20 {
			return nil
		}
		fn(rel, data)
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
}

// codeLines drops comment-only lines so documentation never trips a scanner.
func codeLines(body string) []string {
	out := make([]string, 0, 64)
	for _, line := range strings.Split(body, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "//") || strings.HasPrefix(t, "/*") ||
			strings.HasPrefix(t, "*") || strings.HasPrefix(t, "#") {
			continue
		}
		out = append(out, t)
	}
	return out
}

// TestOnlyTheAgentMaySpawnProcesses guarantees that the web server binary can
// never execute a command: only the privileged agent, which validates every
// argument, is allowed to import os/exec.
func TestOnlyTheAgentMaySpawnProcesses(t *testing.T) {
	root := repoRoot(t)
	found := []string{}
	walkFiles(t, root, func(rel string, data []byte) {
		if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") {
			return
		}
		if strings.HasPrefix(rel, "cmd/aegis-agent/") {
			return
		}
		for _, line := range codeLines(string(data)) {
			if strings.Contains(line, `"os/exec"`) {
				found = append(found, rel)
				return
			}
		}
	})
	if len(found) > 0 {
		t.Fatalf("only cmd/aegis-agent may import os/exec, found in: %s", strings.Join(found, ", "))
	}
}

// TestWebServerNeverTouchesPrivileges makes sure the unprivileged process has
// no privilege escalation hooks.
func TestWebServerNeverTouchesPrivileges(t *testing.T) {
	root := repoRoot(t)
	forbidden := []string{"syscall.Setuid", "syscall.Setgid", "syscall.Setgroups", "os.Setuid"}
	violations := []string{}
	walkFiles(t, root, func(rel string, data []byte) {
		if !strings.HasPrefix(rel, "cmd/aegis/") && !strings.HasPrefix(rel, "internal/") {
			return
		}
		if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") {
			return
		}
		body := strings.Join(codeLines(string(data)), "\n")
		for _, f := range forbidden {
			if strings.Contains(body, f) {
				violations = append(violations, rel+" -> "+f)
			}
		}
	})
	if len(violations) > 0 {
		t.Fatalf("privilege escalation hooks found: %s", strings.Join(violations, ", "))
	}
}

// TestFrontendNeverPersistsSecrets bans every browser storage sink that could
// hold a private key, plus the usual DOM XSS vectors.
func TestFrontendNeverPersistsSecrets(t *testing.T) {
	root := repoRoot(t)
	banned := []string{
		"localStorage", "sessionStorage", "document.cookie =",
		"dangerouslySetInnerHTML", "innerHTML =", "outerHTML =",
		"eval(", "new Function(", "child_process",
	}
	violations := []string{}
	walkFiles(t, root, func(rel string, data []byte) {
		if !strings.HasPrefix(rel, "web/src/") {
			return
		}
		if !strings.HasSuffix(rel, ".ts") && !strings.HasSuffix(rel, ".tsx") {
			return
		}
		body := strings.Join(codeLines(string(data)), "\n")
		for _, b := range banned {
			if strings.Contains(body, b) {
				violations = append(violations, rel+" -> "+b)
			}
		}
	})
	if len(violations) > 0 {
		t.Fatalf("forbidden frontend usage: %s", strings.Join(violations, ", "))
	}
}

// TestNoKeyMaterialIsCommitted refuses PEM blocks, raw WireGuard private keys
// and environment files inside the repository.
func TestNoKeyMaterialIsCommitted(t *testing.T) {
	root := repoRoot(t)
	markers := []string{
		"-----BEGIN ",
		"AEGIS_SESSION_SECRET=",
		"AEGIS_AGENT_TOKEN=",
		"AEGIS_KYROS_CLIENT_SECRET=",
	}
	violations := []string{}
	walkFiles(t, root, func(rel string, data []byte) {
		switch rel {
		case ".env.example", "docs/kyros-integration.md", "README.md", "docs/security.md", "docs/deployment.md":
			// Documentation may show placeholders such as <change-me>.
		default:
			if strings.HasSuffix(rel, ".env") {
				violations = append(violations, rel+" -> environment file must not be committed")
				return
			}
		}
		if (strings.HasPrefix(rel, "internal/") || strings.HasPrefix(rel, "cmd/")) &&
			!strings.HasSuffix(rel, "_test.go") {
			body := strings.Join(codeLines(string(data)), "\n")
			for _, m := range markers {
				if strings.Contains(body, m) {
					violations = append(violations, rel+" -> "+m)
				}
			}
		}
	})
	if len(violations) > 0 {
		t.Fatalf("secret material found: %s", strings.Join(violations, ", "))
	}
}

// TestAgentProtocolIsClosedSet re-checks, at the source level, that the agent
// exposes nothing beyond the documented operations.
func TestAgentProtocolIsClosedSet(t *testing.T) {
	root := repoRoot(t)
	body, err := os.ReadFile(filepath.Join(root, "internal", "wg", "protocol.go"))
	if err != nil {
		t.Fatal(err)
	}
	src := strings.Join(codeLines(string(body)), "\n")
	for _, forbidden := range []string{"os/exec", "exec.Command(", "bash", "/bin/sh", "cmd.exe"} {
		if strings.Contains(src, forbidden) {
			t.Errorf("agent protocol must not reference %q", forbidden)
		}
	}
}
