package api

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

var routePattern = regexp.MustCompile(`"(GET|POST|PATCH|DELETE) (/api/v1[^"]+)"`)

// specPaths extracts "path -> methods" from the embedded OpenAPI document.
func specPaths(spec string) map[string]map[string]bool {
	out := map[string]map[string]bool{}
	var current string
	methodRe := regexp.MustCompile(`^ {4}(get|post|patch|delete|put|head|options):`)
	pathRe := regexp.MustCompile(`^ {2}(/[^:]*):$`)
	for _, line := range strings.Split(spec, "\n") {
		if m := pathRe.FindStringSubmatch(line); m != nil {
			current = m[1]
			out[current] = map[string]bool{}
			continue
		}
		if current == "" {
			continue
		}
		if strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "  /") && !pathRe.MatchString(line) {
			// left the paths section (e.g. reached "components:")
			if strings.HasPrefix(line, "components:") {
				current = ""
				continue
			}
		}
		if m := methodRe.FindStringSubmatch(line); m != nil {
			out[current][m[1]] = true
		}
	}
	return out
}

// TestOpenAPICoversEveryRegisteredRoute keeps the served specification in sync
// with the router: every registered pattern must be documented.
func TestOpenAPICoversEveryRegisteredRoute(t *testing.T) {
	src, err := os.ReadFile("router.go")
	if err != nil {
		t.Fatal(err)
	}
	documented := specPaths(string(openAPISpec))
	if len(documented) < 30 {
		t.Fatalf("only %d paths parsed out of openapi.yaml, the parser is broken", len(documented))
	}

	seen := 0
	missing := []string{}
	for _, m := range routePattern.FindAllStringSubmatch(string(src), -1) {
		seen++
		method := strings.ToLower(m[1])
		path := m[2]
		if path == "/api/v1/openapi.yaml" {
			continue // self-describing endpoint
		}
		rel := strings.TrimPrefix(path, "/api/v1")
		ops, ok := documented[rel]
		if !ok {
			missing = append(missing, m[1]+" "+path+" (path absent)")
			continue
		}
		if !ops[method] {
			missing = append(missing, m[1]+" "+path+" (method absent)")
		}
	}
	if seen < 30 {
		t.Fatalf("only %d routes found in router.go, the scanner is broken", seen)
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Fatalf("openapi.yaml is out of sync with router.go:\n  %s",
			strings.Join(missing, "\n  "))
	}
}

// TestOpenAPIDocumentsTheSecurityScheme guards the contract used by clients.
func TestOpenAPIDocumentsTheSecurityScheme(t *testing.T) {
	spec := string(openAPISpec)
	for _, want := range []string{
		"sessionCookie", "aegis_session", "X-CSRF-Token", "openapi: 3.",
		"servers:", "/api/v1",
	} {
		if !strings.Contains(spec, want) {
			t.Errorf("openapi.yaml must mention %q", want)
		}
	}
}
