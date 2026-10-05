package npm

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writePkg(t *testing.T, dir, body string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func fixture(t *testing.T) string {
	root := t.TempDir()
	nm := filepath.Join(root, "node_modules")
	writePkg(t, filepath.Join(nm, "lodahs"), `{"name":"lodahs","version":"1.0.0","scripts":{"postinstall":"node steal.js"}}`)
	writePkg(t, filepath.Join(nm, "colors"), `{"name":"colors","version":"1.4.1"}`)
	writePkg(t, filepath.Join(nm, "@scope", "pkg"), `{"name":"@scope/pkg","version":"2.0.0","dependencies":{"x":"github:evil/x"}}`)
	writePkg(t, filepath.Join(nm, "native"), `{"name":"native","version":"1.0.0","scripts":{"install":"node-gyp rebuild"},"deprecated":"use other"}`)
	writePkg(t, filepath.Join(nm, "colors", "node_modules", "nested"), `{"name":"nested","version":"0.0.1"}`)
	return root
}

func TestCollect(t *testing.T) {
	inv := Collect(fixture(t), map[string]any{"dependencies": map[string]any{"lodahs": "1.0.0"}})
	n, depth := Stats(inv)
	if n != 5 || depth != 2 || !inv.HasModules {
		t.Fatalf("got %d packages, depth %d, modules %v", n, depth, inv.HasModules)
	}
}

func TestChecks(t *testing.T) {
	inv := Collect(fixture(t), map[string]any{})
	cases := []struct {
		f    func(Inventory) *Finding
		want string
	}{
		{InstallScripts, "lodahs@1.0.0 (postinstall: node steal.js)"},
		{Protestware, "colors@1.4.1"},
		{GitDependencies, "@scope/pkg → x (github:evil/x)"},
		{Deprecated, "native@1.0.0"},
		{Typosquats, "lodahs (looks like lodash)"},
		{MissingLockfile, "without a lockfile"},
	}
	for _, c := range cases {
		f := c.f(inv)
		if f == nil || !strings.Contains(f.Message, c.want) {
			t.Errorf("want %q, got %+v", c.want, f)
		}
	}
	if f := InstallScripts(inv); f.Confidence != 0.9 {
		t.Errorf("arbitrary install script confidence %v", f.Confidence)
	}
	if Bloat(inv) != nil {
		t.Error("five packages are not bloat")
	}
}

func TestCleanInventory(t *testing.T) {
	root := t.TempDir()
	writePkg(t, filepath.Join(root, "node_modules", "lodash"), `{"name":"lodash","version":"4.17.21"}`)
	if err := os.WriteFile(filepath.Join(root, "package-lock.json"), []byte(`{"packages":{}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	inv := Collect(root, map[string]any{"dependencies": map[string]any{"react": "^18.0.0", "ws": "8.0.0"}})
	for _, f := range []func(Inventory) *Finding{InstallScripts, Protestware, GitDependencies, Deprecated, Typosquats, MissingLockfile, Bloat} {
		if got := f(inv); got != nil {
			t.Errorf("unexpected finding %+v", got)
		}
	}
}

func TestLockfile(t *testing.T) {
	root := t.TempDir()
	lock := `{"lockfileVersion":3,"packages":{"":{},"node_modules/a":{"version":"1.0.0","resolved":"https://evil.example/a.tgz","hasInstallScript":true},"node_modules/b":{"version":"1.0.0","dev":true,"hasInstallScript":true}}}`
	if err := os.WriteFile(filepath.Join(root, "package-lock.json"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	inv := Collect(root, map[string]any{})
	if len(inv.Packages) != 1 || inv.Packages[0].Name != "a" {
		t.Fatalf("dev entries must be skipped: %+v", inv.Packages)
	}
	if f := GitDependencies(inv); f == nil || !strings.Contains(f.Message, "evil.example") {
		t.Errorf("non-registry resolved URL not reported: %+v", f)
	}
	if f := InstallScripts(inv); f == nil || f.Confidence != 0.6 {
		t.Errorf("lockfile install flag: %+v", f)
	}
}

func TestEditDistanceAndVersions(t *testing.T) {
	if editDistance("lodash", "lodahs") != 1 || editDistance("express", "expres") != 1 || editDistance("react", "preact") != 1 {
		t.Error("edit distance")
	}
	if typosquatOf("preact") != "" && popularSet["preact"] {
		t.Error("popular packages are not typosquats")
	}
	if typosquatOf("cross_env") != "cross-env" {
		t.Error("separator swap")
	}
	if CompareVersions("1.2.3", "1.10.0") >= 0 || CompareVersions("1.0.0-beta", "1.0.0") >= 0 || CompareVersions("2.0.0", "2.0.0") != 0 {
		t.Error("version order")
	}
}
