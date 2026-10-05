package vsix

import (
	"archive/zip"
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func makeVSIX(t *testing.T, files map[string]string) []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte(body))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestDownloadAndCompare(t *testing.T) {
	pkg := makeVSIX(t, map[string]string{
		"extension.vsixmanifest":   "<x/>",
		"extension/package.json":   `{"name":"ext","version":"1.0.0"}`,
		"extension/out/main.js":    "console.log(1)",
		"extension/media/icon.png": "png",
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/publishers/acme/vsextensions/ext/1.0.0/vspackage") {
			_, _ = w.Write(pkg)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	MarketplaceBase, OpenVSXBase = srv.URL, srv.URL

	published, err := Download(context.Background(), srv.Client(), Marketplace, "acme.ext", "1.0.0", "")
	if err != nil || len(published) != 3 {
		t.Fatalf("download: %v %v", published, err)
	}
	if _, err := Download(context.Background(), srv.Client(), OpenVSX, "acme.ext", "1.0.0", ""); err != ErrNotFound {
		t.Fatalf("want ErrNotFound, got %v", err)
	}

	root := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(root, rel)
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Editors add __metadata on install and keep .vsixmanifest: neither counts as tampering.
	write("package.json", `{"version":"1.0.0","name":"ext","__metadata":{"id":"x"}}`)
	write(".vsixmanifest", "<x/>")
	write("out/main.js", "console.log(1)")
	write("media/icon.png", "png")
	installed, err := Installed(root)
	if err != nil {
		t.Fatal(err)
	}
	if d := Compare(published, installed); !d.Empty() {
		t.Fatalf("pristine install reported as changed: %+v", d)
	}
	write("out/main.js", "console.log(1);require('child_process').exec('x')")
	write("out/extra.js", "evil")
	installed, _ = Installed(root)
	d := Compare(published, installed)
	if strings.Join(d.Modified, ",") != "out/main.js" || strings.Join(d.Added, ",") != "out/extra.js" || len(d.Missing) != 0 {
		t.Fatalf("diff: %+v", d)
	}
}

func TestTargetPlatformAndRepo(t *testing.T) {
	root := t.TempDir()
	_ = os.WriteFile(filepath.Join(root, ".vsixmanifest"), []byte(`<Identity Id="x" TargetPlatform="darwin-arm64" />`), 0o644)
	if TargetPlatform(root) != "darwin-arm64" {
		t.Error("target platform")
	}
	o, r, ok := GitHubRepo(map[string]any{"repository": map[string]any{"url": "git+https://github.com/acme/ext.git"}})
	if !ok || o != "acme" || r != "ext" {
		t.Errorf("repo: %s %s %v", o, r, ok)
	}
}

func TestHasVersionTag(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/acme/ext/tags"):
			_, _ = w.Write([]byte(`[{"name":"v1.2.3"},{"name":"v1.2.30"}]`))
		case strings.HasSuffix(r.URL.Path, "/acme/ext/releases"):
			_, _ = w.Write([]byte(`[]`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	GitHubAPI = srv.URL
	ctx := context.Background()
	if ok, err := HasVersionTag(ctx, srv.Client(), "acme", "ext", "1.2.3"); !ok || err != nil {
		t.Errorf("1.2.3: %v %v", ok, err)
	}
	if ok, err := HasVersionTag(ctx, srv.Client(), "acme", "ext", "1.2.4"); ok || err != nil {
		t.Errorf("1.2.4: %v %v", ok, err)
	}
	if ok, err := HasVersionTag(ctx, srv.Client(), "acme", "ext", "2.3"); ok || err != nil {
		t.Errorf("2.3 must not match 1.2.30: %v %v", ok, err)
	}
	if _, err := HasVersionTag(ctx, srv.Client(), "nobody", "gone", "1.0.0"); err != ErrNotFound {
		t.Errorf("missing repo: %v", err)
	}
}
