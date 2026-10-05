// Package vsix compares an installed extension with the package its registry publishes for the same
// version. Downloads happen only with --online.
package vsix

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

var (
	MarketplaceBase       = "https://marketplace.visualstudio.com"
	OpenVSXBase           = "https://open-vsx.org"
	MaxBytes        int64 = 400 << 20
)

var ErrNotFound = errors.New("not published")

type Source string

const (
	Marketplace Source = "Marketplace"
	OpenVSX     Source = "Open VSX"
)

// Files maps a path inside the extension folder to its SHA-256.
type Files map[string]string

func get(ctx context.Context, client *http.Client, u string) (*http.Response, error) {
	cctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	req, _ := http.NewRequestWithContext(cctx, http.MethodGet, u, nil)
	res, err := client.Do(req)
	if err != nil {
		cancel()
		return nil, err
	}
	if res.StatusCode == http.StatusNotFound {
		res.Body.Close()
		cancel()
		return nil, ErrNotFound
	}
	if res.StatusCode != http.StatusOK {
		res.Body.Close()
		cancel()
		return nil, fmt.Errorf("GET %s: HTTP %d", u, res.StatusCode)
	}
	res.Body = &cancelOnClose{res.Body, cancel}
	return res, nil
}

type cancelOnClose struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (c *cancelOnClose) Close() error {
	err := c.ReadCloser.Close()
	c.cancel()
	return err
}

func split(id string) (string, string) {
	p := strings.SplitN(id, ".", 2)
	if len(p) < 2 {
		return id, ""
	}
	return p[0], p[1]
}

// Download fetches the published VSIX for id@version (and target platform, if any).
func Download(ctx context.Context, client *http.Client, src Source, id, version, target string) (Files, error) {
	pub, name := split(id)
	var u string
	switch src {
	case Marketplace:
		u = fmt.Sprintf("%s/_apis/public/gallery/publishers/%s/vsextensions/%s/%s/vspackage", MarketplaceBase, url.PathEscape(pub), url.PathEscape(name), url.PathEscape(version))
		if target != "" {
			u += "?targetPlatform=" + url.QueryEscape(target)
		}
	case OpenVSX:
		meta := fmt.Sprintf("%s/api/%s/%s/%s", OpenVSXBase, url.PathEscape(pub), url.PathEscape(name), url.PathEscape(version))
		if target != "" {
			meta = fmt.Sprintf("%s/api/%s/%s/%s/%s", OpenVSXBase, url.PathEscape(pub), url.PathEscape(name), url.PathEscape(target), url.PathEscape(version))
		}
		res, err := get(ctx, client, meta)
		if err != nil {
			return nil, err
		}
		var m struct {
			Files map[string]string `json:"files"`
		}
		err = json.NewDecoder(res.Body).Decode(&m)
		res.Body.Close()
		if err != nil || m.Files["download"] == "" {
			return nil, ErrNotFound
		}
		u = m.Files["download"]
	}
	res, err := get(ctx, client, u)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	tmp, err := os.CreateTemp("", "jest-ext-go-*.vsix")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	n, err := io.Copy(tmp, io.LimitReader(res.Body, MaxBytes+1))
	if err != nil {
		return nil, err
	}
	if n > MaxBytes {
		return nil, fmt.Errorf("VSIX larger than %d MB", MaxBytes>>20)
	}
	zr, err := zip.NewReader(tmp, n)
	if err != nil {
		return nil, err
	}
	return zipFiles(zr)
}

func zipFiles(zr *zip.Reader) (Files, error) {
	out := Files{}
	for _, f := range zr.File {
		if !strings.HasPrefix(f.Name, "extension/") || strings.HasSuffix(f.Name, "/") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		rel := strings.TrimPrefix(f.Name, "extension/")
		out[rel], err = hashReader(rel, rc)
		rc.Close()
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// hashReader hashes file content; package.json is hashed after removing the `__metadata` block
// some editors add on install, so that edit is not reported as tampering.
func hashReader(rel string, r io.Reader) (string, error) {
	if rel == "package.json" {
		b, err := io.ReadAll(r)
		if err != nil {
			return "", err
		}
		var m map[string]any
		if json.Unmarshal(b, &m) == nil {
			delete(m, "__metadata")
			b, _ = json.Marshal(m)
		}
		sum := sha256.Sum256(b)
		return hex.EncodeToString(sum[:]), nil
	}
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Installed hashes the installed folder. Symlinks are not followed.
func Installed(root string) (Files, error) {
	out := Files{}
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		if rel == ".vsixmanifest" {
			return nil
		}
		f, err := os.Open(p)
		if err != nil {
			return nil
		}
		defer f.Close()
		out[rel], err = hashReader(rel, f)
		return err
	})
	return out, err
}

type Diff struct {
	Modified, Added, Missing []string
}

func (d Diff) Empty() bool { return len(d.Modified)+len(d.Added)+len(d.Missing) == 0 }

var codeExt = map[string]bool{".js": true, ".cjs": true, ".mjs": true, ".node": true, ".exe": true, ".dll": true, ".dylib": true, ".so": true, ".sh": true, ".ps1": true, ".bat": true, ".cmd": true, ".py": true, ".wasm": true, ".html": true}

// IsCode reports whether a path holds code (where tampering matters most).
func IsCode(p string) bool { return codeExt[strings.ToLower(filepath.Ext(p))] }

// Compare lists files that differ between the published package and the installed folder.
func Compare(published, installed Files) Diff {
	var d Diff
	for p, h := range published {
		switch ih, ok := installed[p]; {
		case !ok:
			d.Missing = append(d.Missing, p)
		case ih != h:
			d.Modified = append(d.Modified, p)
		}
	}
	for p := range installed {
		if _, ok := published[p]; !ok {
			d.Added = append(d.Added, p)
		}
	}
	sort.Strings(d.Modified)
	sort.Strings(d.Added)
	sort.Strings(d.Missing)
	return d
}

// TargetPlatform reads the platform the installed copy was built for from its .vsixmanifest.
func TargetPlatform(root string) string {
	b, err := os.ReadFile(filepath.Join(root, ".vsixmanifest"))
	if err != nil {
		return ""
	}
	i := bytes.Index(b, []byte(`TargetPlatform="`))
	if i < 0 {
		return ""
	}
	rest := b[i+len(`TargetPlatform="`):]
	if j := bytes.IndexByte(rest, '"'); j > 0 {
		return string(rest[:j])
	}
	return ""
}
