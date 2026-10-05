// Package domains inventories the hosts an extension's code and assets reference and classifies
// them as first-party (the publisher's own), platform (editor, registries, standards bodies) or
// third-party.
package domains

import (
	"bufio"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

type Class string

const (
	FirstParty Class = "first-party"
	Platform   Class = "platform"
	ThirdParty Class = "third-party"
)

type Host struct {
	Name  string
	Class Class
	Count int
	File  string // first occurrence, relative to the extension folder
	Line  int
}

var urlRe = regexp.MustCompile(`\b(?:https?|wss?)://([A-Za-z0-9](?:[A-Za-z0-9-]{0,62}\.)+[A-Za-z]{2,24})(?::\d{2,5})?(?:[/?#"'\x60\s)]|$)`)

var scanExt = map[string]bool{".js": true, ".cjs": true, ".mjs": true, ".json": true, ".html": true, ".htm": true}

// platform hosts: the editor, package registries, code hosting and standards/spec sites.
var platformSuffixes = []string{
	"visualstudio.com", "vscode-cdn.net", "vscode-unpkg.net", "code.visualstudio.com", "microsoft.com", "azure.com", "azureedge.net", "windows.net",
	"github.com", "githubusercontent.com", "github.io", "githubassets.com", "npmjs.org", "npmjs.com", "yarnpkg.com", "unpkg.com", "jsdelivr.net",
	"nodejs.org", "w3.org", "whatwg.org", "ietf.org", "json-schema.org", "schemastore.org", "mozilla.org", "ecma-international.org", "open-vsx.org",
	"opensource.org", "apache.org", "creativecommons.org", "spdx.org", "example.com", "example.org", "example.net", "localhost",
}

var ignoredTLD = map[string]bool{"js": true, "json": true, "ts": true, "md": true, "html": true, "css": true, "png": true, "svg": true, "node": true, "map": true}

func hasSuffix(host, suffix string) bool {
	return host == suffix || strings.HasSuffix(host, "."+suffix)
}

// firstPartyHints derives the publisher's own names from the manifest (publisher, repository
// owner, homepage / bugs hosts).
func firstPartyHints(id string, manifest map[string]any) (owners []string, hosts []string) {
	owners = append(owners, strings.ToLower(strings.SplitN(id, ".", 2)[0]))
	add := func(raw string) {
		u, err := url.Parse(strings.TrimPrefix(raw, "git+"))
		if err != nil || u.Host == "" {
			return
		}
		h := strings.ToLower(u.Hostname())
		parts := strings.Split(strings.Trim(u.Path, "/"), "/")
		if (h == "github.com" || h == "gitlab.com" || h == "bitbucket.org") && parts[0] != "" {
			owners = append(owners, strings.ToLower(parts[0]))
		} else {
			hosts = append(hosts, h)
		}
	}
	for _, key := range []string{"repository", "homepage", "bugs"} {
		switch v := manifest[key].(type) {
		case string:
			add(v)
		case map[string]any:
			if s, ok := v["url"].(string); ok {
				add(s)
			}
		}
	}
	return owners, hosts
}

// registrable returns the last two labels (a coarse eTLD+1, good enough for classification).
func registrable(host string) string {
	parts := strings.Split(host, ".")
	if len(parts) <= 2 {
		return host
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

func Classify(host string, owners, ownHosts []string) Class {
	for _, h := range ownHosts {
		if hasSuffix(host, h) || registrable(host) == registrable(h) {
			return FirstParty
		}
	}
	for _, o := range owners {
		if len(o) >= 4 && strings.Contains(strings.ReplaceAll(host, "-", ""), strings.ReplaceAll(o, "-", "")) {
			return FirstParty
		}
	}
	for _, s := range platformSuffixes {
		if hasSuffix(host, s) {
			return Platform
		}
	}
	return ThirdParty
}

// Inventory scans code and asset files (node_modules included only when asked) for URLs.
func Inventory(root, id string, manifest map[string]any, includeNodeModules bool, maxFileBytes int64, maxFiles int) []Host {
	owners, ownHosts := firstPartyHints(id, manifest)
	found := map[string]*Host{}
	files := 0
	_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		if d.IsDir() {
			if n := d.Name(); n == ".git" || (n == "node_modules" && !includeNodeModules) {
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		if !scanExt[strings.ToLower(filepath.Ext(name))] || name == "package-lock.json" || strings.HasSuffix(name, ".map") || files >= maxFiles {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() > maxFileBytes {
			return nil
		}
		files++
		rel, _ := filepath.Rel(root, p)
		scanFile(p, filepath.ToSlash(rel), found)
		return nil
	})
	out := make([]Host, 0, len(found))
	for _, h := range found {
		h.Class = Classify(h.Name, owners, ownHosts)
		out = append(out, *h)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func scanFile(path, rel string, found map[string]*Host) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 16*1024*1024)
	line := 0
	for sc.Scan() {
		line++
		for _, m := range urlRe.FindAllStringSubmatch(sc.Text(), -1) {
			host := strings.ToLower(strings.TrimSuffix(m[1], "."))
			tld := host[strings.LastIndex(host, ".")+1:]
			if ignoredTLD[tld] || net.ParseIP(host) != nil {
				continue
			}
			if h, ok := found[host]; ok {
				h.Count++
			} else {
				found[host] = &Host{Name: host, Count: 1, File: rel, Line: line}
			}
		}
	}
}
