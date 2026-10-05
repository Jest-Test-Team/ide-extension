// Package scan runs the Go analyzer's checks over the extensions of one request.
package scan

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Jest-Test-Team/ide-extension/analyzers/go/internal/domains"
	"github.com/Jest-Test-Team/ide-extension/analyzers/go/internal/npm"
	"github.com/Jest-Test-Team/ide-extension/analyzers/go/internal/osv"
	"github.com/Jest-Test-Team/ide-extension/analyzers/go/internal/protocol"
	"github.com/Jest-Test-Team/ide-extension/analyzers/go/internal/vsix"
)

// Offline and online vectors this analyzer implements.
var (
	OfflineVectors = []string{
		"ext/domain-inventory", "ext/dependency-typosquat", "ext/dependency-install-script", "ext/protestware",
		"ext/git-dependency", "ext/deprecated-dependency", "ext/dependency-bloat", "ext/missing-lockfile",
	}
	OnlineVectors = []string{"ext/vulnerable-dependency", "ext/malicious-dependency", "ext/vsix-tampered", "ext/registry-mismatch", "ext/repo-missing-version"}
)

func Vectors() []string { return append(append([]string{}, OfflineVectors...), OnlineVectors...) }

type Runner struct {
	Out    *protocol.Emitter
	Client *http.Client
	Ctx    context.Context
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

var exactVersion = regexp.MustCompile(`^\d+\.\d+\.\d+(?:-[\w.]+)?$`)

func (r *Runner) Run(req protocol.Request) {
	want := func(v string) bool { return contains(req.Vectors, v) }
	var ran []string
	var skipped []protocol.Skipped
	for _, v := range OfflineVectors {
		if want(v) {
			ran = append(ran, v)
		}
	}
	online := req.Options.Online
	for _, v := range OnlineVectors {
		if !want(v) {
			continue
		}
		if online {
			ran = append(ran, v)
		} else {
			skipped = append(skipped, protocol.Skipped{ID: v, Reason: "needs --online"})
		}
	}
	maxFiles := req.Options.MaxFiles
	if maxFiles <= 0 {
		maxFiles = 5000
	}
	maxBytes := int64(req.Options.MaxFileMB * 1024 * 1024)
	if maxBytes <= 0 {
		maxBytes = 10 << 20
	}

	var queries []osv.Query
	owner := map[string][]string{} // name@version → extension ids
	for _, ext := range req.Extensions {
		r.Out.Progress(ext.ID, "supply chain")
		inv := npm.Collect(ext.Path, ext.Manifest)
		n, depth := npm.Stats(inv)
		r.Out.Metric(ext.ID, "npm.packages", float64(n))
		r.Out.Metric(ext.ID, "npm.depth", float64(depth))
		checks := map[string]func(npm.Inventory) *npm.Finding{
			"ext/dependency-typosquat":      npm.Typosquats,
			"ext/dependency-install-script": npm.InstallScripts,
			"ext/protestware":               npm.Protestware,
			"ext/git-dependency":            npm.GitDependencies,
			"ext/deprecated-dependency":     npm.Deprecated,
			"ext/dependency-bloat":          npm.Bloat,
			"ext/missing-lockfile":          npm.MissingLockfile,
		}
		ids := make([]string, 0, len(checks))
		for id := range checks {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			if !want(id) {
				continue
			}
			if f := checks[id](inv); f != nil {
				r.Out.Signal(ext.ID, f.Vector, f.Message, locations(f.Files), "", f.Confidence)
			}
		}
		if want("ext/domain-inventory") {
			r.domainInventory(ext, maxBytes, maxFiles)
		}
		for _, p := range inv.Packages {
			if exactVersion.MatchString(p.Version) {
				key := p.Name + "@" + p.Version
				if _, ok := owner[key]; !ok {
					queries = append(queries, osv.Query{Name: p.Name, Version: p.Version})
				}
				owner[key] = appendUnique(owner[key], ext.ID)
			}
		}
		if !inv.HasModules {
			// Bundled extensions: their own pinned dependencies are the best available evidence.
			for name, spec := range inv.Declared {
				v := strings.TrimPrefix(spec, "=")
				if exactVersion.MatchString(v) {
					key := name + "@" + v
					if _, ok := owner[key]; !ok {
						queries = append(queries, osv.Query{Name: name, Version: v})
					}
					owner[key] = appendUnique(owner[key], ext.ID)
				}
			}
		}
		if online {
			r.online(ext, want)
		}
	}
	if online && (want("ext/vulnerable-dependency") || want("ext/malicious-dependency")) && len(queries) > 0 {
		r.osv(queries, owner, want)
	}
	r.Out.Done(ran, skipped)
}

func appendUnique(xs []string, s string) []string {
	if contains(xs, s) {
		return xs
	}
	return append(xs, s)
}

func locations(files []string) []protocol.Location {
	var out []protocol.Location
	for i, f := range files {
		if i >= 20 {
			break
		}
		out = append(out, protocol.Location{File: f})
	}
	return out
}

func (r *Runner) domainInventory(ext protocol.Extension, maxBytes int64, maxFiles int) {
	hosts := domains.Inventory(ext.Path, ext.ID, ext.Manifest, false, maxBytes, maxFiles)
	count := map[domains.Class]int{}
	var third []string
	var locs []protocol.Location
	for _, h := range hosts {
		count[h.Class]++
		if h.Class == domains.ThirdParty {
			third = append(third, h.Name)
			if len(locs) < 20 {
				locs = append(locs, protocol.Location{File: h.File, Line: h.Line})
			}
		}
	}
	r.Out.Metric(ext.ID, "domains.total", float64(len(hosts)))
	r.Out.Metric(ext.ID, "domains.thirdParty", float64(count[domains.ThirdParty]))
	if len(hosts) == 0 {
		return
	}
	shown := third
	if len(shown) > 8 {
		shown = append(append([]string{}, shown[:8]...), fmt.Sprintf("… (%d)", len(third)))
	}
	msg := fmt.Sprintf("%d hosts referenced: %d first-party, %d platform, %d third-party", len(hosts), count[domains.FirstParty], count[domains.Platform], count[domains.ThirdParty])
	if len(shown) > 0 {
		msg += ": " + strings.Join(shown, ", ")
	}
	r.Out.Signal(ext.ID, "ext/domain-inventory", msg+".", locs, "", 1)
}

func (r *Runner) osv(queries []osv.Query, owner map[string][]string, want func(string) bool) {
	results, err := osv.Lookup(r.Ctx, r.Client, queries)
	if err != nil {
		r.Out.Error("", "OSV lookup: "+err.Error())
	}
	type agg struct{ vuln, mal []string }
	byExt := map[string]*agg{}
	for _, res := range results {
		key := res.Name + "@" + res.Version
		for _, id := range owner[key] {
			a := byExt[id]
			if a == nil {
				a = &agg{}
				byExt[id] = a
			}
			label := fmt.Sprintf("%s (%s)", key, strings.Join(res.IDs[:min(3, len(res.IDs))], ", "))
			if res.Malicious() {
				a.mal = append(a.mal, label)
			} else {
				a.vuln = append(a.vuln, label)
			}
		}
	}
	ids := make([]string, 0, len(byExt))
	for id := range byExt {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		a := byExt[id]
		if len(a.mal) > 0 && want("ext/malicious-dependency") {
			r.Out.Signal(id, "ext/malicious-dependency", "Bundled package(s) listed as malware by OSV: "+short(a.mal, 3)+".", nil, "", 1)
		}
		if len(a.vuln) > 0 && want("ext/vulnerable-dependency") {
			r.Out.Signal(id, "ext/vulnerable-dependency", fmt.Sprintf("%d bundled package version(s) with OSV advisories: %s.", len(a.vuln), short(a.vuln, 3)), nil, "", 1)
		}
	}
}

func short(xs []string, n int) string {
	if len(xs) <= n {
		return strings.Join(xs, "; ")
	}
	return strings.Join(xs[:n], "; ") + fmt.Sprintf("; … (%d)", len(xs))
}

func (r *Runner) online(ext protocol.Extension, want func(string) bool) {
	if want("ext/vsix-tampered") || want("ext/registry-mismatch") {
		r.Out.Progress(ext.ID, "comparing with the published VSIX")
		installed, err := vsix.Installed(ext.Path)
		if err != nil {
			r.Out.Error(ext.ID, "hashing installed files: "+err.Error())
			return
		}
		target := vsix.TargetPlatform(ext.Path)
		published := map[vsix.Source]vsix.Files{}
		for _, src := range []vsix.Source{vsix.Marketplace, vsix.OpenVSX} {
			files, err := vsix.Download(r.Ctx, r.Client, src, ext.ID, ext.Version, target)
			if errors.Is(err, vsix.ErrNotFound) {
				continue
			}
			if err != nil {
				r.Out.Error(ext.ID, fmt.Sprintf("%s download: %s", src, err))
				continue
			}
			published[src] = files
		}
		if want("ext/vsix-tampered") && len(published) > 0 {
			r.tamper(ext, installed, published)
		}
		mp, ov := published[vsix.Marketplace], published[vsix.OpenVSX]
		if want("ext/registry-mismatch") && mp != nil && ov != nil {
			d := vsix.Compare(mp, ov)
			code := filterCode(append(append([]string{}, d.Modified...), append(d.Added, d.Missing...)...))
			if len(code) > 0 {
				r.Out.Signal(ext.ID, "ext/registry-mismatch", fmt.Sprintf("%s@%s differs between the Marketplace and Open VSX in %d code file(s): %s.", ext.ID, ext.Version, len(code), short(code, 4)), locations(code), "", 0.5)
			}
		}
	}
	if want("ext/repo-missing-version") {
		if owner, repo, ok := vsix.GitHubRepo(ext.Manifest); ok {
			has, err := vsix.HasVersionTag(r.Ctx, r.Client, owner, repo, ext.Version)
			switch {
			case errors.Is(err, vsix.ErrNotFound):
				r.Out.Signal(ext.ID, "ext/repo-missing-version", fmt.Sprintf("The declared repository github.com/%s/%s does not exist or is private.", owner, repo), []protocol.Location{{File: "package.json"}}, "", 0.8)
			case err != nil:
				r.Out.Error(ext.ID, "repository check: "+err.Error())
			case !has:
				r.Out.Signal(ext.ID, "ext/repo-missing-version", fmt.Sprintf("github.com/%s/%s has no tag or release for version %s among its latest 100.", owner, repo, ext.Version), []protocol.Location{{File: "package.json"}}, "", 0.6)
			}
		}
	}
}

func filterCode(paths []string) []string {
	var out []string
	for _, p := range paths {
		if vsix.IsCode(p) {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

// tamper reports files that differ from every registry the version is published on. Runtime
// downloads into the extension folder show up as added files and weigh less than modified ones.
func (r *Runner) tamper(ext protocol.Extension, installed vsix.Files, published map[vsix.Source]vsix.Files) {
	var best vsix.Diff
	var src vsix.Source
	first := true
	for s, files := range published {
		d := vsix.Compare(files, installed)
		if d.Empty() {
			return
		}
		if first || len(d.Modified) < len(best.Modified) {
			best, src, first = d, s, false
		}
	}
	addedCode := filterCode(best.Added)
	r.Out.Metric(ext.ID, "vsix.modified", float64(len(best.Modified)))
	r.Out.Metric(ext.ID, "vsix.added", float64(len(best.Added)))
	switch {
	case len(best.Modified) > 0:
		r.Out.Signal(ext.ID, "ext/vsix-tampered", fmt.Sprintf("%d installed file(s) differ from the %s package for %s: %s.", len(best.Modified), src, ext.Version, short(best.Modified, 4)), locations(best.Modified), "", 0.9)
	case len(addedCode) > 0:
		r.Out.Signal(ext.ID, "ext/vsix-tampered", fmt.Sprintf("%d code file(s) not in the %s package (runtime downloads or injected code): %s.", len(addedCode), src, short(addedCode, 4)), locations(addedCode), "", 0.4)
	}
}

// DefaultClient is the HTTP client used for online checks.
func DefaultClient() *http.Client {
	return &http.Client{Timeout: 10 * time.Minute}
}
