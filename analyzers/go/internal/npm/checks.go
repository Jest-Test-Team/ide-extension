package npm

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Finding is a result of one check; the scan package turns it into a protocol signal.
type Finding struct {
	Vector     string
	Message    string
	Files      []string
	Confidence float64
}

var installHooks = []string{"preinstall", "install", "postinstall"}

func list(xs []string, max int) string {
	if len(xs) <= max {
		return strings.Join(xs, ", ")
	}
	return strings.Join(xs[:max], ", ") + fmt.Sprintf(", … (%d)", len(xs))
}

// InstallScripts: dependencies with npm lifecycle hooks. A plain `node-gyp rebuild` (native build)
// is reported with lower confidence than arbitrary scripts.
func InstallScripts(inv Inventory) *Finding {
	var names, files []string
	arbitrary := false
	for _, p := range inv.Packages {
		for _, h := range installHooks {
			s, ok := p.Scripts[h]
			if !ok {
				continue
			}
			names = append(names, fmt.Sprintf("%s@%s (%s: %s)", p.Name, p.Version, h, truncate(s, 60)))
			files = append(files, p.Path+"/package.json")
			if !strings.Contains(s, "node-gyp") && !strings.Contains(s, "prebuild-install") && !strings.HasPrefix(s, "(declared") {
				arbitrary = true
			}
			break
		}
	}
	if len(names) == 0 {
		return nil
	}
	conf := 0.6
	if arbitrary {
		conf = 0.9
	}
	return &Finding{"ext/dependency-install-script", fmt.Sprintf("%d bundled package(s) declare install scripts: %s.", len(names), list(names, 4)), files, conf}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

// nonRegistry: dependency specs or lockfile sources outside the npm registry. `file:` links are
// local workspace packages (already bundled), not a download source.
func nonRegistry(spec string) bool {
	for _, p := range []string{"git+", "git://", "git@", "github:", "gitlab:", "bitbucket:", "http://", "https://"} {
		if strings.HasPrefix(spec, p) {
			return true
		}
	}
	// "user/repo" shorthand
	return strings.Count(spec, "/") == 1 && !strings.HasPrefix(spec, "@") && !strings.ContainsAny(spec, " ^~<>=*")
}

func GitDependencies(inv Inventory) *Finding {
	var hits, files []string
	add := func(who, name, spec, file string) {
		hits = append(hits, fmt.Sprintf("%s → %s (%s)", who, name, truncate(spec, 70)))
		files = append(files, file)
	}
	for name, spec := range inv.Declared {
		if nonRegistry(spec) {
			add("package.json", name, spec, "package.json")
		}
	}
	for _, p := range inv.Packages {
		for name, spec := range p.Deps {
			if nonRegistry(spec) {
				add(p.Name, name, spec, p.Path+"/package.json")
			}
		}
		if p.Resolved != "" && !strings.HasPrefix(p.Resolved, "https://registry.npmjs.org/") && !strings.HasPrefix(p.Resolved, "https://registry.yarnpkg.com/") {
			add("lockfile", p.Name, p.Resolved, p.Path)
		}
	}
	if len(hits) == 0 {
		return nil
	}
	sort.Strings(hits)
	return &Finding{"ext/git-dependency", fmt.Sprintf("%d dependency source(s) bypass the npm registry: %s.", len(hits), list(hits, 3)), files, 0.9}
}

func Deprecated(inv Inventory) *Finding {
	var names, files []string
	for _, p := range inv.Packages {
		if p.Deprecated != "" {
			names = append(names, p.Name+"@"+p.Version)
			files = append(files, p.Path)
		}
	}
	if len(names) == 0 {
		return nil
	}
	return &Finding{"ext/deprecated-dependency", fmt.Sprintf("%d deprecated package(s): %s.", len(names), list(names, 5)), files, 1}
}

const (
	bloatCount = 500
	bloatDepth = 10
)

// Stats returns the package count and maximum nesting depth.
func Stats(inv Inventory) (int, int) {
	depth := 0
	for _, p := range inv.Packages {
		if p.Depth > depth {
			depth = p.Depth
		}
	}
	return len(inv.Packages), depth
}

func Bloat(inv Inventory) *Finding {
	n, depth := Stats(inv)
	if n < bloatCount && depth < bloatDepth {
		return nil
	}
	return &Finding{"ext/dependency-bloat", fmt.Sprintf("%d bundled packages, nested %d levels deep (typical extensions bundle far fewer).", n, depth), nil, 0.8}
}

func MissingLockfile(inv Inventory) *Finding {
	if !inv.HasModules || len(inv.Lockfiles) > 0 {
		return nil
	}
	n, _ := Stats(inv)
	return &Finding{"ext/missing-lockfile", fmt.Sprintf("Ships node_modules (%d packages) without a lockfile.", n), []string{"node_modules"}, 1}
}

// protestware: package → affected versions ("*" = every version). Sources: GitHub advisories and
// the npm security notices for each incident.
var protestware = map[string][]string{
	"node-ipc":    {"9.2.2", "10.1.1", "10.1.2", "10.1.3", "11.0.0", "11.1.0"},
	"peacenotwar": {"*"},
	"colors":      {"1.4.1", "1.4.2", "1.4.44-liberty-2"},
	"faker":       {"6.6.6"},
}

func Protestware(inv Inventory) *Finding {
	var hits, files []string
	for _, p := range inv.Packages {
		for _, v := range protestware[p.Name] {
			if v == "*" || v == p.Version {
				hits = append(hits, p.Name+"@"+p.Version)
				files = append(files, p.Path)
				break
			}
		}
	}
	if len(hits) == 0 {
		return nil
	}
	return &Finding{"ext/protestware", "Known sabotage / protestware versions bundled: " + list(hits, 5) + ".", files, 1}
}

// Typosquats: unscoped dependency names one edit (or a separator change) away from a popular
// package, which are not popular themselves.
func Typosquats(inv Inventory) *Finding {
	var hits, files []string
	done := map[string]bool{}
	check := func(name, file string) {
		if done[name] || strings.HasPrefix(name, "@") {
			return
		}
		done[name] = true
		if target := typosquatOf(name); target != "" {
			hits = append(hits, fmt.Sprintf("%s (looks like %s)", name, target))
			files = append(files, file)
		}
	}
	for name := range inv.Declared {
		check(name, "package.json")
	}
	for _, p := range inv.Packages {
		check(p.Name, p.Path)
	}
	if len(hits) == 0 {
		return nil
	}
	sort.Strings(hits)
	return &Finding{"ext/dependency-typosquat", "Dependency names imitate popular packages: " + list(hits, 4) + ".", files, 0.7}
}

func squash(s string) string { return strings.NewReplacer("-", "", "_", "", ".", "").Replace(s) }

func typosquatOf(name string) string {
	if popularSet[name] || len(name) < 4 {
		return ""
	}
	for _, p := range popular {
		if squash(p) == squash(name) {
			return p
		}
		if len(p) >= 5 && abs(len(p)-len(name)) <= 1 && editDistance(p, name) == 1 {
			return p
		}
	}
	return ""
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// editDistance is the Damerau–Levenshtein (optimal string alignment) distance.
func editDistance(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	d := make([][]int, len(ra)+1)
	for i := range d {
		d[i] = make([]int, len(rb)+1)
		d[i][0] = i
	}
	for j := range d[0] {
		d[0][j] = j
	}
	for i := 1; i <= len(ra); i++ {
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			d[i][j] = min(d[i-1][j]+1, d[i][j-1]+1, d[i-1][j-1]+cost)
			if i > 1 && j > 1 && ra[i-1] == rb[j-2] && ra[i-2] == rb[j-1] {
				d[i][j] = min(d[i][j], d[i-2][j-2]+1)
			}
		}
	}
	return d[len(ra)][len(rb)]
}

// CompareVersions compares dotted numeric versions; pre-release suffixes sort before the release.
func CompareVersions(a, b string) int {
	pa, pb := strings.SplitN(a, "-", 2), strings.SplitN(b, "-", 2)
	xa, xb := strings.Split(pa[0], "."), strings.Split(pb[0], ".")
	for i := 0; i < 3; i++ {
		var na, nb int
		if i < len(xa) {
			na, _ = strconv.Atoi(xa[i])
		}
		if i < len(xb) {
			nb, _ = strconv.Atoi(xb[i])
		}
		if na != nb {
			if na < nb {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(pa) == len(pb):
		return strings.Compare(strings.Join(pa[1:], ""), strings.Join(pb[1:], ""))
	case len(pa) > len(pb):
		return -1
	default:
		return 1
	}
}
