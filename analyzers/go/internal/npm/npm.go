// Package npm inventories the npm packages shipped inside an extension (node_modules and lockfiles)
// and checks them for supply-chain risks. It only reads package.json / lockfile data.
package npm

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Package is one installed (or locked) dependency.
type Package struct {
	Name       string
	Version    string
	Path       string // relative to the extension folder; lockfile entries use the lockfile key
	Depth      int    // nesting level of node_modules (1 = direct)
	Scripts    map[string]string
	Deprecated string
	Resolved   string            // lockfile `resolved`
	Deps       map[string]string // dependencies + optionalDependencies as declared
	FromLock   bool
}

// Inventory is everything known about an extension's dependencies.
type Inventory struct {
	Packages   []Package
	Declared   map[string]string // the extension's own dependencies
	Lockfiles  []string
	HasModules bool
}

const maxPackages = 20000

type manifest struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Scripts              map[string]string `json:"scripts"`
	Deprecated           any               `json:"deprecated"`
	Dependencies         map[string]string `json:"dependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
}

func readManifest(path string) (*manifest, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

func merged(a, b map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

func deprecatedText(v any) string {
	switch d := v.(type) {
	case string:
		return d
	case bool:
		if d {
			return "deprecated"
		}
	}
	return ""
}

// Collect walks node_modules (symlinks are not followed) and reads package-lock.json /
// npm-shrinkwrap.json. Lockfile entries add packages not present on disk.
func Collect(root string, own map[string]any) Inventory {
	inv := Inventory{Declared: map[string]string{}}
	for _, key := range []string{"dependencies", "optionalDependencies"} {
		if deps, ok := own[key].(map[string]any); ok {
			for k, v := range deps {
				if s, ok := v.(string); ok {
					inv.Declared[k] = s
				}
			}
		}
	}
	seen := map[string]bool{}
	var walk func(dir string, depth int)
	walk = func(dir string, depth int) {
		nm := filepath.Join(dir, "node_modules")
		entries, err := os.ReadDir(nm)
		if err != nil {
			return
		}
		inv.HasModules = true
		for _, e := range entries {
			if len(inv.Packages) >= maxPackages {
				return
			}
			if e.Type()&os.ModeSymlink != 0 || !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
				continue
			}
			dirs := []string{filepath.Join(nm, e.Name())}
			if strings.HasPrefix(e.Name(), "@") {
				dirs = nil
				sub, _ := os.ReadDir(filepath.Join(nm, e.Name()))
				for _, s := range sub {
					if s.IsDir() && s.Type()&os.ModeSymlink == 0 {
						dirs = append(dirs, filepath.Join(nm, e.Name(), s.Name()))
					}
				}
			}
			for _, d := range dirs {
				m, err := readManifest(filepath.Join(d, "package.json"))
				if err != nil || m.Name == "" {
					continue
				}
				rel, _ := filepath.Rel(root, d)
				rel = filepath.ToSlash(rel)
				seen[m.Name+"@"+m.Version] = true
				inv.Packages = append(inv.Packages, Package{
					Name: m.Name, Version: m.Version, Path: rel, Depth: depth, Scripts: m.Scripts,
					Deprecated: deprecatedText(m.Deprecated), Deps: merged(m.Dependencies, m.OptionalDependencies),
				})
				walk(d, depth+1)
			}
		}
	}
	walk(root, 1)

	for _, name := range []string{"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"} {
		if _, err := os.Stat(filepath.Join(root, name)); err == nil {
			inv.Lockfiles = append(inv.Lockfiles, name)
		}
	}
	for _, name := range []string{"package-lock.json", "npm-shrinkwrap.json"} {
		b, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			continue
		}
		var lock struct {
			Packages map[string]struct {
				Version          string            `json:"version"`
				Resolved         string            `json:"resolved"`
				HasInstallScript bool              `json:"hasInstallScript"`
				Deprecated       string            `json:"deprecated"`
				Dev              bool              `json:"dev"`
				Dependencies     map[string]string `json:"dependencies"`
			} `json:"packages"`
		}
		if json.Unmarshal(b, &lock) != nil {
			continue
		}
		keys := make([]string, 0, len(lock.Packages))
		for k := range lock.Packages {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			p := lock.Packages[k]
			i := strings.LastIndex(k, "node_modules/")
			if k == "" || i < 0 || p.Dev {
				continue
			}
			pkgName := k[i+len("node_modules/"):]
			if seen[pkgName+"@"+p.Version] {
				continue
			}
			seen[pkgName+"@"+p.Version] = true
			var scripts map[string]string
			if p.HasInstallScript {
				scripts = map[string]string{"install": "(declared in " + name + ")"}
			}
			inv.Packages = append(inv.Packages, Package{
				Name: pkgName, Version: p.Version, Path: name + ":" + k, Depth: strings.Count(k, "node_modules/"),
				Scripts: scripts, Deprecated: p.Deprecated, Resolved: p.Resolved, Deps: p.Dependencies, FromLock: true,
			})
		}
	}
	return inv
}
