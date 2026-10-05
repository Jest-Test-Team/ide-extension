package vsix

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

var GitHubAPI = "https://api.github.com"

var ghRepo = regexp.MustCompile(`github\.com[/:]([\w.-]+)/([\w.-]+?)(?:\.git)?(?:[/#?]|$)`)

// GitHubRepo extracts owner/repo from a manifest `repository` value.
func GitHubRepo(manifest map[string]any) (string, string, bool) {
	var raw string
	switch v := manifest["repository"].(type) {
	case string:
		raw = v
	case map[string]any:
		raw, _ = v["url"].(string)
	}
	m := ghRepo.FindStringSubmatch(raw)
	if m == nil {
		return "", "", false
	}
	return m[1], m[2], true
}

// HasVersionTag checks the repository's latest 100 tags and releases for one naming the version
// (`1.2.3`, `v1.2.3`, `name@1.2.3`, `name-v1.2.3`, …). The result is false with a nil error only when
// the repository answered and no tag matched.
func HasVersionTag(ctx context.Context, client *http.Client, owner, repo, version string) (bool, error) {
	re := regexp.MustCompile(`(^|[^0-9.])v?` + regexp.QuoteMeta(version) + `$`)
	for _, kind := range []string{"tags", "releases"} {
		u := fmt.Sprintf("%s/repos/%s/%s/%s?per_page=100", GitHubAPI, url.PathEscape(owner), url.PathEscape(repo), kind)
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		req, _ := http.NewRequestWithContext(cctx, http.MethodGet, u, nil)
		req.Header.Set("Accept", "application/vnd.github+json")
		if tok := os.Getenv("GITHUB_TOKEN"); tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		res, err := client.Do(req)
		if err != nil {
			cancel()
			return false, err
		}
		var items []struct {
			Name    string `json:"name"`
			TagName string `json:"tag_name"`
		}
		status := res.StatusCode
		err = json.NewDecoder(res.Body).Decode(&items)
		res.Body.Close()
		cancel()
		if status == http.StatusNotFound {
			return false, ErrNotFound
		}
		if status != http.StatusOK {
			return false, fmt.Errorf("GitHub API: HTTP %d", status)
		}
		if err != nil {
			return false, err
		}
		for _, it := range items {
			name := it.Name
			if kind == "releases" {
				name = it.TagName
			}
			if re.MatchString(strings.TrimSpace(name)) {
				return true, nil
			}
		}
	}
	return false, nil
}
