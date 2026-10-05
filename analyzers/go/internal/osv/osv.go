// Package osv looks npm package versions up in the OSV database (https://osv.dev). Only package
// names and versions are sent; it is used only when the user passes --online.
package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

var Endpoint = "https://api.osv.dev/v1/querybatch"

const batch = 500

type Query struct {
	Name    string
	Version string
}

type Result struct {
	Query
	IDs []string
}

// Malicious reports whether any advisory is an OSV malicious-package entry.
func (r Result) Malicious() bool {
	for _, id := range r.IDs {
		if strings.HasPrefix(id, "MAL-") {
			return true
		}
	}
	return false
}

// Lookup returns the queries with at least one advisory.
func Lookup(ctx context.Context, client *http.Client, qs []Query) ([]Result, error) {
	var out []Result
	for i := 0; i < len(qs); i += batch {
		end := min(i+batch, len(qs))
		type pkg struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		}
		type query struct {
			Package pkg    `json:"package"`
			Version string `json:"version"`
		}
		body := struct {
			Queries []query `json:"queries"`
		}{}
		for _, q := range qs[i:end] {
			body.Queries = append(body.Queries, query{pkg{q.Name, "npm"}, q.Version})
		}
		b, _ := json.Marshal(body)
		cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		req, _ := http.NewRequestWithContext(cctx, http.MethodPost, Endpoint, bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		res, err := client.Do(req)
		if err != nil {
			cancel()
			return out, err
		}
		var parsed struct {
			Results []struct {
				Vulns []struct {
					ID string `json:"id"`
				} `json:"vulns"`
			} `json:"results"`
		}
		err = json.NewDecoder(res.Body).Decode(&parsed)
		res.Body.Close()
		cancel()
		if res.StatusCode != http.StatusOK {
			return out, fmt.Errorf("OSV query failed: HTTP %d", res.StatusCode)
		}
		if err != nil {
			return out, err
		}
		for j, r := range parsed.Results {
			if len(r.Vulns) == 0 || i+j >= len(qs) {
				continue
			}
			res := Result{Query: qs[i+j]}
			for _, v := range r.Vulns {
				res.IDs = append(res.IDs, v.ID)
			}
			out = append(out, res)
		}
	}
	return out, nil
}
