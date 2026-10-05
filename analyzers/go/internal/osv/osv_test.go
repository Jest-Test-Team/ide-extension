package osv

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLookup(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Queries []struct {
				Package struct{ Name, Ecosystem string }
				Version string
			}
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		out := map[string]any{"results": []any{}}
		res := []any{}
		for _, q := range body.Queries {
			switch q.Package.Name {
			case "evil":
				res = append(res, map[string]any{"vulns": []any{map[string]any{"id": "MAL-2024-1"}}})
			case "old":
				res = append(res, map[string]any{"vulns": []any{map[string]any{"id": "GHSA-xxxx"}}})
			default:
				res = append(res, map[string]any{})
			}
			if q.Package.Ecosystem != "npm" {
				t.Errorf("ecosystem %q", q.Package.Ecosystem)
			}
		}
		out["results"] = res
		_ = json.NewEncoder(w).Encode(out)
	}))
	defer srv.Close()
	Endpoint = srv.URL
	got, err := Lookup(context.Background(), srv.Client(), []Query{{"ok", "1.0.0"}, {"evil", "1.0.0"}, {"old", "0.1.0"}})
	if err != nil || len(got) != 2 {
		t.Fatalf("%v %v", got, err)
	}
	if !got[0].Malicious() || got[1].Malicious() || got[1].Name != "old" {
		t.Errorf("classification: %+v", got)
	}
}
