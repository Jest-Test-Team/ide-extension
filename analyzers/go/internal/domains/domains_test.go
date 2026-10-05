package domains

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInventory(t *testing.T) {
	root := t.TempDir()
	js := "fetch('https://api.acme-tools.io/v1');\nfetch(\"https://telemetry.unknown-cdn.net/x\");\nconst ns='http://www.w3.org/2000/svg';\nconst f='https://evil.example.org';\nrequire('./x.js');\nfetch('https://telemetry.unknown-cdn.net/y')"
	if err := os.WriteFile(filepath.Join(root, "extension.js"), []byte(js), 0o644); err != nil {
		t.Fatal(err)
	}
	manifest := map[string]any{"repository": map[string]any{"url": "https://github.com/acme-tools/ext.git"}, "homepage": "https://docs.acme.dev"}
	hosts := Inventory(root, "acme.ext", manifest, false, 1<<20, 100)
	got := map[string]Class{}
	for _, h := range hosts {
		got[h.Name] = h.Class
	}
	want := map[string]Class{"api.acme-tools.io": FirstParty, "telemetry.unknown-cdn.net": ThirdParty, "www.w3.org": Platform, "evil.example.org": Platform}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: got %q want %q (all %v)", k, got[k], v, got)
		}
	}
	if len(hosts) != len(want) {
		t.Errorf("unexpected hosts %v", got)
	}
	if hosts[0].Name != "telemetry.unknown-cdn.net" || hosts[0].Count != 2 || hosts[0].Line != 2 {
		t.Errorf("ordering / count / line: %+v", hosts[0])
	}
}
