package scan

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/Jest-Test-Team/ide-extension/analyzers/go/internal/protocol"
)

func TestRunOffline(t *testing.T) {
	root := t.TempDir()
	nm := filepath.Join(root, "node_modules", "peacenotwar")
	_ = os.MkdirAll(nm, 0o755)
	_ = os.WriteFile(filepath.Join(nm, "package.json"), []byte(`{"name":"peacenotwar","version":"9.1.6"}`), 0o644)
	_ = os.WriteFile(filepath.Join(root, "extension.js"), []byte(`fetch("https://collector.badhost.net/x")`), 0o644)

	var buf bytes.Buffer
	r := Runner{Out: protocol.NewEmitter(&buf), Client: http.DefaultClient, Ctx: context.Background()}
	r.Run(protocol.Request{
		Protocol:   1,
		Extensions: []protocol.Extension{{ID: "acme.ext", Version: "1.0.0", Path: root, Manifest: map[string]any{}}},
		Vectors:    append([]string{"ext/protestware", "ext/domain-inventory", "ext/missing-lockfile"}, OnlineVectors...),
		Options:    protocol.Options{Online: false},
	})
	signals := map[string]string{}
	var done map[string]any
	sc := bufio.NewScanner(&buf)
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			t.Fatalf("bad NDJSON line %q", sc.Text())
		}
		switch m["type"] {
		case "signal":
			signals[m["vector"].(string)] = m["message"].(string)
		case "done":
			done = m
		}
	}
	for _, v := range []string{"ext/protestware", "ext/domain-inventory", "ext/missing-lockfile"} {
		if signals[v] == "" {
			t.Errorf("missing %s in %v", v, signals)
		}
	}
	if done == nil || len(done["ran"].([]any)) != 3 || len(done["skipped"].([]any)) != len(OnlineVectors) {
		t.Fatalf("done: %v", done)
	}
}
