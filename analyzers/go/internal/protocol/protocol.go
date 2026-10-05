// Package protocol implements the jest-security analyzer protocol v1: `info` prints an Info object,
// `analyze` reads one Request from stdin and writes NDJSON messages, ending with a `done` message.
package protocol

import (
	"encoding/json"
	"io"
	"sync"
)

const Version = 1

type Info struct {
	Name     string   `json:"name"`
	Version  string   `json:"version"`
	Protocol int      `json:"protocol"`
	Vectors  []string `json:"vectors"`
}

type Extension struct {
	ID       string         `json:"id"`
	Version  string         `json:"version"`
	Path     string         `json:"path"`
	Manifest map[string]any `json:"manifest"`
}

type Options struct {
	Online    bool    `json:"online"`
	MaxFileMB float64 `json:"maxFileMB"`
	MaxFiles  int     `json:"maxFiles"`
}

type Request struct {
	Protocol   int         `json:"protocol"`
	Extensions []Extension `json:"extensions"`
	Vectors    []string    `json:"vectors"`
	Options    Options     `json:"options"`
}

type Location struct {
	File string `json:"file"`
	Line int    `json:"line,omitempty"`
	Col  int    `json:"col,omitempty"`
}

type Skipped struct {
	ID     string `json:"id"`
	Reason string `json:"reason"`
}

// Emitter writes messages as NDJSON; safe for concurrent use.
type Emitter struct {
	mu  sync.Mutex
	enc *json.Encoder
}

func NewEmitter(w io.Writer) *Emitter { return &Emitter{enc: json.NewEncoder(w)} }

func (e *Emitter) write(m map[string]any) {
	e.mu.Lock()
	defer e.mu.Unlock()
	_ = e.enc.Encode(m)
}

// Signal reports one vector hit. confidence is 0..1.
func (e *Emitter) Signal(ext, vector, message string, locs []Location, evidence string, confidence float64) {
	m := map[string]any{"type": "signal", "ext": ext, "vector": vector, "message": message, "confidence": confidence}
	if len(locs) > 0 {
		m["locations"] = locs
	}
	if evidence != "" {
		m["evidence"] = evidence
	}
	e.write(m)
}

func (e *Emitter) Metric(ext, name string, value float64) {
	e.write(map[string]any{"type": "metric", "ext": ext, "name": name, "value": value})
}

func (e *Emitter) Progress(ext, message string) {
	e.write(map[string]any{"type": "progress", "ext": ext, "message": message})
}

func (e *Emitter) Error(ext, message string) {
	e.write(map[string]any{"type": "error", "ext": ext, "message": message})
}

func (e *Emitter) Done(ran []string, skipped []Skipped) {
	if ran == nil {
		ran = []string{}
	}
	m := map[string]any{"type": "done", "ran": ran}
	if len(skipped) > 0 {
		m["skipped"] = skipped
	}
	e.write(m)
}
