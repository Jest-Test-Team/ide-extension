// jest-ext-go is the Go analyzer of `jest-security scan-extension --deep`: supply chain (bundled npm
// packages, OSV), published-package integrity and domain inventory. It never runs extension code.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/Jest-Test-Team/ide-extension/analyzers/go/internal/protocol"
	"github.com/Jest-Test-Team/ide-extension/analyzers/go/internal/scan"
)

var version = "0.1.0"

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: jest-ext-go info | analyze < request.json | version")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "info":
		_ = json.NewEncoder(os.Stdout).Encode(protocol.Info{Name: "jest-ext-go", Version: version, Protocol: protocol.Version, Vectors: scan.Vectors()})
	case "version", "--version":
		fmt.Println(version)
	case "analyze":
		var req protocol.Request
		if err := json.NewDecoder(os.Stdin).Decode(&req); err != nil {
			fmt.Fprintln(os.Stderr, "invalid request:", err)
			os.Exit(2)
		}
		if req.Protocol != protocol.Version {
			fmt.Fprintf(os.Stderr, "unsupported protocol %d (want %d)\n", req.Protocol, protocol.Version)
			os.Exit(2)
		}
		r := scan.Runner{Out: protocol.NewEmitter(os.Stdout), Client: scan.DefaultClient(), Ctx: context.Background()}
		r.Run(req)
	default:
		fmt.Fprintln(os.Stderr, "unknown command:", os.Args[1])
		os.Exit(2)
	}
}
