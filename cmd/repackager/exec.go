package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// run returns the stdout of a tool. It also returns the stdout of a tool
// that failed, because sbom-utility prints its findings there.
var run = func(ctx context.Context, name string, args ...string) ([]byte, error) {
	logf("+ %s %s", name, strings.Join(args, " "))
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		tail := strings.TrimSpace(stderr.String())
		// The callers match the error text, so it holds only the stderr of the
		// tool and not the args.
		return stdout.Bytes(), fmt.Errorf("%s: %w: %s", name, err, tail[max(0, len(tail)-2048):])
	}
	return stdout.Bytes(), nil
}

func runJSON(ctx context.Context, name string, args ...string) (any, error) {
	return decode(run(ctx, name, args...))
}

func readJSON(path string) (any, error) { return decode(os.ReadFile(path)) }

func decode(data []byte, err error) (any, error) {
	var v any
	if err == nil {
		err = json.Unmarshal(data, &v)
	}
	return v, err
}

// ghArgs passes --hostname, so that GH_HOST cannot change the host.
func ghArgs(args ...string) []string {
	return append([]string{"api", "--hostname", "github.com"}, args...)
}

func get(v any, path ...string) any {
	for _, p := range path {
		m, _ := v.(map[string]any)
		v = m[p]
	}
	return v
}

func str(v any, path ...string) string {
	s, _ := get(v, path...).(string)
	return s
}

func list(v any, path ...string) []any {
	l, _ := get(v, path...).([]any)
	return l
}

func fileSHA256(path string) (string, error) {
	data, err := os.ReadFile(path)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), err
}
