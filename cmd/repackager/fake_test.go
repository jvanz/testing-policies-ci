package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"slices"
	"strings"
	"testing"
)

// rule gives the result of the first call whose command line starts with
// prefix. In the command line, the work directory is "$WORK".
type rule struct {
	prefix string
	out    string
	err    string // if not empty, the call fails with this message
	write  string // if not empty, written to the path after -o or --output
	once   bool   // if true, the rule is removed after its first match
}

type fake struct {
	t     *testing.T
	work  string
	rules []rule
	calls []string
}

// newFake replaces run until the test ends. It also sets the tool names,
// which otherwise only the flags set, discards the log and clears the GitHub
// Actions files, so that a test run in a workflow does not write to them.
func newFake(t *testing.T, work string, rules ...rule) *fake {
	f := &fake{t: t, work: work, rules: rules}
	oldRun, oldLog, oldGh := run, logOut, gh
	run, logOut = f.run, io.Discard
	gh = "gh"
	t.Cleanup(func() { run, logOut, gh = oldRun, oldLog, oldGh })
	t.Setenv("GITHUB_OUTPUT", "")
	t.Setenv("GITHUB_STEP_SUMMARY", "")
	return f
}

func (f *fake) run(_ context.Context, name string, args ...string) ([]byte, error) {
	line := strings.Join(append([]string{name}, args...), " ")
	if f.work != "" {
		line = strings.ReplaceAll(line, f.work, "$WORK")
	}
	f.calls = append(f.calls, line)
	i := slices.IndexFunc(f.rules, func(r rule) bool { return strings.HasPrefix(line, r.prefix) })
	if i < 0 {
		f.t.Errorf("no rule matches the call %q", line)
		return nil, errors.New("no rule matches the call")
	}
	r := f.rules[i]
	if r.once {
		f.rules = slices.Delete(f.rules, i, i+1)
	}
	if r.write != "" {
		for k, a := range args[:len(args)-1] {
			if a == "-o" || a == "--output" {
				if err := os.WriteFile(args[k+1], []byte(r.write), 0o644); err != nil {
					f.t.Fatal(err)
				}
			}
		}
	}
	if r.err != "" {
		return []byte(r.out), errors.New(r.err)
	}
	return []byte(r.out), nil
}

// execute runs the command line and returns what it wrote to stdout.
func execute(t *testing.T, args ...string) (string, error) {
	var out bytes.Buffer
	old := cmdOut
	cmdOut = &out
	t.Cleanup(func() { cmdOut = old })
	root := newRootCommand()
	root.SetArgs(args)
	err := root.ExecuteContext(context.Background())
	return out.String(), err
}
