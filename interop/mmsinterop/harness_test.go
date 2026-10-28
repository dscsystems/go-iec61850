// Package mmsinterop_test runs this library against the adapter images of
// otfabric/mms-interop: libiec61850, iec61850bean and iec61850-rust, each
// in a container of its own, loading the same fixture (testdata/, a copy
// of mms-interop's fixtures/) and speaking the adapter contract of JSON
// Lines on stdout. See README.md.
//
// The tests are skipped unless MMS_INTEROP=1. With it set, a missing
// Docker daemon or image fails the run instead of skipping it, so CI
// cannot pass on infrastructure that never ran.
package mmsinterop_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// Images are mms-interop v0.4.0, pinned by the digest of their multi-arch
// index. An environment variable named after the stack replaces one, for
// a locally built image (mms-interop `make build`) or a newer release.
var stacks = []stack{
	{
		name:     "libiec61850",
		imageEnv: "LIBIEC61850_IMAGE",
		image:    "ghcr.io/otfabric/mms-interop-libiec61850@sha256:966e17e37e7fb5c22b825443ce79565d51067705c8f8485fd63d4001b4bd31ff",
	},
	{
		name:     "iec61850bean",
		imageEnv: "IEC61850BEAN_IMAGE",
		image:    "ghcr.io/otfabric/mms-interop-iec61850bean@sha256:ab2cda6a77ea054a04a736fdf1c36c5c8f50c766aa41cf5818bd11f3fadfac7d",
	},
	{
		name:     "iec61850-rust",
		imageEnv: "IEC61850RUST_IMAGE",
		image:    "ghcr.io/otfabric/mms-interop-iec61850-rust@sha256:c46c83c6d7eaa9800bbe48fb6ca9d25a4e9338d0bfc6f31fbba7813d89e4445d",
	},
}

// fixtureRevision is the IEC 61850 fixture of testdata/; an adapter that
// reports another one serves a different model.
const fixtureRevision = "iec61850-v3"

// stack is one third-party implementation and its adapter image. The
// dscsystems adapter of mms-interop is this library at a pinned commit,
// so it is not one of them.
type stack struct {
	name     string
	imageEnv string
	image    string
}

func (s stack) dockerImage() string {
	if v := os.Getenv(s.imageEnv); v != "" {
		return v
	}
	return s.image
}

// command is the adapter command of a role, e.g. "libiec61850-ied-server".
func (s stack) command(role string) string { return s.name + "-" + role }

// has reports whether the stack's image provides the command of role,
// according to testdata/capabilities.json.
func (s stack) has(role string) bool { return caps.Commands[s.command(role)] }

// capabilities is testdata/capabilities.json, the authoritative list of
// what each adapter provides and of the limitations known for it.
type capabilities struct {
	AdapterVersion   string          `json:"adapterVersion"`
	FixtureRevision  string          `json:"fixtureRevision"`
	Commands         map[string]bool `json:"commands"`
	KnownLimitations []struct {
		Stack      string `json:"stack"`
		Direction  string `json:"direction"`
		Capability string `json:"capability"`
		Reason     string `json:"reason"`
	} `json:"knownLimitations"`
	SVCBOverMMS map[string]any `json:"svcbOverMms"`
}

var caps capabilities

// svcbOverMMS reports whether the stack's IED server exposes MSVCB02.
func (c capabilities) svcbOverMMS(stack string) bool {
	b, _ := c.SVCBOverMMS[stack].(bool)
	return b
}

// limitation returns the reason capabilities.json records for a known
// limitation of stack whose capability text contains capability.
func (c capabilities) limitation(stack, capability string) (string, bool) {
	for _, l := range c.KnownLimitations {
		if l.Stack == stack && strings.Contains(l.Capability, capability) {
			return l.Reason, true
		}
	}
	return "", false
}

// gaps are peer behaviours these tests found that capabilities.json does
// not record, by stack and a key the test names. A test that meets one
// skips with its reason rather than passing quietly; each is a candidate
// for mms-interop's knownLimitations.
var gaps = map[string]map[string]string{
	"libiec61850": {
		"values:InteropLD/GGIO1.DPS1.stVal":    "the adapter's ied-server does not apply this values.json entry (it reads the SCL default)",
		"values:InteropLD/MMTR1.TotVAh.actVal": "the adapter's ied-server does not apply this values.json entry (it reads the SCL default)",
	},
	"iec61850-rust": {
		"urcb:datset": "the URCB's DatSet is the dataset without its logical device (LLN0$dsInterop), " +
			"where IEC 61850-8-1 has the full reference",
	},
	"iec61850bean": {
		"values:InteropLD/GGIO1.DPS1.stVal":    "the adapter's ied-server does not apply this values.json entry (it reads the SCL default)",
		"values:InteropLD/MMTR1.TotVAh.actVal": "the adapter's ied-server does not apply this values.json entry (it reads the SCL default)",
		"read-dataset:no-spec": "the server answers a Read of a named variable list with specificationWithResult FALSE (the ISO 9506 default) " +
			"with a service error (others); with TRUE it answers",
	},
}

// noteGap reports whether stack has the gap key, and logs its reason when
// it has, for a check that is waived without skipping the test.
func noteGap(t *testing.T, stack, key string) bool {
	t.Helper()
	why, ok := gaps[stack][key]
	if ok {
		t.Logf("%s: known gap: %s", stack, why)
	}
	return ok
}

// skipGap skips the test when stack has the gap key.
func skipGap(t *testing.T, stack, key string) {
	t.Helper()
	if why, ok := gaps[stack][key]; ok {
		t.Skipf("%s: known gap: %s", stack, why)
	}
}

func TestMain(m *testing.M) {
	b, err := os.ReadFile("testdata/capabilities.json")
	if err == nil {
		err = json.Unmarshal(b, &caps)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "testdata/capabilities.json:", err)
		os.Exit(1)
	}
	if caps.FixtureRevision != fixtureRevision {
		fmt.Fprintf(os.Stderr, "capabilities.json is for fixture %s, the tests for %s\n",
			caps.FixtureRevision, fixtureRevision)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

// peers returns the stacks to test against: all of them, or those named
// in MMS_INTEROP_STACKS (comma-separated). It skips the test unless
// MMS_INTEROP=1, and fails it when Docker is not usable.
func peers(t *testing.T) []stack {
	t.Helper()
	if os.Getenv("MMS_INTEROP") != "1" {
		t.Skip("set MMS_INTEROP=1 to run against the mms-interop adapter images (see interop/run-mms-interop.sh)")
	}
	dockerOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if out, err := exec.CommandContext(ctx, "docker", "version", "--format", "{{.Server.Version}}").CombinedOutput(); err != nil {
			dockerErr = fmt.Errorf("docker is not usable: %v: %s", err, bytes.TrimSpace(out))
		}
	})
	if dockerErr != nil {
		t.Fatal(dockerErr)
	}
	want := os.Getenv("MMS_INTEROP_STACKS")
	var out []stack
	for _, s := range stacks {
		if want == "" || slices.Contains(strings.Split(want, ","), s.name) {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		t.Fatalf("MMS_INTEROP_STACKS=%q names no stack", want)
	}
	return out
}

var (
	dockerOnce sync.Once
	dockerErr  error
)

// forEachPeer runs fn as a subtest per stack that provides role.
func forEachPeer(t *testing.T, role string, fn func(t *testing.T, s stack)) {
	t.Helper()
	for _, s := range peers(t) {
		t.Run(s.name, func(t *testing.T) {
			if !s.has(role) {
				t.Skipf("%s has no %s command", s.name, role)
			}
			fn(t, s)
		})
	}
}

// line is one JSON Line an adapter wrote on stdout.
type line map[string]any

func (l line) str(k string) string { s, _ := l[k].(string); return s }
func (l line) ok() bool            { b, _ := l["ok"].(bool); return b }
func (l line) event() string       { return l.str("event") }
func (l line) op() string          { return l.str("operation") }

func (l line) String() string {
	b, _ := json.Marshal(map[string]any(l))
	return string(b)
}

// adapter is a running adapter container.
type adapter struct {
	t    *testing.T
	name string // the container's name

	mu     sync.Mutex
	lines  []line
	notify chan struct{} // closed and replaced on every new line
	stderr bytes.Buffer

	done     chan struct{} // closed when the container exits
	exitCode int
}

// startAdapter runs command of the stack's image in a container on the
// host network, so that the adapter and this process reach each other on
// the loopback: a client adapter dials a server of this process, and a
// server adapter listens on a port this process dials. The container is
// removed when the test ends, whatever its outcome.
func startAdapter(t *testing.T, s stack, role string, args ...string) *adapter {
	t.Helper()
	ensureImage(t, s)
	a := &adapter{
		t:      t,
		name:   containerName(t, role),
		notify: make(chan struct{}),
		done:   make(chan struct{}),
	}
	// Removing the container is the cleanup; the process context is a
	// backstop against a docker CLI that does not return.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	t.Cleanup(func() {
		rm := exec.Command("docker", "rm", "-f", a.name)
		_ = rm.Run()
		select {
		case <-a.done:
		case <-time.After(15 * time.Second):
			t.Errorf("%s: container did not stop", a.name)
		}
		cancel()
		if t.Failed() {
			a.mu.Lock()
			t.Logf("%s stdout:\n%s", a.name, joinLines(a.lines))
			t.Logf("%s stderr:\n%s", a.name, a.stderr.String())
			a.mu.Unlock()
		}
	})
	dockerArgs := append([]string{
		"run", "--rm", "--name", a.name,
		"--network", "host",
		"--entrypoint", s.command(role),
		s.dockerImage(),
	}, args...)
	cmd := exec.CommandContext(ctx, "docker", dockerArgs...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = &lockedWriter{mu: &a.mu, w: &a.stderr}
	if err := cmd.Start(); err != nil {
		t.Fatalf("docker run %s: %v", s.command(role), err)
	}
	go func() {
		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			var l line
			if err := json.Unmarshal(sc.Bytes(), &l); err != nil {
				// The contract keeps stdout for JSON Lines only.
				t.Errorf("%s: stdout line is not JSON: %q", a.name, sc.Text())
				continue
			}
			a.mu.Lock()
			a.lines = append(a.lines, l)
			close(a.notify)
			a.notify = make(chan struct{})
			a.mu.Unlock()
		}
		_ = cmd.Wait() // the exit code is the result
		a.mu.Lock()
		a.exitCode = cmd.ProcessState.ExitCode()
		a.mu.Unlock()
		close(a.done)
	}()
	return a
}

// waitFor returns the first line that match accepts, waiting up to d. It
// fails the test when the adapter exits or d passes first.
func (a *adapter) waitFor(d time.Duration, what string, match func(line) bool) line {
	a.t.Helper()
	deadline := time.After(d)
	seen := 0
	for {
		a.mu.Lock()
		for ; seen < len(a.lines); seen++ {
			if match(a.lines[seen]) {
				l := a.lines[seen]
				a.mu.Unlock()
				return l
			}
		}
		notify := a.notify
		a.mu.Unlock()
		select {
		case <-notify:
		case <-a.done:
			// Lines written just before the exit may still be unread.
			a.mu.Lock()
			rest := slices.ContainsFunc(a.lines[seen:], match)
			a.mu.Unlock()
			if !rest {
				a.t.Fatalf("%s exited (code %d) before %s", a.name, a.exitCode, what)
			}
		case <-deadline:
			a.t.Fatalf("%s: no %s within %v", a.name, what, d)
		}
	}
}

// wait waits for the adapter to exit and returns its exit code and every
// line it wrote.
func (a *adapter) wait(d time.Duration) (int, []line) {
	a.t.Helper()
	select {
	case <-a.done:
	case <-time.After(d):
		a.t.Fatalf("%s did not exit within %v", a.name, d)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.exitCode, slices.Clone(a.lines)
}

// ready waits for the readiness event of a server adapter and checks the
// fixture it reports.
func (a *adapter) ready() line {
	a.t.Helper()
	// iec61850bean starts a JVM; the others are ready within a second.
	l := a.waitFor(90*time.Second, "ready event", func(l line) bool { return l.event() == "ready" })
	if f := l.str("fixture"); f != "" && f != fixtureRevision {
		a.t.Fatalf("%s serves fixture %s, testdata/ is %s", a.name, f, fixtureRevision)
	}
	return l
}

// startPeerServer starts the stack's IED server on a free port and
// returns the address to dial once it is ready.
func startPeerServer(t *testing.T, s stack) string {
	t.Helper()
	port := freePort(t)
	a := startAdapter(t, s, "ied-server", "--port", strconv.Itoa(port))
	a.ready()
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
}

// runPeerClient runs a client adapter of the stack against addr, a server
// of this process, to the end of its fixed sequence.
func runPeerClient(t *testing.T, s stack, role, addr string, args ...string) (int, []line) {
	t.Helper()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	a := startAdapter(t, s, role, append([]string{"--host", host, "--port", port}, args...)...)
	return a.wait(2 * time.Minute)
}

// find returns the first line of operation op (and target, when not
// empty).
func find(lines []line, op, target string) (line, bool) {
	for _, l := range lines {
		if l.op() == op && (target == "" || l.str("target") == target) {
			return l, true
		}
	}
	return nil, false
}

// mustFind is find that fails the test when there is no such line.
func mustFind(t *testing.T, lines []line, op, target string) line {
	t.Helper()
	l, ok := find(lines, op, target)
	if !ok {
		t.Fatalf("no %q line for %q in:\n%s", op, target, joinLines(lines))
	}
	return l
}

// skipUnsupported skips the test when the adapter answered that it cannot
// run the command at all, which the contract allows a stack to do.
func skipUnsupported(t *testing.T, lines []line) {
	t.Helper()
	for _, l := range lines {
		if l.event() == "error" && l.str("code") == "unsupported" {
			t.Skipf("adapter: unsupported: %s", l.str("reason"))
		}
	}
}

// ensureImage pulls the stack's image unless it is present, so the pull
// does not run against the timeouts of a test.
func ensureImage(t *testing.T, s stack) {
	t.Helper()
	img := s.dockerImage()
	imagesMu.Lock()
	defer imagesMu.Unlock()
	if err, done := images[img]; done {
		if err != nil {
			t.Fatal(err)
		}
		return
	}
	var err error
	if exec.Command("docker", "image", "inspect", img).Run() != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		if out, perr := exec.CommandContext(ctx, "docker", "pull", "-q", img).CombinedOutput(); perr != nil {
			err = fmt.Errorf("docker pull %s: %v: %s", img, perr, bytes.TrimSpace(out))
		}
	}
	images[img] = err
	if err != nil {
		t.Fatal(err)
	}
}

var (
	imagesMu sync.Mutex
	images   = map[string]error{}
)

// containerName is unique per test and role, and recognisable in docker ps.
func containerName(t *testing.T, role string) string {
	r := strings.NewReplacer("/", "-", " ", "_", "#", "")
	return fmt.Sprintf("gi61850-%s-%s-%d", r.Replace(t.Name()), role, time.Now().UnixNano()%1e9)
}

// freePort returns a TCP port free on the loopback for an adapter server
// to listen on. The adapters take a port rather than a listener, so there
// is a window in which another process could take it; on a test host
// that is acceptable.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

func joinLines(lines []line) string {
	var b strings.Builder
	for _, l := range lines {
		b.WriteString(l.String())
		b.WriteByte('\n')
	}
	return b.String()
}

type lockedWriter struct {
	mu *sync.Mutex
	w  *bytes.Buffer
}

func (w *lockedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.w.Write(p)
}
