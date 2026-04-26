// Command agentctl is the user-facing CLI for agent-sandbox-runtime.
//
// It is a thin HTTP client over the daemon's API (decision D-009) plus
// a tiny cgroup-launching shim. Subcommands:
//
//   agentctl run     <manifest.yaml>   create cgroup, apply policy, exec
//   agentctl ps                        list running sandboxed agents
//   agentctl events  [--filter=...]    stream live events
//   agentctl policy  list | apply | delete
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"

	"gopkg.in/yaml.v3"
)

const cgroupRoot = "/sys/fs/cgroup/agentsandbox"

var daemonURL = envOr("AGENTSANDBOX_DAEMON", "http://127.0.0.1:9000")

type Manifest struct {
	Name           string   `yaml:"name"`
	Command        []string `yaml:"command"`
	Mode           string   `yaml:"mode"`
	AllowedHosts   []string `yaml:"allowed_hosts"`
	AllowedPaths   []string `yaml:"allowed_paths"`
	AllowedBins    []string `yaml:"allowed_bins"`
	ForbiddenCaps  []string `yaml:"forbidden_caps"`
}

func main() {
	flag.Parse()
	args := flag.Args()
	if len(args) == 0 {
		usage()
	}
	switch args[0] {
	case "run":
		if len(args) < 2 {
			fail("usage: agentctl run <manifest.yaml>")
		}
		runManifest(args[1])
	case "events":
		streamEvents()
	case "policy":
		policyCmd(args[1:])
	default:
		usage()
	}
}

// ----- run ------------------------------------------------------------

func runManifest(path string) {
	b, err := os.ReadFile(path)
	check(err)
	var m Manifest
	check(yaml.Unmarshal(b, &m))
	if m.Name == "" || len(m.Command) == 0 {
		fail("manifest must specify name and command")
	}

	// 1. Create the cgroup directory.
	cgroupPath := filepath.Join(cgroupRoot, m.Name)
	check(os.MkdirAll(cgroupPath, 0755))

	// 2. Read its inode (= cgroup_id used by the kernel).
	var st syscall.Stat_t
	check(syscall.Stat(cgroupPath, &st))
	cgID := st.Ino

	// 3. Push policy to the daemon. Use a deterministic ID = hash of name.
	policyID := uint32(fnv32(m.Name)%30 + 1) // 1..30, leaves 31 for ad-hoc
	policy := map[string]any{
		"id":             policyID,
		"name":           m.Name,
		"mode":           defaultStr(m.Mode, "enforce"),
		"allowed_hosts":  m.AllowedHosts,
		"allowed_paths":  m.AllowedPaths,
		"allowed_bins":   m.AllowedBins,
		"forbidden_caps": m.ForbiddenCaps,
	}
	check(httpPut(fmt.Sprintf("/api/policies/%d", policyID), policy))

	// 4. Bind cgroup -> policy.
	check(httpPost("/api/bindings", map[string]any{
		"cgroup_id": cgID,
		"policy_id": policyID,
	}))

	// 5. Move ourselves into the cgroup, then exec the command.
	pid := os.Getpid()
	check(os.WriteFile(filepath.Join(cgroupPath, "cgroup.procs"),
		[]byte(strconv.Itoa(pid)), 0644))

	fmt.Fprintf(os.Stderr,
		"agentctl: cgroup=%s id=%d policy=%d mode=%s — exec %v\n",
		cgroupPath, cgID, policyID, policy["mode"], m.Command)

	bin, err := exec.LookPath(m.Command[0])
	check(err)
	check(syscall.Exec(bin, m.Command, os.Environ()))
}

// ----- events ---------------------------------------------------------

func streamEvents() {
	resp, err := http.Get(daemonURL + "/api/events")
	check(err)
	defer resp.Body.Close()
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if !bytes.HasPrefix([]byte(line), []byte("data: ")) {
			continue
		}
		fmt.Println(line[len("data: "):])
	}
}

// ----- policy --------------------------------------------------------

func policyCmd(args []string) {
	if len(args) == 0 {
		fail("usage: agentctl policy list|apply|delete")
	}
	switch args[0] {
	case "list":
		var out []map[string]any
		check(httpGet("/api/policies", &out))
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
	case "apply":
		if len(args) < 2 {
			fail("usage: agentctl policy apply <file.yaml>")
		}
		b, err := os.ReadFile(args[1])
		check(err)
		var p map[string]any
		check(yaml.Unmarshal(b, &p))
		id, _ := p["id"].(int)
		check(httpPut(fmt.Sprintf("/api/policies/%d", id), p))
	default:
		fail("unknown policy subcommand: " + args[0])
	}
}

// ----- helpers --------------------------------------------------------

func httpGet(path string, out interface{}) error {
	resp, err := http.Get(daemonURL + path)
	if err != nil { return err }
	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(out)
}

func httpPut(path string, body interface{}) error {
	return httpDo("PUT", path, body)
}

func httpPost(path string, body interface{}) error {
	return httpDo("POST", path, body)
}

func httpDo(method, path string, body interface{}) error {
	b, err := json.Marshal(body)
	if err != nil { return err }
	req, err := http.NewRequest(method, daemonURL+path, bytes.NewReader(b))
	if err != nil { return err }
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil { return err }
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("%s %s: %s: %s", method, path, resp.Status, msg)
	}
	return nil
}

func fnv32(s string) uint32 {
	h := uint32(2166136261)
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619
	}
	return h
}

func envOr(k, dflt string) string {
	if v := os.Getenv(k); v != "" { return v }
	return dflt
}

func defaultStr(s, dflt string) string { if s == "" { return dflt }; return s }

func check(err error) { if err != nil { fail(err.Error()) } }

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "agentctl: "+msg)
	os.Exit(1)
}

func usage() {
	fmt.Fprintln(os.Stderr,
		"usage: agentctl run <manifest> | events | policy list|apply <file>")
	os.Exit(2)
}
