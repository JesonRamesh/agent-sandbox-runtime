// test-client is a minimal stand-in for P3's agentctl. It lets us drive
// every IPC method end-to-end before the real CLI lands. Print response
// JSON to stdout; everything diagnostic goes to stderr.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/JesonRamesh/agent-sandbox-runtime/daemon/internal/ipc"
)

func main() {
	socketPath := flag.String("socket", ipc.DefaultSocketPath, "path to the daemon Unix socket")
	flag.Usage = usage
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		usage()
		os.Exit(2)
	}

	cmd, rest := args[0], args[1:]
	var err error
	switch cmd {
	case "run":
		err = cmdRun(*socketPath, rest)
	case "stop":
		err = cmdStop(*socketPath, rest)
	case "list":
		err = cmdList(*socketPath)
	case "logs":
		err = cmdLogs(*socketPath, rest)
	case "stream":
		err = cmdStream(*socketPath, rest)
	case "status":
		err = cmdStatus(*socketPath)
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "test-client: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `Usage: test-client [--socket PATH] <command> [args]

Commands:
  run <manifest-json-file>   send RunAgent
  stop <agent_id>            send StopAgent
  list                       send ListAgents
  logs <agent_id>            send AgentLogs (tail 100)
  stream [agent_id]          subscribe to StreamEvents
  status                     send DaemonStatus
`)
}

// dial opens the socket and returns the connection. Caller closes.
func dial(socketPath string) (net.Conn, error) {
	c, err := net.Dial("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", socketPath, err)
	}
	return c, nil
}

// sendRequest writes a single request and reads a single response, returning
// the raw response. Suitable for everything except StreamEvents.
func sendRequest(socketPath, method string, params any) (*ipc.Response, error) {
	c, err := dial(socketPath)
	if err != nil {
		return nil, err
	}
	defer c.Close()

	raw, err := json.Marshal(params)
	if err != nil {
		return nil, fmt.Errorf("marshal params: %w", err)
	}
	if err := ipc.WriteFrame(c, ipc.Request{Method: method, Params: raw}); err != nil {
		return nil, fmt.Errorf("write request: %w", err)
	}
	var resp ipc.Response
	if err := ipc.ReadFrame(c, &resp); err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	return &resp, nil
}

// printResponse pretty-prints a response. Returns a non-nil error when the
// response is an error response, so the process exits non-zero.
func printResponse(resp *ipc.Response) error {
	out, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal response: %w", err)
	}
	fmt.Println(string(out))
	if !resp.OK {
		if resp.Error != nil {
			return fmt.Errorf("server error: %s: %s", resp.Error.Code, resp.Error.Message)
		}
		return errors.New("server error with no detail")
	}
	return nil
}

func cmdRun(socketPath string, args []string) error {
	if len(args) != 1 {
		return errors.New("run requires <manifest-json-file>")
	}
	data, err := os.ReadFile(args[0])
	if err != nil {
		return fmt.Errorf("read manifest %s: %w", args[0], err)
	}
	var m ipc.Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return fmt.Errorf("parse manifest: %w", err)
	}
	resp, err := sendRequest(socketPath, ipc.MethodRunAgent, ipc.RunAgentParams{Manifest: m})
	if err != nil {
		return err
	}
	return printResponse(resp)
}

func cmdStop(socketPath string, args []string) error {
	if len(args) != 1 {
		return errors.New("stop requires <agent_id>")
	}
	resp, err := sendRequest(socketPath, ipc.MethodStopAgent, ipc.StopAgentParams{AgentID: args[0]})
	if err != nil {
		return err
	}
	return printResponse(resp)
}

func cmdList(socketPath string) error {
	resp, err := sendRequest(socketPath, ipc.MethodListAgents, ipc.ListAgentsParams{})
	if err != nil {
		return err
	}
	return printResponse(resp)
}

func cmdLogs(socketPath string, args []string) error {
	if len(args) != 1 {
		return errors.New("logs requires <agent_id>")
	}
	// Hardcoded tail of 100 mirrors api/proto.md's example. A real CLI would
	// expose a flag; we don't.
	resp, err := sendRequest(socketPath, ipc.MethodAgentLogs, ipc.AgentLogsParams{
		AgentID: args[0],
		TailN:   100,
	})
	if err != nil {
		return err
	}
	return printResponse(resp)
}

func cmdStream(socketPath string, args []string) error {
	var agentID string
	if len(args) == 1 {
		agentID = args[0]
	} else if len(args) > 1 {
		return errors.New("stream takes at most one arg")
	}
	c, err := dial(socketPath)
	if err != nil {
		return err
	}
	defer c.Close()

	// Catch SIGINT so Ctrl-C cleanly closes the connection rather than
	// dumping a stack trace.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		_ = c.Close()
	}()

	raw, _ := json.Marshal(ipc.StreamEventsParams{AgentID: agentID})
	if err := ipc.WriteFrame(c, ipc.Request{Method: ipc.MethodStreamEvents, Params: raw}); err != nil {
		return fmt.Errorf("write request: %w", err)
	}
	for {
		var resp ipc.Response
		if err := ipc.ReadFrame(c, &resp); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("read frame: %w", err)
		}
		out, err := json.Marshal(resp)
		if err != nil {
			return fmt.Errorf("marshal: %w", err)
		}
		fmt.Println(string(out))
		if !resp.OK {
			if resp.Error != nil {
				return fmt.Errorf("server error: %s: %s", resp.Error.Code, resp.Error.Message)
			}
			return errors.New("server error with no detail")
		}
	}
}

func cmdStatus(socketPath string) error {
	resp, err := sendRequest(socketPath, ipc.MethodDaemonStatus, ipc.DaemonStatusParams{})
	if err != nil {
		return err
	}
	return printResponse(resp)
}
