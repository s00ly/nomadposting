// netbroker is the narrow privileged boundary for egress setup.
//
// The current release intentionally ships with namespace execution disabled.
// Status and dry-run work on every supported development platform. The Linux
// Unix-socket service also remains fail-closed until a packet-capture-verified
// namespace executor replaces DisabledNamespaceExecutor.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"os/user"
	"runtime"
	"strings"
	"syscall"
	"time"

	"ivpn/internal/egress"
)

const (
	brokerSocket = "/run/ivpn/netbroker.sock"
	maxRequest   = 4096
)

type wireRequest struct {
	Operation string               `json:"operation"`
	Request   egress.BrokerRequest `json:"request"`
}

type wireResponse struct {
	OK     bool   `json:"ok"`
	Code   string `json:"code,omitempty"`
	Error  string `json:"error,omitempty"`
	Result any    `json:"result,omitempty"`
}

func main() {
	mode := flag.String("mode", "status", "status, dry-run, execute, or serve")
	jobID := flag.String("job", "", "validated job ID")
	platform := flag.String("platform", "", "x or nostr")
	endpointID := flag.String("endpoint", "", "registered endpoint ID")
	flag.Parse()

	registry, err := egress.NewRegistry(egress.DefaultEndpointCatalog())
	if err != nil {
		fatal("REGISTRY_INVALID", err)
	}
	broker, err := egress.NewGuardedBroker(registry, egress.DisabledNamespaceExecutor{}, false, egress.DefaultBrokerPolicy())
	if err != nil {
		fatal("BROKER_INVALID", err)
	}

	request := egress.BrokerRequest{JobID: *jobID, Platform: egress.Platform(*platform), EndpointID: egress.EndpointID(*endpointID)}
	switch *mode {
	case "status":
		writeJSON(os.Stdout, wireResponse{OK: true, Result: broker.Status()})
	case "dry-run":
		result, dryErr := broker.DryRun(request)
		if dryErr != nil {
			fatal(errorCode(dryErr), dryErr)
		}
		writeJSON(os.Stdout, wireResponse{OK: true, Result: result})
	case "execute":
		_, executeErr := broker.Execute(context.Background(), request, time.Now())
		if executeErr != nil {
			fatal(errorCode(executeErr), executeErr)
		}
	case "serve":
		if err := serve(broker); err != nil {
			fatal(errorCode(err), err)
		}
	default:
		fatal("INVALID_MODE", fmt.Errorf("unknown mode %q", *mode))
	}
}

func serve(broker *egress.GuardedBroker) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("%w: service mode requires Linux", egress.ErrExecutionDisabled)
	}
	currentUser, err := user.Current()
	if err != nil || currentUser.Uid != "0" {
		return errors.New("service mode must run as root")
	}
	// brokerSocket is a compile-time constant. No request can choose a path.
	if err := os.Remove(brokerSocket); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove stale broker socket: %w", err)
	}
	listener, err := net.Listen("unix", brokerSocket)
	if err != nil {
		return fmt.Errorf("listen on broker socket: %w", err)
	}
	defer listener.Close()
	defer os.Remove(brokerSocket)
	if err := os.Chmod(brokerSocket, 0o660); err != nil {
		return fmt.Errorf("set broker socket permissions: %w", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()

	for {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept broker request: %w", acceptErr)
		}
		handleConnection(ctx, broker, connection)
	}
}

func handleConnection(ctx context.Context, broker *egress.GuardedBroker, connection net.Conn) {
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
	// The socket protocol is one newline-delimited JSON object per connection.
	payload, readErr := bufio.NewReader(io.LimitReader(connection, maxRequest+1)).ReadBytes('\n')
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		writeJSON(connection, wireResponse{OK: false, Code: "INVALID_REQUEST", Error: "request could not be read"})
		return
	}
	if len(payload) > maxRequest {
		writeJSON(connection, wireResponse{OK: false, Code: "REQUEST_TOO_LARGE", Error: "request exceeds size limit"})
		return
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var request wireRequest
	if err := decoder.Decode(&request); err != nil {
		writeJSON(connection, wireResponse{OK: false, Code: "INVALID_REQUEST", Error: "request must match the typed broker schema"})
		return
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		writeJSON(connection, wireResponse{OK: false, Code: "INVALID_REQUEST", Error: "request must contain one JSON object"})
		return
	}

	var result any
	var err error
	switch request.Operation {
	case "status":
		result = broker.Status()
	case "dry_run":
		result, err = broker.DryRun(request.Request)
	case "execute":
		result, err = broker.Execute(ctx, request.Request, time.Now())
	default:
		err = errors.New("operation must be status, dry_run, or execute")
	}
	if err != nil {
		writeJSON(connection, wireResponse{OK: false, Code: errorCode(err), Error: publicError(err)})
		return
	}
	writeJSON(connection, wireResponse{OK: true, Result: result})
}

func errorCode(err error) string {
	switch {
	case errors.Is(err, egress.ErrUnknownEndpoint):
		return "UNKNOWN_ENDPOINT"
	case errors.Is(err, egress.ErrEndpointPlatformMismatch):
		return "ENDPOINT_PLATFORM_MISMATCH"
	case errors.Is(err, egress.ErrEndpointNotHealthy):
		return "ENDPOINT_NOT_HEALTHY"
	case errors.Is(err, egress.ErrExecutionDisabled):
		return "EXECUTION_DISABLED"
	default:
		return "INVALID_REQUEST"
	}
}

func publicError(err error) string {
	switch errorCode(err) {
	case "UNKNOWN_ENDPOINT":
		return "endpoint ID is not registered"
	case "ENDPOINT_PLATFORM_MISMATCH":
		return "endpoint is not allowed for the requested platform"
	case "ENDPOINT_NOT_HEALTHY":
		return "endpoint is not currently healthy"
	case "EXECUTION_DISABLED":
		return "privileged namespace execution is disabled"
	default:
		return "request rejected"
	}
}

func writeJSON(writer io.Writer, value wireResponse) {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(true)
	_ = encoder.Encode(value)
}

func fatal(code string, err error) {
	message := publicError(err)
	if strings.HasPrefix(code, "BROKER_") || strings.HasPrefix(code, "REGISTRY_") || code == "INVALID_MODE" {
		message = err.Error()
	}
	writeJSON(os.Stderr, wireResponse{OK: false, Code: code, Error: message})
	os.Exit(1)
}
