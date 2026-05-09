//go:build linux

package ipc

import (
	"fmt"
	"net"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

func authorizeIngest(conn net.Conn) error {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("%w: ingest requires a unix socket peer", ErrPermissionDeniedErr)
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return fmt.Errorf("%w: inspect peer credentials: %v", ErrPermissionDeniedErr, err)
	}

	var cred *unix.Ucred
	var controlErr error
	if err := raw.Control(func(fd uintptr) {
		cred, controlErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return fmt.Errorf("%w: inspect peer credentials: %v", ErrPermissionDeniedErr, err)
	}
	if controlErr != nil {
		return fmt.Errorf("%w: inspect peer credentials: %v", ErrPermissionDeniedErr, controlErr)
	}

	if cred != nil && cred.Uid == uint32(os.Getuid()) {
		return nil
	}
	if allowed := os.Getenv("AGENT_SANDBOX_INGEST_UID"); allowed != "" {
		uid, err := strconv.ParseUint(allowed, 10, 32)
		if err == nil && cred != nil && cred.Uid == uint32(uid) {
			return nil
		}
	}
	if cred == nil {
		return fmt.Errorf("%w: missing peer credentials", ErrPermissionDeniedErr)
	}
	return fmt.Errorf("%w: peer uid %d is not authorized to ingest events", ErrPermissionDeniedErr, cred.Uid)
}
