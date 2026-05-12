//go:build !linux

package ipc

import "net"

func authorizeIngest(net.Conn) error {
	return nil
}
