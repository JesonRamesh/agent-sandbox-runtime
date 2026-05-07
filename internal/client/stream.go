package client

import (
	"encoding/binary"
	"fmt"
	"io"
)

// WriteFrame writes a single length-prefixed frame to w. Mirrors P2's
// `WriteFrame` byte-for-byte: [4-byte BE uint32 length][body bytes].
//
// Returns ErrFrameOversize if body would exceed MaxFrameBytes.
func WriteFrame(w io.Writer, body []byte) error {
	if len(body) > MaxFrameBytes {
		return ErrFrameOversize
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(body))) //nolint:gosec // bounded by MaxFrameBytes check above
	if _, err := w.Write(hdr[:]); err != nil {
		return fmt.Errorf("write frame header: %w", err)
	}
	if _, err := w.Write(body); err != nil {
		return fmt.Errorf("write frame body: %w", err)
	}
	return nil
}

// ReadFrame reads a single length-prefixed frame from r. Returns the body
// (without the length prefix). On a clean connection close before any header
// bytes are read, returns io.EOF.
//
// Frames whose declared length exceeds MaxFrameBytes are rejected with
// ErrFrameOversize and the caller is expected to close the connection.
func ReadFrame(r io.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		// io.EOF here means the peer closed before sending any header bytes;
		// surface it directly so streaming readers can use it as the terminator.
		if err == io.EOF {
			return nil, io.EOF
		}
		if err == io.ErrUnexpectedEOF {
			return nil, fmt.Errorf("short read on frame header: %w", err)
		}
		return nil, fmt.Errorf("read frame header: %w", err)
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > MaxFrameBytes {
		return nil, ErrFrameOversize
	}
	if n == 0 {
		return []byte{}, nil
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, fmt.Errorf("read frame body: %w", err)
	}
	return body, nil
}
