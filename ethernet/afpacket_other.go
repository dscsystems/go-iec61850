//go:build !linux

package ethernet

import "errors"

// Open is unavailable on this platform: the AF_PACKET backend is
// Linux-only. Non-Linux platforms need a capture-library backend.
func Open(ifname string, etherTypes ...uint16) (Interface, error) {
	return nil, errors.New("ethernet: raw ethernet only supported on linux (build with pcap tag for other platforms)")
}
