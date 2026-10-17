//go:build !linux

package ethernet

import "errors"

// Open is unavailable on this platform: the AF_PACKET backend is
// Linux-only, and no capture-library backend is implemented.
func Open(ifname string, etherTypes ...uint16) (Interface, error) {
	return nil, errors.New("ethernet: raw Ethernet is only supported on Linux (AF_PACKET); no capture backend exists for this platform")
}
