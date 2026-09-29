//go:build !(linux || darwin || freebsd || netbsd || openbsd)

package rsession

import (
	"errors"
	"net"
)

// setMulticast is not implemented on this platform beyond the defaults: a
// hop limit of 1 and the system's choice of interface.
func setMulticast(c *net.UDPConn, v6 bool, ttl int, ifi *net.Interface) error {
	if ttl != 1 || ifi != nil {
		return errors.New("rsession: multicast TTL and interface are not settable on this platform")
	}
	return nil
}
