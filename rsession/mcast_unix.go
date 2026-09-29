//go:build linux || darwin || freebsd || netbsd || openbsd

package rsession

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// setMulticast sets the hop limit of the multicast c sends, and the
// interface it sends on when ifi is not nil.
func setMulticast(c *net.UDPConn, v6 bool, ttl int, ifi *net.Interface) error {
	rc, err := c.SyscallConn()
	if err != nil {
		return fmt.Errorf("rsession: %w", err)
	}
	var serr error
	err = rc.Control(func(fd uintptr) {
		if v6 {
			serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_MULTICAST_HOPS, ttl)
			if serr == nil && ifi != nil {
				serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_MULTICAST_IF, ifi.Index)
			}
			return
		}
		serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MULTICAST_TTL, ttl)
		if serr == nil && ifi != nil {
			serr = setMulticastIf4(int(fd), ifi)
		}
	})
	if err == nil {
		err = serr
	}
	if err != nil {
		return fmt.Errorf("rsession: multicast socket options: %w", err)
	}
	return nil
}

// setMulticastIf4 selects the IPv4 interface multicast leaves by, by its
// first IPv4 address.
func setMulticastIf4(fd int, ifi *net.Interface) error {
	addrs, err := ifi.Addrs()
	if err != nil {
		return err
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			if ip4 := n.IP.To4(); ip4 != nil {
				return unix.SetsockoptInet4Addr(fd, unix.IPPROTO_IP, unix.IP_MULTICAST_IF, [4]byte(ip4))
			}
		}
	}
	return fmt.Errorf("interface %s has no IPv4 address", ifi.Name)
}
