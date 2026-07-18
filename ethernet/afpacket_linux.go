//go:build linux

package ethernet

import (
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

// afPacket is the Linux AF_PACKET SOCK_RAW backend.
type afPacket struct {
	fd     int
	name   string
	filter []uint16
	closed atomic.Bool
}

// Open binds a raw AF_PACKET socket to the named interface. With no
// etherTypes every protocol is delivered; with one or more, reception is
// restricted to those EtherTypes (compared after VLAN decapsulation, so
// tagged frames are matched on their inner protocol). Requires
// CAP_NET_RAW or root.
func Open(ifname string, etherTypes ...uint16) (Interface, error) {
	ifi, err := net.InterfaceByName(ifname)
	if err != nil {
		return nil, fmt.Errorf("ethernet: %w", err)
	}
	// A single requested EtherType is also filtered in the kernel via the
	// bind protocol; otherwise everything is received and filtered here.
	proto := uint16(unix.ETH_P_ALL)
	if len(etherTypes) == 1 {
		proto = etherTypes[0]
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(proto)))
	if err != nil {
		return nil, fmt.Errorf("ethernet: socket: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(proto), Ifindex: ifi.Index}); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("ethernet: bind %s: %w", ifname, err)
	}
	// A receive timeout lets ReadFrame poll the closed flag, so Close
	// unblocks a concurrent reader.
	tv := unix.NsecToTimeval(int64(200 * time.Millisecond))
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("ethernet: SO_RCVTIMEO: %w", err)
	}
	p := &afPacket{fd: fd, name: ifname}
	if len(etherTypes) > 0 {
		p.filter = append([]uint16(nil), etherTypes...)
	}
	return p, nil
}

func (p *afPacket) WriteFrame(f *Frame) error {
	if p.closed.Load() {
		return net.ErrClosed
	}
	if _, err := unix.Write(p.fd, f.Marshal()); err != nil {
		return fmt.Errorf("ethernet: write %s: %w", p.name, err)
	}
	return nil
}

func (p *afPacket) ReadFrame() (*Frame, error) {
	for {
		if p.closed.Load() {
			return nil, net.ErrClosed
		}
		buf := make([]byte, 9216)
		n, _, err := unix.Recvfrom(p.fd, buf, 0)
		switch err {
		case nil:
		case unix.EAGAIN, unix.EINTR:
			continue
		default:
			if p.closed.Load() {
				return nil, net.ErrClosed
			}
			return nil, fmt.Errorf("ethernet: read %s: %w", p.name, err)
		}
		f, err := ParseFrame(buf[:n])
		if err != nil {
			continue // runt frame
		}
		if p.filter != nil && !p.wants(f.EtherType) {
			continue
		}
		return f, nil
	}
}

func (p *afPacket) wants(et uint16) bool {
	for _, w := range p.filter {
		if w == et {
			return true
		}
	}
	return false
}

func (p *afPacket) Close() error {
	if p.closed.Swap(true) {
		return nil
	}
	return unix.Close(p.fd)
}
