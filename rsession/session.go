package rsession

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dscsystems/go-iec61850/ethernet"
)

// DefaultPort is the UDP port of the session protocol.
const DefaultPort = 102

// Config configures a Session.
type Config struct {
	// Listen is the local UDP address to receive on, e.g. ":102" or
	// "192.168.1.10:102". Empty with no Groups makes a send-only session.
	Listen string
	// Groups are multicast groups to join for receiving, each "address"
	// or "address:port" (the port defaults to Listen's, else 102). A group
	// socket receives only what is sent to its group, and cannot share a
	// port with Listen: give a session Listen for unicast, Groups for
	// multicast, or both on different ports.
	Groups []string
	// Interface is the network interface to join Groups and send
	// multicast on; empty lets the system choose.
	Interface string
	// Remote is where Send and WriteFrame send, "address:port" (port 102
	// when omitted), unicast or multicast. Empty makes a receive-only
	// session.
	Remote string
	// TTL is the hop limit of multicast sent (1 when 0, which does not
	// leave the local network: routing R-GOOSE needs more).
	TTL int

	// Keys holds the keys: the active one secures what is sent, and every
	// one of them is accepted on receipt. Nil sends unsecured.
	Keys *KeyStore
	// Version is the protocol version sent, 1 or 2 (2 when 0). Both are
	// accepted on receipt. Version 1 cannot carry encryption.
	Version int

	// AllowUnsecured accepts SPDUs that carry no key. By default they are
	// refused: a receiver that holds keys expects its publishers to use
	// them, and one that accepts unsecured traffic can be fed forged
	// messages by anyone on the path.
	AllowUnsecured bool
	// ReplayWindow is how many SPDU numbers below the highest seen from a
	// sender are still accepted, once each (64 when 0, at most 64;
	// negative disables replay protection). It applies to secured SPDUs,
	// whose numbers cannot be forged.
	ReplayWindow int
	// ReplayReset is how long a sender may be silent before its numbering
	// is allowed to start again, as a restarted publisher's does (10 s
	// when 0, negative never). A replay of old SPDUs within it is refused.
	ReplayReset time.Duration

	// OnReject, when set, is told of every SPDU refused, for audit
	// (IEC 62351-14 security events). It is called from the receiving
	// goroutine and must not block.
	OnReject func(Reject)
}

// Reject describes an SPDU a session refused.
type Reject struct {
	From net.Addr
	Err  error // wraps one of the Err* values of this package, or ErrReplay
}

// ErrReplay is a secured SPDU whose number was already accepted, or is too
// old for the replay window.
var ErrReplay = errors.New("rsession: replayed SPDU")

// ErrNotListening is returned by Receive and ReadFrame on a send-only
// session, and ErrNoRemote by Send and WriteFrame on a receive-only one.
var (
	ErrNotListening = errors.New("rsession: session does not receive")
	ErrNoRemote     = errors.New("rsession: session has no remote address")
)

// Stats counts what a session has received.
type Stats struct {
	Accepted, Malformed, UnknownKey, Unauthentic, Unsecured, Replayed uint64
}

// Session sends and receives SPDUs of the IEC 61850-90-5 session protocol
// over UDP: R-GOOSE and R-SV.
//
// A Session is also an ethernet.Interface, so the GOOSE and sampled value
// publishers and subscribers of this module run over it unchanged: a
// frame written is sent as the payload of an SPDU, with the frame's APPID
// and simulation bit in the session header, and an SPDU received is handed
// back as a frame of its EtherType.
//
//	keys, _ := rsession.NewKeyStore(rsession.Key{ID: 1, Material: k,
//		Sig: rsession.SigHMACSHA256_128})
//	s, _ := rsession.Open(rsession.Config{Remote: "239.0.0.1:102", Keys: keys})
//	pub, _ := goose.NewPublisher(s, goose.PublisherConfig{...})
type Session struct {
	cfg    Config
	send   *net.UDPConn
	remote *net.UDPAddr
	recv   []*net.UDPConn
	in     chan datagram
	done   chan struct{}
	once   sync.Once
	wg     sync.WaitGroup

	number atomic.Uint32
	sendMu sync.Mutex

	replayMu sync.Mutex
	replay   map[streamKey]*replayWindow

	frameMu sync.Mutex
	pending []*ethernet.Frame // frames of an SPDU not yet read

	stats struct {
		accepted, malformed, unknownKey, unauthentic, unsecured, replayed atomic.Uint64
	}
}

type datagram struct {
	b    []byte
	from *net.UDPAddr
}

type streamKey struct {
	from  string
	si    SessionID
	keyID uint32
}

// maxStreams bounds the replay state kept: beyond it, the state of
// senders silent longer than the reset time is dropped.
const maxStreams = 4096

// Open opens a session.
func Open(cfg Config) (*Session, error) {
	if cfg.Version == 0 {
		cfg.Version = 2
	}
	if cfg.Version != 1 && cfg.Version != 2 {
		return nil, fmt.Errorf("%w: %d", ErrVersion, cfg.Version)
	}
	if cfg.ReplayWindow == 0 {
		cfg.ReplayWindow = 64
	}
	if cfg.ReplayWindow > 64 {
		cfg.ReplayWindow = 64
	}
	if cfg.ReplayReset == 0 {
		cfg.ReplayReset = 10 * time.Second
	}
	if cfg.TTL == 0 {
		cfg.TTL = 1
	}
	s := &Session{cfg: cfg, done: make(chan struct{}), replay: map[streamKey]*replayWindow{}}
	var ifi *net.Interface
	if cfg.Interface != "" {
		var err error
		if ifi, err = net.InterfaceByName(cfg.Interface); err != nil {
			return nil, fmt.Errorf("rsession: %w", err)
		}
	}

	if cfg.Remote != "" {
		ra, err := resolve(cfg.Remote, DefaultPort)
		if err != nil {
			return nil, err
		}
		s.remote = ra
		network := "udp4"
		if ra.IP.To4() == nil {
			network = "udp6"
		}
		if s.send, err = net.ListenUDP(network, nil); err != nil {
			return nil, fmt.Errorf("rsession: %w", err)
		}
		if ra.IP.IsMulticast() {
			if err := setMulticast(s.send, ra.IP.To4() == nil, cfg.TTL, ifi); err != nil {
				s.send.Close()
				return nil, err
			}
		}
	}

	listenPort := DefaultPort
	if cfg.Listen != "" {
		la, err := resolve(cfg.Listen, DefaultPort)
		if err != nil {
			s.closeSockets()
			return nil, err
		}
		listenPort = la.Port
		c, err := net.ListenUDP("udp", la)
		if err != nil {
			s.closeSockets()
			return nil, fmt.Errorf("rsession: %w", err)
		}
		s.recv = append(s.recv, c)
	}
	for _, g := range cfg.Groups {
		ga, err := resolve(g, listenPort)
		if err != nil {
			s.closeSockets()
			return nil, err
		}
		if !ga.IP.IsMulticast() {
			s.closeSockets()
			return nil, fmt.Errorf("rsession: %s is not a multicast group", g)
		}
		network := "udp4"
		if ga.IP.To4() == nil {
			network = "udp6"
		}
		c, err := net.ListenMulticastUDP(network, ifi, ga)
		if err != nil {
			s.closeSockets()
			return nil, fmt.Errorf("rsession: joining %s: %w", g, err)
		}
		s.recv = append(s.recv, c)
	}
	if len(s.recv) > 0 {
		s.in = make(chan datagram, 64)
		for _, c := range s.recv {
			s.wg.Add(1)
			go s.read(c)
		}
	}
	return s, nil
}

func resolve(addr string, defPort int) (*net.UDPAddr, error) {
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, strconv.Itoa(defPort))
	}
	a, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("rsession: %w", err)
	}
	return a, nil
}

// LocalAddr returns the address the session receives on (the first, when
// it listens on several), nil when it does not receive.
func (s *Session) LocalAddr() net.Addr {
	if len(s.recv) == 0 {
		return nil
	}
	return s.recv[0].LocalAddr()
}

// read feeds the datagrams of one socket to the session.
func (s *Session) read(c *net.UDPConn) {
	defer s.wg.Done()
	buf := make([]byte, 65536)
	for {
		n, from, err := c.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-s.done:
				return
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		d := datagram{b: append([]byte(nil), buf[:n]...), from: from}
		select {
		case s.in <- d:
		case <-s.done:
			return
		}
	}
}

// Send sends one SPDU carrying payloads, secured with the active key of
// Config.Keys; unsecured when the session has no key store. A session
// with a key store and no active key sends nothing: ErrNoActiveKey.
func (s *Session) Send(si SessionID, payloads ...Payload) error {
	if s.send == nil {
		return ErrNoRemote
	}
	var key *Key
	if s.cfg.Keys != nil {
		if key = s.cfg.Keys.activeKey(); key == nil {
			return ErrNoActiveKey
		}
	}
	// Numbers are taken and sent in order, so a receiver's replay window
	// sees them increase.
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	spdu := &SPDU{SI: si, Number: s.number.Load(), Version: uint16(s.cfg.Version), Payloads: payloads}
	b, err := Marshal(spdu, key, nil)
	if err != nil {
		return err
	}
	s.number.Add(1)
	_, err = s.send.WriteToUDP(b, s.remote)
	return err
}

// Receive returns the next SPDU that passes the session's checks, and its
// sender. SPDUs that fail are counted in Stats and reported to
// Config.OnReject, and Receive carries on. It returns net.ErrClosed once
// the session is closed.
func (s *Session) Receive() (*SPDU, net.Addr, error) {
	if s.in == nil {
		return nil, nil, ErrNotListening
	}
	for {
		var d datagram
		select {
		case d = <-s.in:
		case <-s.done:
			return nil, nil, net.ErrClosed
		}
		spdu, err := s.check(d)
		if err != nil {
			if s.cfg.OnReject != nil {
				s.cfg.OnReject(Reject{From: d.from, Err: err})
			}
			continue
		}
		s.stats.accepted.Add(1)
		return spdu, d.from, nil
	}
}

// check decodes and verifies one datagram against the session's keys and
// policy.
func (s *Session) check(d datagram) (*SPDU, error) {
	spdu, err := Unmarshal(d.b, s.cfg.Keys)
	switch {
	case err == nil:
	case errors.Is(err, ErrUnknownKey):
		s.stats.unknownKey.Add(1)
		return nil, err
	case errors.Is(err, ErrAuthentication), errors.Is(err, ErrAlgorithm):
		s.stats.unauthentic.Add(1)
		return nil, err
	default:
		s.stats.malformed.Add(1)
		return nil, err
	}
	if spdu.KeyID == 0 {
		if !s.cfg.AllowUnsecured {
			s.stats.unsecured.Add(1)
			return nil, ErrUnsecured
		}
		return spdu, nil
	}
	if s.cfg.ReplayWindow > 0 && !s.fresh(d.from, spdu) {
		s.stats.replayed.Add(1)
		return nil, fmt.Errorf("%w: number %d from %v", ErrReplay, spdu.Number, d.from)
	}
	return spdu, nil
}

func (s *Session) fresh(from *net.UDPAddr, spdu *SPDU) bool {
	k := streamKey{from: from.String(), si: spdu.SI, keyID: spdu.KeyID}
	now := time.Now()
	s.replayMu.Lock()
	defer s.replayMu.Unlock()
	w, ok := s.replay[k]
	if !ok {
		if len(s.replay) >= maxStreams {
			for key, old := range s.replay {
				if now.Sub(old.last) > s.cfg.ReplayReset {
					delete(s.replay, key)
				}
			}
		}
		w = &replayWindow{}
		s.replay[k] = w
	}
	return w.accept(spdu.Number, now, s.cfg.ReplayWindow, s.cfg.ReplayReset)
}

// Stats returns the session's receive counters.
func (s *Session) Stats() Stats {
	return Stats{
		Accepted:    s.stats.accepted.Load(),
		Malformed:   s.stats.malformed.Load(),
		UnknownKey:  s.stats.unknownKey.Load(),
		Unauthentic: s.stats.unauthentic.Load(),
		Unsecured:   s.stats.unsecured.Load(),
		Replayed:    s.stats.replayed.Load(),
	}
}

// Close closes the session's sockets and unblocks Receive and ReadFrame.
func (s *Session) Close() error {
	s.once.Do(func() {
		close(s.done)
		s.closeSockets()
	})
	s.wg.Wait()
	return nil
}

func (s *Session) closeSockets() {
	if s.send != nil {
		s.send.Close()
	}
	for _, c := range s.recv {
		c.Close()
	}
}

// Frame header of a GOOSE or SV APDU on Ethernet: APPID, length, two
// reserved words, the first of which carries the simulation bit.
const (
	l2Header = 8
	simBit   = 0x8000
)

// WriteFrame sends a GOOSE or SV frame as an SPDU: the APDU without its
// layer-2 header is the payload, and the APPID and the simulation bit of
// Reserved 1 go in the session's payload element. The addresses and VLAN
// of the frame are not used; the session's remote address is.
func (s *Session) WriteFrame(f *ethernet.Frame) error {
	var si SessionID
	var pt PayloadType
	switch f.EtherType {
	case ethernet.EtherTypeGOOSE:
		si, pt = SIGOOSE, PayloadGOOSE
	case ethernet.EtherTypeSV:
		si, pt = SISV, PayloadSV
	default:
		return fmt.Errorf("rsession: EtherType %#04x is neither GOOSE nor SV", f.EtherType)
	}
	p := f.Payload
	if len(p) < l2Header {
		return fmt.Errorf("%w: frame payload of %d octets", ErrMalformed, len(p))
	}
	length := int(p[2])<<8 | int(p[3])
	if length < l2Header || length > len(p) {
		length = len(p)
	}
	return s.Send(si, Payload{
		Type:       pt,
		Simulation: (int(p[4])<<8|int(p[5]))&simBit != 0,
		AppID:      uint16(p[0])<<8 | uint16(p[1]),
		APDU:       p[l2Header:length],
	})
}

// ReadFrame returns the next GOOSE or SV payload received, as a frame of
// its EtherType with the layer-2 header rebuilt from the session's
// payload element. Payloads of other types are skipped, and so are SPDUs
// the session refuses (see Receive).
func (s *Session) ReadFrame() (*ethernet.Frame, error) {
	for {
		s.frameMu.Lock()
		if len(s.pending) > 0 {
			f := s.pending[0]
			s.pending = s.pending[1:]
			s.frameMu.Unlock()
			return f, nil
		}
		s.frameMu.Unlock()
		spdu, _, err := s.Receive()
		if err != nil {
			return nil, err
		}
		var frames []*ethernet.Frame
		for _, p := range spdu.Payloads {
			var et uint16
			switch p.Type {
			case PayloadGOOSE:
				et = ethernet.EtherTypeGOOSE
			case PayloadSV:
				et = ethernet.EtherTypeSV
			default:
				continue
			}
			length := l2Header + len(p.APDU)
			if length > 0xFFFF {
				continue
			}
			var r1 uint16
			if p.Simulation {
				r1 = simBit
			}
			b := make([]byte, 0, length)
			b = append(b, byte(p.AppID>>8), byte(p.AppID), byte(length>>8), byte(length),
				byte(r1>>8), byte(r1), 0, 0)
			b = append(b, p.APDU...)
			frames = append(frames, &ethernet.Frame{EtherType: et, Payload: b})
		}
		if len(frames) == 0 {
			continue
		}
		s.frameMu.Lock()
		s.pending = append(s.pending, frames[1:]...)
		s.frameMu.Unlock()
		return frames[0], nil
	}
}

var _ ethernet.Interface = (*Session)(nil)
var _ io.Closer = (*Session)(nil)
