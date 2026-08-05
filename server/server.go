// Package server is the high-level IEC 61850 ACSI server. It serves a
// data model (built from SCL or programmatically) over MMS to clients,
// with hooks for write access and control, and an atomic Update API for
// the process side to drive value changes.
package server

import (
	"crypto/tls"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"sync"

	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/model"
)

// Server serves one IED data model over MMS.
type Server struct {
	model *model.Model
	log   *slog.Logger
	tls   *tls.Config

	mu       sync.RWMutex // guards model values
	writeH   func(*model.DataAttribute, *mms.Value) error
	identity Identity
	reports  *reportManager

	ctlMu    sync.RWMutex
	controls map[model.ObjectReference]ControlHandler

	files *fileStore

	numOfSG uint8
	sgs     map[string]*sgManager // by logical device name

	// reportBufSize is the default buffered-report depth; see
	// WithReportBufferSize.
	reportBufSize int

	selMu      sync.Mutex
	selections map[model.ObjectReference]*selection

	lnMu sync.Mutex
	lns  net.Listener

	connMu   sync.Mutex
	conns    map[*mms.ServerConn]struct{}
	open     int // slots taken: established associations and those setting up
	maxConns int
	connH    func(ConnectionEvent)
}

// ConnectionState is what happened to a client connection.
type ConnectionState uint8

const (
	// ConnectionOpened is an association that completed its handshake.
	ConnectionOpened ConnectionState = iota
	// ConnectionClosed is an association that has ended, by either side.
	ConnectionClosed
	// ConnectionRefused is a connection dropped without an association
	// because the server was already at its maximum.
	ConnectionRefused
)

func (c ConnectionState) String() string {
	switch c {
	case ConnectionOpened:
		return "opened"
	case ConnectionClosed:
		return "closed"
	case ConnectionRefused:
		return "refused"
	}
	return fmt.Sprintf("ConnectionState(%d)", uint8(c))
}

// ConnectionEvent describes a change in the server's client connections.
type ConnectionEvent struct {
	// Peer is the client's transport address in text.
	Peer string
	// Addr is the same address as a net.Addr, so a *net.TCPAddr yields the
	// client's IP on its own. It is set for every event, a refused
	// connection included — that one has no association to read it from.
	Addr net.Addr
	// State says what happened to it.
	State ConnectionState
	// Open is the number of connections held just after the event,
	// counting associations still setting up.
	Open int
	// Conn is the association. It is nil for a refused connection, which
	// never became one. Closing it disconnects the client.
	Conn *mms.ServerConn
}

// Identity is returned by the Identify service.
type Identity struct {
	Vendor, Model, Revision string
}

// Option configures a Server.
type Option func(*Server)

// WithLogger sets the diagnostic logger.
func WithLogger(l *slog.Logger) Option { return func(s *Server) { s.log = l } }

// WithTLS enables TLS per IEC 62351-3.
func WithTLS(cfg *tls.Config) Option { return func(s *Server) { s.tls = cfg } }

// WithIdentity sets the Identify response.
func WithIdentity(id Identity) Option { return func(s *Server) { s.identity = id } }

// WithFileStore enables MMS file services backed by fsys (for example
// os.DirFS("/var/comtrade")).
func WithFileStore(fsys fs.FS) Option {
	return func(s *Server) { s.files = newFileStore(fsys) }
}

// WithMaxConnections caps the number of client connections served at once.
// A client arriving at the cap is dropped at the transport, before any
// association is set up, and reported as ConnectionRefused. Zero, the
// default, is unlimited.
func WithMaxConnections(n int) Option {
	return func(s *Server) { s.maxConns = n }
}

// WithReportBufferSize sets how many reports a buffered control block
// retains while no subscriber is enabled. It is the default for the blocks
// that do not set a MaxQueueSize of their own; zero keeps the library's
// default of 256.
func WithReportBufferSize(n int) Option {
	return func(s *Server) { s.reportBufSize = n }
}

// WithSettingGroups enables setting-group handling with numOfSG groups for
// every logical device that has SG/SE setting attributes. An SGCB is
// materialised into each such device's LLN0.
func WithSettingGroups(numOfSG uint8) Option {
	return func(s *Server) { s.numOfSG = numOfSG }
}

// New returns a server serving m.
func New(m *model.Model, opts ...Option) *Server {
	s := &Server{
		model:    m,
		log:      slog.New(slog.DiscardHandler),
		identity: Identity{Vendor: "go-iec61850", Model: m.Name, Revision: "0.1"},
		conns:    make(map[*mms.ServerConn]struct{}),
	}
	for _, opt := range opts {
		opt(s)
	}
	// Setting groups must be materialised before the report engine so the
	// SGCB appears in the model.
	if s.numOfSG > 0 {
		s.sgs = make(map[string]*sgManager)
		for _, ld := range m.Devices {
			if mgr := newSGManager(ld, s.numOfSG); mgr != nil {
				s.sgs[ld.Name] = mgr
			}
		}
	}
	// Materialise report control blocks into the model and prepare the
	// report engine.
	s.reports = newReportManager(s)
	return s
}

// OnWrite registers a handler consulted before applying a client write.
// Returning a non-nil error (for example server.ErrAccessDenied) rejects
// the write with the corresponding MMS DataAccessError.
func (s *Server) OnWrite(h func(da *model.DataAttribute, v *mms.Value) error) {
	s.writeH = h
}

// ListenAndServe binds to addr and serves associations until the listener
// is closed.
func (s *Server) ListenAndServe(addr string) error {
	var ln net.Listener
	var err error
	if s.tls != nil {
		ln, err = tls.Listen("tcp", addr, s.tls)
	} else {
		ln, err = net.Listen("tcp", addr)
	}
	if err != nil {
		return err
	}
	return s.Serve(ln)
}

// Serve accepts associations on ln until it is closed.
func (s *Server) Serve(ln net.Listener) error {
	s.lnMu.Lock()
	s.lns = ln
	s.lnMu.Unlock()
	for {
		raw, err := ln.Accept()
		if err != nil {
			return err
		}
		go s.serveConn(raw)
	}
}

func (s *Server) serveConn(raw net.Conn) {
	defer raw.Close()
	addr := raw.RemoteAddr()
	peer := addr.String()

	// The slot is taken before the handshake, so a flood of half-open
	// connections cannot outrun the limit.
	open, ok := s.takeSlot()
	if !ok {
		s.log.Warn("server: connection refused", "peer", peer, "max", s.maxConns)
		s.notifyConn(ConnectionEvent{Peer: peer, Addr: addr, State: ConnectionRefused, Open: open})
		return
	}

	sc, err := mms.AcceptConn(raw)
	if err != nil {
		s.log.Warn("server: association setup failed", "peer", peer, "err", err)
		s.releaseSlot()
		return
	}
	s.connMu.Lock()
	s.conns[sc] = struct{}{}
	open = s.open
	s.connMu.Unlock()
	defer func() {
		s.connMu.Lock()
		delete(s.conns, sc)
		s.connMu.Unlock()
		open := s.releaseSlot()
		s.reports.disableConn(sc)
		s.releaseSelections(sc)
		sc.Close() // closes the transport and the unconfirmed writer
		s.notifyConn(ConnectionEvent{Peer: peer, Addr: addr, State: ConnectionClosed, Open: open, Conn: sc})
	}()

	s.log.Info("server: association established", "peer", sc.Peer)
	s.notifyConn(ConnectionEvent{Peer: peer, Addr: addr, State: ConnectionOpened, Open: open, Conn: sc})
	if err := sc.Serve(&handler{s: s}); err != nil && err != net.ErrClosed {
		s.log.Debug("server: association ended", "peer", sc.Peer, "err", err)
	}
}

// OnConnection registers a handler called when a client connection opens,
// closes, or is refused for exceeding the maximum. It runs on the
// connection's own goroutine — the close event before that goroutine
// finishes — so it must not block, and it must not call back into the
// server's Update.
//
// Registering a second handler replaces the first. Register before Serve,
// or the first clients may connect unobserved.
func (s *Server) OnConnection(h func(ConnectionEvent)) {
	s.connMu.Lock()
	s.connH = h
	s.connMu.Unlock()
}

func (s *Server) notifyConn(ev ConnectionEvent) {
	s.connMu.Lock()
	h := s.connH
	s.connMu.Unlock()
	if h != nil {
		h(ev)
	}
}

// OpenConnections returns how many client connections the server is
// holding, counting associations still setting up.
func (s *Server) OpenConnections() int {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	return s.open
}

// MaxConnections returns the configured limit, or 0 when unlimited.
func (s *Server) MaxConnections() int {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	return s.maxConns
}

// takeSlot reserves one connection slot, reporting the resulting count and
// whether the limit allowed it.
func (s *Server) takeSlot() (int, bool) {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	if s.maxConns > 0 && s.open >= s.maxConns {
		return s.open, false
	}
	s.open++
	return s.open, true
}

func (s *Server) releaseSlot() int {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	if s.open > 0 {
		s.open--
	}
	return s.open
}

// Close stops accepting and closes open associations.
func (s *Server) Close() error {
	s.lnMu.Lock()
	if s.lns != nil {
		s.lns.Close()
	}
	s.lnMu.Unlock()
	s.connMu.Lock()
	for sc := range s.conns {
		sc.Close()
	}
	s.connMu.Unlock()
	return nil
}

// Update applies a batch of value changes atomically with respect to
// client reads. The transaction is the process side's entry point for
// pushing new measurement and status values.
func (s *Server) Update(fn func(tx *Tx)) {
	s.mu.Lock()
	tx := &Tx{s: s, changed: make(map[model.ObjectReference]bool)}
	fn(tx)
	s.reports.onUpdate(tx.changed)
	s.mu.Unlock()
}

// Read returns a snapshot value for a reference and FC (server-local, no
// network), useful for tests and the process side. It takes the model
// lock, so it must NOT be called from within an Update callback (which
// already holds the lock and would deadlock) — use Tx.Get there instead.
func (s *Server) Read(ref model.ObjectReference, fc model.FC) *mms.Value {
	s.mu.RLock()
	defer s.mu.RUnlock()
	da := s.model.Attribute(ref, fc)
	if da == nil {
		return nil
	}
	return daValue(da)
}
