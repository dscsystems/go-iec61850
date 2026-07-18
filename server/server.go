// Package server is the high-level IEC 61850 ACSI server. It serves a
// data model (built from SCL or programmatically) over MMS to clients,
// with hooks for write access and control, and an atomic Update API for
// the process side to drive value changes.
package server

import (
	"crypto/tls"
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

	selMu      sync.Mutex
	selections map[model.ObjectReference]*selection

	lnMu sync.Mutex
	lns  net.Listener

	connMu sync.Mutex
	conns  map[*mms.ServerConn]struct{}
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
	sc, err := mms.AcceptConn(raw)
	if err != nil {
		s.log.Warn("server: association setup failed", "peer", raw.RemoteAddr(), "err", err)
		return
	}
	s.connMu.Lock()
	s.conns[sc] = struct{}{}
	s.connMu.Unlock()
	defer func() {
		s.connMu.Lock()
		delete(s.conns, sc)
		s.connMu.Unlock()
		s.reports.disableConn(sc)
		s.releaseSelections(sc)
		sc.Close() // closes the transport and the unconfirmed writer
	}()

	s.log.Info("server: association established", "peer", sc.Peer)
	if err := sc.Serve(&handler{s: s}); err != nil && err != net.ErrClosed {
		s.log.Debug("server: association ended", "peer", sc.Peer, "err", err)
	}
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
