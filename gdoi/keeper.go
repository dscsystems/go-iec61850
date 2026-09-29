package gdoi

import (
	"context"
	"sync"
	"time"

	"github.com/dscsystems/go-iec61850/rsession"
)

// EventKind is what a Member reports.
type EventKind int

const (
	// Registered: a registration completed.
	Registered EventKind = iota
	// Installed: a TEK was added to the key store; Active says whether it
	// became the key sent with.
	Installed
	// Removed: a TEK expired, or the key server no longer lists it.
	Removed
	// Skipped: a TEK uses algorithms the session layer does not implement.
	Skipped
	// Failed: a registration failed; the keys already installed stay
	// until they expire, and the member retries.
	Failed
)

func (k EventKind) String() string {
	return [...]string{"registered", "installed", "removed", "skipped", "failed"}[k]
}

// Event reports a change a Member made, or a failure.
type Event struct {
	Kind   EventKind
	SPI    uint32
	Active bool
	Err    error
}

// Member keeps the keys of one group current in an rsession.KeyStore: it
// registers with the key server, installs each TEK when its activation
// delay has passed, makes the most recently activated one the key a
// publisher sends with, removes keys when they expire or when the key
// server stops listing them, and registers again before they run out.
//
// This member re-registers rather than taking GROUPKEY-PUSH rekeys, so a
// key server distributing the next key with an activation delay reaches
// it at its next registration: Refresh has to be shorter than the time
// the key server gives a new key before it is used.
type Member struct {
	cfg   MemberConfig
	group GroupID
	store *rsession.KeyStore

	// Refresh is the longest time between registrations (5 min when 0).
	Refresh time.Duration
	// OnEvent is told of each change and failure. It must not block.
	OnEvent func(Event)

	mu   sync.Mutex
	keys map[uint32]*installedKey
}

type installedKey struct {
	activates, expires time.Time
	added, active      bool
	timers             []*time.Timer
}

// NewMember returns a member keeping group's keys in store.
func NewMember(cfg MemberConfig, group GroupID, store *rsession.KeyStore) *Member {
	return &Member{cfg: cfg, group: group, store: store, keys: map[uint32]*installedKey{}}
}

func (m *Member) event(e Event) {
	if m.OnEvent != nil {
		m.OnEvent(e)
	}
}

// Run registers and keeps registering until ctx is done. When it returns,
// the keys it installed are removed from the store: a member that stops
// following the key server does not keep using its keys.
func (m *Member) Run(ctx context.Context) error {
	defer m.removeAll()
	refresh := m.Refresh
	if refresh <= 0 {
		refresh = 5 * time.Minute
	}
	backoff := time.Second
	for {
		reg, err := Register(ctx, m.cfg, m.group)
		wait := backoff
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			m.event(Event{Kind: Failed, Err: err})
			backoff = min(2*backoff, min(refresh, time.Minute))
		} else {
			backoff = time.Second
			m.event(Event{Kind: Registered})
			m.Install(reg)
			wait = nextRegistration(reg, refresh)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
	}
}

// nextRegistration is when to register again: after refresh, or once a
// TEK has 10% of its lifetime left, whichever comes first.
func nextRegistration(reg *Registration, refresh time.Duration) time.Duration {
	wait := refresh
	for _, t := range reg.TEKs {
		if t.Lifetime > 0 {
			wait = min(wait, max(time.Second, t.Lifetime*9/10))
		}
	}
	return wait
}

// Install puts a registration's TEKs in the store, as Run does after each
// registration: keys the registration no longer lists are removed, new
// ones are added when they activate and removed when they expire.
func (m *Member) Install(reg *Registration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	listed := map[uint32]bool{}
	for i := range reg.TEKs {
		t := &reg.TEKs[i]
		listed[t.SPI] = true
		rk, err := t.RSessionKey()
		if err != nil {
			m.event(Event{Kind: Skipped, SPI: t.SPI, Err: err})
			continue
		}
		ik, known := m.keys[t.SPI]
		if !known {
			ik = &installedKey{activates: reg.Received.Add(t.ActivationDelay)}
			m.keys[t.SPI] = ik
			spi := t.SPI
			ik.timers = append(ik.timers, time.AfterFunc(time.Until(ik.activates), func() { m.activate(spi, rk) }))
		}
		// A later registration's lifetime replaces the earlier one.
		for _, tm := range ik.timers[1:] {
			tm.Stop()
		}
		ik.timers = ik.timers[:1]
		ik.expires = time.Time{}
		if t.Lifetime > 0 {
			ik.expires = reg.Received.Add(t.Lifetime)
			spi := t.SPI
			ik.timers = append(ik.timers, time.AfterFunc(time.Until(ik.expires), func() { m.remove(spi) }))
		}
	}
	for spi := range m.keys {
		if !listed[spi] {
			m.removeLocked(spi)
		}
	}
}

func (m *Member) activate(spi uint32, k rsession.Key) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ik, ok := m.keys[spi]
	if !ok || ik.added {
		return
	}
	if err := m.store.Add(k); err != nil {
		m.event(Event{Kind: Skipped, SPI: spi, Err: err})
		return
	}
	ik.added = true
	active := m.chooseActiveLocked()
	m.event(Event{Kind: Installed, SPI: spi, Active: active == spi})
}

// chooseActiveLocked makes the most recently activated key the one sent
// with, the longest-lived on a tie, and returns its SPI.
func (m *Member) chooseActiveLocked() uint32 {
	var best uint32
	var bk *installedKey
	for spi, ik := range m.keys {
		if !ik.added {
			continue
		}
		if bk == nil || ik.activates.After(bk.activates) ||
			ik.activates.Equal(bk.activates) && laterExpiry(ik.expires, bk.expires) {
			best, bk = spi, ik
		}
	}
	for spi, ik := range m.keys {
		ik.active = spi == best && bk != nil
	}
	if bk != nil {
		m.store.SetActive(best)
	}
	return best
}

func laterExpiry(a, b time.Time) bool {
	if a.IsZero() {
		return !b.IsZero()
	}
	return !b.IsZero() && a.After(b)
}

func (m *Member) remove(spi uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.removeLocked(spi)
}

func (m *Member) removeLocked(spi uint32) {
	ik, ok := m.keys[spi]
	if !ok {
		return
	}
	for _, t := range ik.timers {
		t.Stop()
	}
	delete(m.keys, spi)
	if ik.added {
		m.store.Remove(spi)
		m.event(Event{Kind: Removed, SPI: spi})
		if ik.active {
			m.chooseActiveLocked()
		}
	}
}

func (m *Member) removeAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for spi := range m.keys {
		m.removeLocked(spi)
	}
}
