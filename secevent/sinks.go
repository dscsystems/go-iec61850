package secevent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"slices"
	"sync"
	"sync/atomic"
)

// syncSink marks a sink the Dispatcher calls from Submit itself.
type syncSink struct{ Sink }

// SyncSink makes a Dispatcher deliver to s synchronously, from the
// goroutine that submits the event. Delivery then blocks the protocol for
// as long as s takes: it is meant for tests, where it makes the order and
// the timing of events deterministic.
func SyncSink(s Sink) Sink { return syncSink{s} }

// ChannelSinkHandle is a sink sending to a channel. It never blocks: when
// the channel is full the event is counted in Dropped and lost.
type ChannelSinkHandle struct {
	ch      chan<- Event
	dropped atomic.Uint64
}

// ChannelSink returns a sink sending events to ch without blocking.
func ChannelSink(ch chan<- Event) *ChannelSinkHandle { return &ChannelSinkHandle{ch: ch} }

// Deliver sends e, or counts it as dropped when ch is full.
func (c *ChannelSinkHandle) Deliver(e Event) {
	select {
	case c.ch <- e:
	default:
		c.dropped.Add(1)
	}
}

// Dropped is how many events did not fit in the channel.
func (c *ChannelSinkHandle) Dropped() uint64 { return c.dropped.Load() }

// SlogLevel maps a severity to a slog level: Critical is Error+4, Alert is
// Error, Warning is Warn, Notice and Info are Info.
func SlogLevel(s Severity) slog.Level {
	switch s {
	case Critical:
		return slog.LevelError + 4
	case Alert:
		return slog.LevelError
	case Warning:
		return slog.LevelWarn
	}
	return slog.LevelInfo
}

// SlogSink logs each event on l, with the message "cyber: <kind>" and the
// event's set fields as attributes.
func SlogSink(l *slog.Logger) Sink {
	return SinkFunc(func(e Event) {
		l.LogAttrs(context.Background(), SlogLevel(e.Severity), "cyber: "+string(e.Kind), e.attrs()...)
	})
}

func (e Event) attrs() []slog.Attr {
	a := []slog.Attr{
		slog.String("category", string(e.Category)),
		slog.String("severity", e.Severity.String()),
	}
	str := func(k, v string) {
		if v != "" {
			a = append(a, slog.String(k, v))
		}
	}
	str("action", string(e.Action))
	str("protocol", e.Protocol)
	str("role", e.Role)
	if e.SessionID != 0 {
		a = append(a, slog.Uint64("session", e.SessionID))
	}
	if e.Peer.RemoteAddr.IsValid() {
		a = append(a, slog.String("peer", e.Peer.RemoteAddr.String()))
	}
	if len(e.Peer.MAC) > 0 {
		a = append(a, slog.String("peer_mac", e.Peer.MAC.String()))
	}
	if e.Stream != nil {
		str("stream", e.Stream.ControlRef)
		if len(e.Stream.SrcMAC) > 0 {
			a = append(a, slog.String("src_mac", e.Stream.SrcMAC.String()))
		}
		a = append(a, slog.Int("appid", int(e.Stream.AppID)))
	}
	str("stage", e.Stage)
	if e.Fields&HasService != 0 {
		a = append(a, slog.Int("service", e.Service))
	}
	str("ref", e.ObjectRef)
	if e.Fields&HasAccessError != 0 {
		a = append(a, slog.Int("access_error", e.AccessError))
	}
	if e.Fields&HasAddCause != 0 {
		a = append(a, slog.Int("add_cause", e.AddCause))
	}
	if e.Session != nil {
		a = append(a, slog.String("reason", e.Session.Reason), slog.Duration("duration", e.Session.Duration),
			slog.Uint64("requests", e.Session.Requests))
	}
	if e.Count > 1 {
		a = append(a, slog.Int("count", e.Count))
	}
	str("detail", e.Detail)
	if e.Err != nil {
		a = append(a, slog.String("err", e.Err.Error()))
	}
	str("technique", e.Technique)
	str("iec62351_14", e.Std62351)
	return a
}

// JSONLinesSink writes each event to w as one JSON object per line (see
// Event.MarshalJSON), one Write per line. A failed write loses that event
// only: the next one is written again.
func JSONLinesSink(w io.Writer) Sink {
	var mu sync.Mutex
	return SinkFunc(func(e Event) {
		b, err := json.Marshal(e)
		if err != nil {
			return
		}
		b = append(b, '\n')
		mu.Lock()
		defer mu.Unlock()
		w.Write(b)
	})
}

// MultiSink delivers every event to each of sinks in turn.
func MultiSink(sinks ...Sink) Sink {
	sinks = slices.DeleteFunc(slices.Clone(sinks), func(s Sink) bool { return s == nil })
	return SinkFunc(func(e Event) {
		for _, s := range sinks {
			s.Deliver(e)
		}
	})
}

// FilterSink passes on to s the events of at least severity min and, when
// categories are given, of one of them.
func FilterSink(min Severity, s Sink, categories ...Category) Sink {
	return SinkFunc(func(e Event) {
		if e.Severity < min {
			return
		}
		if len(categories) > 0 && !slices.Contains(categories, e.Category) {
			return
		}
		s.Deliver(e)
	})
}

// Fingerprint is the SHA-256 of a DER certificate, as lower-case hex.
func Fingerprint(der []byte) string {
	if len(der) == 0 {
		return ""
	}
	h := sha256.Sum256(der)
	return hex.EncodeToString(h[:])
}
