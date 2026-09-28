package server

import (
	"bytes"
	"github.com/dscsystems/go-iec61850/model"
	"testing"
)

// An EntryID identifies a report uniquely within the server, not within one
// control block (IEC 61850-7-2). Two buffered blocks must never hand out
// the same identifier, or a client resyncing on EntryID cannot tell which
// block an entry came from.
func TestEntryIDIsUniquePerServer(t *testing.T) {
	rm := &reportManager{}
	seen := map[string]bool{}
	for range 1000 {
		id := string(rm.nextEntryID())
		if len(id) != 8 {
			t.Fatalf("EntryID %x is not 8 octets", id)
		}
		if seen[id] {
			t.Fatalf("EntryID %x handed out twice", id)
		}
		seen[id] = true
	}
	// Two managers of one server share the seed, so identifiers stay
	// distinct across the block sets that share it.
	other := &reportManager{}
	if bytes.Equal(rm.nextEntryID(), other.nextEntryID()) {
		t.Error("two report managers produced the same EntryID")
	}
}

// The high half of an EntryID comes from a per-process seed, so a client
// that persisted an EntryID across a restart does not mistake a new entry
// for the old one it was resuming from.
func TestEntryIDSurvivesRestart(t *testing.T) {
	rm := &reportManager{}
	before := map[string]bool{}
	for range 50 {
		before[string(rm.nextEntryID())] = true
	}
	// A restarted server is a fresh manager: its counter starts at one
	// again, but the seed has moved, so its first EntryID cannot collide
	// with the last one of the run before it.
	oldSeed := serverEntryIDSeed
	serverEntryIDSeed++
	restarted := &reportManager{}
	after := map[string]bool{}
	for range 50 {
		after[string(restarted.nextEntryID())] = true
	}
	serverEntryIDSeed = oldSeed
	for id := range after {
		if before[id] {
			t.Errorf("EntryID %x was handed out by both runs", id)
		}
	}
}

// Every control block the model declares is materialised under the
// functional constraint IEC 61850-8-1 gives it, and a GSSE block is told
// apart from a plain GOOSE one.
func TestControlBlockConstraint(t *testing.T) {
	plain := buildGoCBObject(&model.GSEControl{Name: "gcb01", GoID: "G", Type: model.GOOSE})
	if got := plain.Attributes[0].FC; got != model.GO {
		t.Errorf("a GOOSE block is served under FC %v, want GO", got)
	}
	legacy := buildGoCBObject(&model.GSEControl{Name: "gscb01", GoID: "G", Type: model.GSSE})
	if got := legacy.Attributes[0].FC; got != model.GS {
		t.Errorf("a GSSE block is served under FC %v, want GS", got)
	}
	mcast := buildSVCBObject(&model.SVControl{Name: "msvcb01", Multicast: true})
	if got := mcast.Attributes[0].FC; got != model.MS {
		t.Errorf("a multicast SV block is served under FC %v, want MS", got)
	}
	ucast := buildSVCBObject(&model.SVControl{Name: "usvcb01"})
	if got := ucast.Attributes[0].FC; got != model.US {
		t.Errorf("a unicast SV block is served under FC %v, want US", got)
	}
}
