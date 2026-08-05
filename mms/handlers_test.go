package mms

import (
	"testing"

	"github.com/dscsystems/go-iec61850/asn1"
)

func reportPDU(item string, v int32) []byte {
	spec := asn1.Cons(asn1.ContextConstructed(1), objectName("LD0", item)) // variableListName [1]
	return buildReport(spec, NewInt32(v))
}

// One association carries every RCB subscription a client makes, so a second
// registration must not silence the first: registration is additive.
func TestInformationReportHandlersAreAdditive(t *testing.T) {
	c := &Conn{}
	var order []string
	c.OnInformationReport(func(*InformationReport) { order = append(order, "first") })
	c.OnInformationReport(func(*InformationReport) { order = append(order, "second") })

	c.handleUnconfirmed(reportPDU("LLN0$RP$urcb01", 1))

	if len(order) != 2 || order[0] != "first" || order[1] != "second" {
		t.Fatalf("handlers called = %v, want [first second] in registration order", order)
	}
}

func TestInformationReportRemoveDropsOnlyItsOwn(t *testing.T) {
	c := &Conn{}
	var kept, dropped int
	removeKept := c.OnInformationReport(func(*InformationReport) { kept++ })
	removeDropped := c.OnInformationReport(func(*InformationReport) { dropped++ })

	removeDropped()
	c.handleUnconfirmed(reportPDU("LLN0$RP$urcb01", 1))
	if kept != 1 || dropped != 0 {
		t.Fatalf("kept = %d, dropped = %d, want 1 and 0", kept, dropped)
	}

	// Removal is idempotent: a second Disable must not take out the handler
	// that has since been appended in the freed slot.
	removeDropped()
	c.handleUnconfirmed(reportPDU("LLN0$RP$urcb01", 2))
	if kept != 2 {
		t.Fatalf("kept = %d after repeated removal, want 2", kept)
	}

	removeKept()
	c.handleUnconfirmed(reportPDU("LLN0$RP$urcb01", 3))
	if kept != 2 {
		t.Fatalf("kept = %d after removal, want 2", kept)
	}
	if len(c.reportHandlers) != 0 {
		t.Errorf("reportHandlers = %d, want 0", len(c.reportHandlers))
	}
}

// A handler that unsubscribes itself runs on the reader goroutine, mutating
// the slice the dispatch loop is walking.
func TestInformationReportRemoveFromInsideHandler(t *testing.T) {
	c := &Conn{}
	var self, other int
	var remove func()
	remove = c.OnInformationReport(func(*InformationReport) {
		self++
		remove()
	})
	c.OnInformationReport(func(*InformationReport) { other++ })

	c.handleUnconfirmed(reportPDU("LLN0$RP$urcb01", 1))
	c.handleUnconfirmed(reportPDU("LLN0$RP$urcb01", 2))

	if self != 1 {
		t.Errorf("self-removing handler ran %d times, want 1", self)
	}
	if other != 2 {
		t.Errorf("other handler ran %d times, want 2", other)
	}
}

func TestRawUnconfirmedHandlersAreAdditive(t *testing.T) {
	c := &Conn{}
	var a, b int
	c.OnRawUnconfirmed(func([]byte) { a++ })
	removeB := c.OnRawUnconfirmed(func([]byte) { b++ })

	c.handleUnconfirmed(reportPDU("LLN0$RP$urcb01", 1))
	if a != 1 || b != 1 {
		t.Fatalf("raw handlers = %d/%d, want 1/1", a, b)
	}

	removeB()
	c.handleUnconfirmed(reportPDU("LLN0$RP$urcb01", 2))
	if a != 2 || b != 1 {
		t.Fatalf("raw handlers after removal = %d/%d, want 2/1", a, b)
	}
}

// A nil handler used to clear the registration; it must now be inert rather
// than panic on dispatch.
func TestNilHandlerIsInert(t *testing.T) {
	c := &Conn{}
	var got int
	c.OnInformationReport(func(*InformationReport) { got++ })
	c.OnInformationReport(nil)()
	c.OnRawUnconfirmed(nil)()

	c.handleUnconfirmed(reportPDU("LLN0$RP$urcb01", 1))
	if got != 1 {
		t.Fatalf("handler ran %d times, want 1", got)
	}
}
