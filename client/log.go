package client

import (
	"context"
	"strings"
	"time"

	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/model"
)

// LogEntry is one entry returned by a log query.
type LogEntry = mms.JournalEntry

// QueryLogByTime returns log entries in the inclusive time range from the
// log referenced as "LD/LN.LG.LogName".
func (c *Client) QueryLogByTime(ctx context.Context, logRef model.ObjectReference, start, end time.Time) ([]LogEntry, error) {
	domain, item := logRefToMMS(logRef)
	return c.mc.ReadJournalByTime(ctx, domain, item, start, end)
}

// QueryLogAfter returns log entries after the given time and entry id, for
// gap-free continuation of a previous query.
func (c *Client) QueryLogAfter(ctx context.Context, logRef model.ObjectReference, after time.Time, entryID []byte) ([]LogEntry, error) {
	domain, item := logRefToMMS(logRef)
	return c.mc.ReadJournalAfter(ctx, domain, item, after, entryID)
}

// logRefToMMS converts "LD/LN.LG.LogName" (or an already-$-joined item) to
// domain and MMS item "LN$LG$LogName".
func logRefToMMS(ref model.ObjectReference) (domain, item string) {
	domain = ref.LD()
	return domain, strings.Join(ref.Path(), "$")
}
