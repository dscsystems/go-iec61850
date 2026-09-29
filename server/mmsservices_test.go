package server_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"
	"time"

	"github.com/dscsystems/go-iec61850/client"
	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/model"
	"github.com/dscsystems/go-iec61850/scl"
	"github.com/dscsystems/go-iec61850/server"
)

func testCtx(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func simpleIO(t *testing.T) *model.Model {
	t.Helper()
	m, err := scl.LoadModel("../testdata/simpleIO_direct_control.cid")
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// The server authenticates associations and refuses the ones that fail
// with an ACSE rejection the client can read.
func TestAuthentication(t *testing.T) {
	addr, _ := startServerWith(t, simpleIO(t), server.WithPassword("s3cret"))
	ctx := testCtx(t)
	c, err := client.Dial(ctx, addr, client.WithPassword("s3cret"))
	if err != nil {
		t.Fatalf("right password: %v", err)
	}
	c.Close()

	_, err = client.Dial(ctx, addr, client.WithPassword("guess"))
	var rej *mms.RejectedError
	if !errors.As(err, &rej) || rej.Diagnostic != 13 || !errors.Is(err, mms.ErrAuthenticationFailed) {
		t.Errorf("wrong password: %v, want authentication-failure", err)
	}
	_, err = client.Dial(ctx, addr)
	if !errors.As(err, &rej) || rej.Diagnostic != 14 {
		t.Errorf("no password: %v, want authentication-required", err)
	}

	// An authenticator sees the association's details.
	var seen mms.AssociationRequest
	addr2, _ := startServerWith(t, simpleIO(t), server.WithAuthenticator(func(r mms.AssociationRequest) error {
		seen = r
		return nil
	}))
	c, err = client.Dial(ctx, addr2, client.WithPassword("pw"))
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if seen.Password != "pw" || seen.Peer == nil || seen.TLS != nil {
		t.Errorf("authenticator saw %+v", seen)
	}
}

func TestStatus(t *testing.T) {
	addr, srv := startServerWith(t, simpleIO(t))
	c := dialDemo(t, addr)
	ctx := testCtx(t)
	st, err := c.ServerStatus(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	if st.Logical != mms.LogicalStateChangesAllowed || st.Physical != mms.PhysicalOperational {
		t.Errorf("status %+v", st)
	}
	srv.SetStatus(mms.LogicalNoStateChangesAllowed, mms.PhysicalNeedsCommissioning)
	if st, _ = c.ServerStatus(ctx, true); st.Logical != 1 || st.Physical != 3 {
		t.Errorf("status after SetStatus %+v", st)
	}
}

// An abort ends the association at both ends, whichever end sends it.
func TestAbort(t *testing.T) {
	addr, srv := startServerWith(t, simpleIO(t))
	closed := make(chan *mms.ServerConn, 4)
	opened := make(chan *mms.ServerConn, 4)
	srv.OnConnection(func(ev server.ConnectionEvent) {
		switch ev.State {
		case server.ConnectionOpened:
			opened <- ev.Conn
		case server.ConnectionClosed:
			closed <- ev.Conn
		}
	})
	c := dialDemo(t, addr)
	<-opened
	if err := c.Abort(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-closed:
	case <-time.After(3 * time.Second):
		t.Fatal("the server did not end the aborted association")
	}
	if _, err := c.ServerStatus(testCtx(t), false); !errors.Is(err, mms.ErrAborted) {
		t.Errorf("request after Abort: %v", err)
	}

	// The server aborts; the client sees it.
	c2 := dialDemo(t, addr)
	sc := <-opened
	sc.Abort()
	select {
	case <-c2.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("the client did not see the server's abort")
	}
	if err := c2.Err(); !errors.Is(err, mms.ErrAborted) {
		t.Errorf("client error after the server's abort: %v", err)
	}
}

func TestSetFileAndDeleteFile(t *testing.T) {
	dir := t.TempDir()
	store, err := server.DirFS(dir)
	if err != nil {
		t.Fatal(err)
	}
	addr, _ := startServerWith(t, simpleIO(t), server.WithFileStore(store))
	c := dialDemo(t, addr)
	ctx := testCtx(t)

	// Larger than one fileRead chunk, so the server reads it in several.
	data := bytes.Repeat([]byte("COMTRADE "), 5000)
	if err := c.SetFile(ctx, "fault/record.cfg", nil); err == nil {
		t.Error("a file in a directory that does not exist was written")
	}
	if err := c.SetFile(ctx, "record.cfg", data); err != nil {
		t.Fatalf("SetFile: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "record.cfg"))
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("stored %d octets, %v; want %d", len(got), err, len(data))
	}
	// Read back through GetFile.
	if back, err := c.ReadFile(ctx, "record.cfg"); err != nil || !bytes.Equal(back, data) {
		t.Errorf("GetFile after SetFile: %d octets, %v", len(back), err)
	}
	// An existing name is not overwritten.
	var se *mms.ServiceError
	if err := c.SetFile(ctx, "record.cfg", []byte("x")); !errors.As(err, &se) || se.Class != 11 || se.Code != 8 {
		t.Errorf("SetFile over an existing file: %v, want file/duplicate-filename", err)
	}
	// Nothing outside the store.
	if err := c.SetFile(ctx, "../escape.cfg", []byte("x")); err == nil {
		t.Error("a name outside the store was written")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(dir), "escape.cfg")); err == nil {
		t.Error("a file was written outside the store")
	}

	if err := c.DeleteFile(ctx, "/record.cfg"); err != nil {
		t.Fatalf("DeleteFile: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "record.cfg")); !os.IsNotExist(err) {
		t.Error("the file is still there")
	}
	if err := c.DeleteFile(ctx, "record.cfg"); !errors.As(err, &se) || se.Class != 11 || se.Code != 7 {
		t.Errorf("DeleteFile of a missing file: %v, want file/file-non-existent", err)
	}

	// A read-only store serves neither.
	addr2, _ := startServerWith(t, simpleIO(t), server.WithFileStore(fstest.MapFS{"a.txt": {Data: []byte("a")}}))
	c2 := dialDemo(t, addr2)
	if err := c2.SetFile(ctx, "b.txt", []byte("b")); err == nil {
		t.Error("SetFile succeeded on a read-only store")
	}
	if err := c2.DeleteFile(ctx, "a.txt"); err == nil {
		t.Error("DeleteFile succeeded on a read-only store")
	}
}

func TestJournalServices(t *testing.T) {
	srv, c := startLogServer(t)
	ctx := testCtx(t)
	for i := range 4 {
		setInd(srv, "Ind1", i%2 == 0)
	}
	st, err := c.LogStatus(ctx, logRef)
	if err != nil {
		t.Fatal(err)
	}
	if st.CurrentEntries != 4 || st.Deletable {
		t.Errorf("status %+v, want 4 entries, not deletable", st)
	}
	if _, err := c.ClearLog(ctx, logRef, time.Time{}, nil); !isAccessDenied(err) {
		t.Errorf("clearing a log without WithDeletableLogs: %v, want access denied", err)
	}

	srv2, c2 := startLogServer(t, server.WithDeletableLogs())
	for i := range 3 {
		setInd(srv2, "Ind1", i%2 == 0)
	}
	entries := queryAll(t, c2)
	if len(entries) != 3 {
		t.Fatalf("%d entries", len(entries))
	}
	// Up to and including the second entry.
	n, err := c2.ClearLog(ctx, logRef, entries[2].OccurrenceTime, entries[1].EntryID)
	if err != nil || n != 2 {
		t.Fatalf("ClearLog to the second entry: %d, %v", n, err)
	}
	if left := queryAll(t, c2); len(left) != 1 || !bytes.Equal(left[0].EntryID, entries[2].EntryID) {
		t.Errorf("left %d entries", len(left))
	}
	if n, err := c2.ClearLog(ctx, logRef, time.Time{}, nil); err != nil || n != 1 {
		t.Errorf("ClearLog all: %d, %v", n, err)
	}
	if st, _ := c2.LogStatus(ctx, logRef); st.CurrentEntries != 0 || !st.Deletable {
		t.Errorf("status after clearing %+v", st)
	}
}

func isAccessDenied(err error) bool {
	var se *mms.ServiceError
	return errors.As(err, &se) && se.Class == 7 && se.Code == 3
}

// A configured data set, or one a control block uses, is not deleted.
func TestDeleteDataSetRules(t *testing.T) {
	addr, _ := startServerWith(t, simpleIO(t))
	c := dialDemo(t, addr)
	ctx := testCtx(t)
	if err := c.DeleteDataSet(ctx, "simpleIOGenericIO/LLN0.Events"); !errors.Is(err, mms.ErrNotDeleted) {
		t.Errorf("deleting a configured data set: %v, want ErrNotDeleted", err)
	}
	members := []client.DataSetEntry{{Ref: "simpleIOGenericIO/GGIO1.SPCSO1.stVal", FC: model.ST}}
	if err := c.CreateDataSet(ctx, "simpleIOGenericIO/LLN0.Dyn1", members); err != nil {
		t.Fatal(err)
	}
	if err := c.CreateDataSet(ctx, "simpleIOGenericIO/LLN0.Dyn2", members); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteDataSet(ctx, "simpleIOGenericIO/LLN0.Dyn1"); err != nil {
		t.Errorf("deleting a data set the client made: %v", err)
	}
	// Point a report control block at Dyn2: now it is in use.
	if err := c.Write(ctx, "simpleIOGenericIO/LLN0.EventsRCB01.DatSet", model.RP,
		mms.NewVisibleString("simpleIOGenericIO/LLN0$Dyn2")); err != nil {
		t.Fatalf("setting DatSet: %v", err)
	}
	if err := c.DeleteDataSet(ctx, "simpleIOGenericIO/LLN0.Dyn2"); !errors.Is(err, mms.ErrNotDeleted) {
		t.Errorf("deleting a data set a report uses: %v, want ErrNotDeleted", err)
	}
	if err := c.DeleteDataSet(ctx, "simpleIOGenericIO/LLN0.Nope"); err == nil {
		t.Error("deleting a data set that does not exist succeeded")
	}
}
