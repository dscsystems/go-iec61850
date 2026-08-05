package server_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/dscsystems/go-iec61850/client"
	"github.com/dscsystems/go-iec61850/model"
	"github.com/dscsystems/go-iec61850/server"
)

// Reads issued together are answered together: the association carries
// several invokes at once and each handle collects its own.
func TestReadAsyncConcurrentReads(t *testing.T) {
	addr, srv := startServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	c, err := client.Dial(ctx, addr, client.WithTimeout(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	// Give each indication a distinct value so a crossed response is
	// visible rather than plausible.
	refs := []model.ObjectReference{
		"simpleIOGenericIO/GGIO1.Ind1",
		"simpleIOGenericIO/GGIO1.Ind2",
		"simpleIOGenericIO/GGIO1.Ind3",
		"simpleIOGenericIO/GGIO1.Ind4",
	}
	want := []bool{true, false, true, false}
	srv.Update(func(tx *server.Tx) {
		for i, ref := range refs {
			tx.SetBool(ref.Child("stVal"), want[i])
		}
	})

	reqs := make([]*client.ReadRequest, len(refs))
	for i, ref := range refs {
		reqs[i] = c.ReadAsync(ctx, ref.Child("stVal"), model.ST)
	}
	for i, r := range reqs {
		if r.Ref() != refs[i].Child("stVal") || r.FC() != model.ST {
			t.Errorf("request %d describes %s [%s]", i, r.Ref(), r.FC())
		}
		v, err := r.Result()
		if err != nil {
			t.Fatalf("read %s: %v", r.Ref(), err)
		}
		if v.Bool() != want[i] {
			t.Errorf("%s = %v, want %v", r.Ref(), v.Bool(), want[i])
		}
		// Collecting twice returns the same answer.
		if v2, err2 := r.Result(); v2 != v || err2 != err {
			t.Errorf("%s: second Result differs", r.Ref())
		}
	}
}

// ReadAllAsync keeps the handles aligned with the references given, and a
// reference that fails does not take the others with it.
func TestReadAllAsync(t *testing.T) {
	addr, srv := startServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	c, err := client.Dial(ctx, addr, client.WithTimeout(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	good := []model.ObjectReference{
		"simpleIOGenericIO/GGIO1.Ind1",
		"simpleIOGenericIO/GGIO1.Ind2",
		"simpleIOGenericIO/GGIO1.Ind3",
	}
	want := []bool{false, true, true}
	srv.Update(func(tx *server.Tx) {
		for i, ref := range good {
			tx.SetBool(ref.Child("stVal"), want[i])
		}
	})

	// A missing object in the middle: its neighbours must still be read.
	refs := []model.ObjectReference{
		good[0].Child("stVal"),
		"simpleIOGenericIO/GGIO1.NoSuchObject.stVal",
		good[1].Child("stVal"),
		good[2].Child("stVal"),
	}
	reqs := c.ReadAllAsync(ctx, model.ST, refs...)
	if len(reqs) != len(refs) {
		t.Fatalf("got %d handles for %d references", len(reqs), len(refs))
	}
	for i, r := range reqs {
		if r.Ref() != refs[i] {
			t.Errorf("handle %d is for %s, want %s", i, r.Ref(), refs[i])
		}
		if r.FC() != model.ST {
			t.Errorf("handle %d reads under %s, want ST", i, r.FC())
		}
	}

	if v, err := reqs[1].Result(); err == nil {
		t.Errorf("missing object read as %v, want an error", v)
	}
	for i, idx := range []int{0, 2, 3} {
		v, err := reqs[idx].Result()
		if err != nil {
			t.Fatalf("%s: %v", reqs[idx].Ref(), err)
		}
		if v.Bool() != want[i] {
			t.Errorf("%s = %v, want %v", reqs[idx].Ref(), v.Bool(), want[i])
		}
	}

	if got := c.ReadAllAsync(ctx, model.ST); len(got) != 0 {
		t.Errorf("no references = %v, want no handles", got)
	}
}

// Done lets a caller take whichever read finishes first.
func TestReadAsyncDone(t *testing.T) {
	addr, _ := startServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	c, err := client.Dial(ctx, addr, client.WithTimeout(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	r := c.ReadAsync(ctx, "simpleIOGenericIO/GGIO1.Ind1.stVal", model.ST)
	select {
	case <-r.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("read never completed")
	}
	if _, err := r.Result(); err != nil {
		t.Fatalf("Result after Done: %v", err)
	}
}

// More requests than the association allows outstanding still all complete:
// the surplus waits for a slot instead of being rejected.
func TestReadAsyncBeyondOutstandingLimit(t *testing.T) {
	addr, _ := startServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	c, err := client.Dial(ctx, addr, client.WithTimeout(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	limit := c.MMS().MaxServOutstanding()
	if limit < 1 {
		t.Fatalf("negotiated outstanding limit = %d", limit)
	}
	n := limit*3 + 5
	reqs := make([]*client.ReadRequest, n)
	for i := range reqs {
		reqs[i] = c.ReadAsync(ctx, "simpleIOGenericIO/GGIO1.Ind1.stVal", model.ST)
	}
	for i, r := range reqs {
		if _, err := r.Result(); err != nil {
			t.Fatalf("read %d of %d: %v", i, n, err)
		}
	}
}

func TestReadAsyncCancel(t *testing.T) {
	addr, _ := startServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	c, err := client.Dial(ctx, addr, client.WithTimeout(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	r := c.ReadAsync(ctx, "simpleIOGenericIO/GGIO1.Ind1.stVal", model.ST)
	r.Cancel()
	v, err := r.Result()
	if err == nil {
		// The read may have finished before the cancel landed; that is a
		// legitimate race, but then it must report a value.
		if v == nil {
			t.Error("cancelled read reported neither value nor error")
		}
	} else if !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled read = %v, want context.Canceled", err)
	}

	// Cancelling a finished request is harmless.
	done := c.ReadAsync(ctx, "simpleIOGenericIO/GGIO1.Ind1.stVal", model.ST)
	if _, err := done.Result(); err != nil {
		t.Fatal(err)
	}
	done.Cancel()
	if _, err := done.Result(); err != nil {
		t.Errorf("Result after a late Cancel = %v, want nil", err)
	}

	// A cancelled parent context stops the reads that come after it.
	pctx, pcancel := context.WithCancel(ctx)
	pcancel()
	if _, err := c.ReadAsync(pctx, "simpleIOGenericIO/GGIO1.Ind1.stVal", model.ST).Result(); !errors.Is(err, context.Canceled) {
		t.Errorf("read on a cancelled context = %v, want context.Canceled", err)
	}
}

// Failures arrive through the handle like any other outcome.
func TestReadAsyncErrors(t *testing.T) {
	addr, _ := startServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	c, err := client.Dial(ctx, addr, client.WithTimeout(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}

	bad := c.ReadAsync(ctx, "simpleIOGenericIO/GGIO1.NoSuchObject.stVal", model.ST)
	if v, err := bad.Result(); err == nil {
		t.Errorf("read of a missing object = %v, want an error", v)
	}

	// After the connection ends, requests fail rather than hang.
	c.Close()
	if _, err := c.ReadAsync(ctx, "simpleIOGenericIO/GGIO1.Ind1.stVal", model.ST).Result(); err == nil {
		t.Error("read on a closed connection succeeded")
	}
}
