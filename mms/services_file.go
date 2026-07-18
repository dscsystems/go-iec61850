package mms

import (
	"context"
	"time"

	"github.com/dscsystems/go-iec61850/asn1"
)

// FileEntry describes one entry returned by FileDirectory.
type FileEntry struct {
	Name         string
	Size         uint32
	LastModified time.Time
}

// FileOpen opens a file for reading and returns the file-read state
// machine id and the file size (MMS fileOpen, ISO 9506-2 service 72).
func (c *Conn) FileOpen(ctx context.Context, name string) (frsmID int32, size uint32, err error) {
	req := asn1.Cons(asn1.ContextConstructed(svcFileOpen),
		asn1.Cons(asn1.ContextConstructed(0), // fileName [0] SEQUENCE OF GraphicString
			asn1.Prim(asn1.TagGraphicString, []byte(name))),
		asn1.UintElem(asn1.ContextPrimitive(1), 0), // initialPosition [1]
	)
	resp, err := c.call(ctx, req)
	if err != nil {
		return 0, 0, err
	}
	dec := asn1.NewDecoder(resp)
	content, err := dec.Expect(asn1.ContextConstructed(svcFileOpen))
	if err != nil {
		return 0, 0, err
	}
	inner := asn1.NewDecoder(content)
	idBytes, err := inner.Expect(asn1.ContextPrimitive(0)) // frsmId [0]
	if err != nil {
		return 0, 0, err
	}
	id, _ := asn1.DecodeInt(idBytes)
	if attrs, ok, _ := inner.Optional(asn1.ContextConstructed(1)); ok {
		ad := asn1.NewDecoder(attrs)
		if sz, err := ad.Expect(asn1.ContextPrimitive(0)); err == nil {
			n, _ := asn1.DecodeUint(sz)
			size = uint32(n)
		}
	}
	return int32(id), size, nil
}

// FileRead reads the next chunk of an open file. moreFollows is false on
// the last chunk (MMS fileRead, service 73).
func (c *Conn) FileRead(ctx context.Context, frsmID int32) (data []byte, moreFollows bool, err error) {
	req := asn1.IntElem(asn1.ContextPrimitive(svcFileRead), int64(frsmID))
	resp, err := c.call(ctx, req)
	if err != nil {
		return nil, false, err
	}
	dec := asn1.NewDecoder(resp)
	content, err := dec.Expect(asn1.ContextConstructed(svcFileRead))
	if err != nil {
		return nil, false, err
	}
	inner := asn1.NewDecoder(content)
	fileData, err := inner.Expect(asn1.ContextPrimitive(0)) // fileData [0]
	if err != nil {
		return nil, false, err
	}
	moreFollows = true // DEFAULT TRUE
	if mf, ok, _ := inner.Optional(asn1.ContextPrimitive(1)); ok {
		moreFollows, _ = asn1.DecodeBool(mf)
	}
	return append([]byte(nil), fileData...), moreFollows, nil
}

// FileClose releases a file-read state machine (MMS fileClose, service 74).
func (c *Conn) FileClose(ctx context.Context, frsmID int32) error {
	req := asn1.IntElem(asn1.ContextPrimitive(svcFileClose), int64(frsmID))
	_, err := c.call(ctx, req)
	return err
}

// FileDirectory lists directory entries under path (empty for the root)
// following continuation (MMS fileDirectory, service 77).
func (c *Conn) FileDirectory(ctx context.Context, path string) ([]FileEntry, error) {
	var entries []FileEntry
	after := ""
	for {
		batch, more, err := c.fileDirectoryPage(ctx, path, after)
		if err != nil {
			return nil, err
		}
		entries = append(entries, batch...)
		if !more || len(batch) == 0 {
			return entries, nil
		}
		after = batch[len(batch)-1].Name
	}
}

func (c *Conn) fileDirectoryPage(ctx context.Context, path, after string) ([]FileEntry, bool, error) {
	req := asn1.Cons(asn1.ContextConstructed(svcFileDirectory))
	if path != "" {
		req.Add(asn1.Cons(asn1.ContextConstructed(0), asn1.Prim(asn1.TagGraphicString, []byte(path))))
	}
	if after != "" {
		req.Add(asn1.Cons(asn1.ContextConstructed(1), asn1.Prim(asn1.TagGraphicString, []byte(after))))
	}
	resp, err := c.call(ctx, req)
	if err != nil {
		return nil, false, err
	}
	dec := asn1.NewDecoder(resp)
	content, err := dec.Expect(asn1.ContextConstructed(svcFileDirectory))
	if err != nil {
		return nil, false, err
	}
	inner := asn1.NewDecoder(content)
	listContent, err := inner.Expect(asn1.ContextConstructed(0)) // listOfDirectoryEntry [0]
	if err != nil {
		return nil, false, err
	}
	// [0] explicitly wraps a SEQUENCE OF DirectoryEntry.
	seqOf, err := asn1.NewDecoder(listContent).Expect(asn1.TagSequence)
	if err != nil {
		return nil, false, err
	}
	var entries []FileEntry
	ld := asn1.NewDecoder(seqOf)
	for ld.More() {
		entryContent, err := ld.Expect(asn1.TagSequence)
		if err != nil {
			return nil, false, err
		}
		e, err := parseDirEntry(entryContent)
		if err != nil {
			return nil, false, err
		}
		entries = append(entries, e)
	}
	more := false
	if mf, ok, _ := inner.Optional(asn1.ContextPrimitive(1)); ok {
		more, _ = asn1.DecodeBool(mf)
	}
	return entries, more, nil
}

func parseDirEntry(content []byte) (FileEntry, error) {
	dec := asn1.NewDecoder(content)
	var e FileEntry
	// fileName [0] SEQUENCE OF GraphicString
	nameSeq, err := dec.Expect(asn1.ContextConstructed(0))
	if err != nil {
		return e, err
	}
	nd := asn1.NewDecoder(nameSeq)
	if name, err := nd.Expect(asn1.TagGraphicString); err == nil {
		e.Name = string(name)
	}
	// fileAttributes [1] { sizeOfFile [0] Unsigned32, lastModified [1] GraphicString }
	if attrs, ok, _ := dec.Optional(asn1.ContextConstructed(1)); ok {
		ad := asn1.NewDecoder(attrs)
		if sz, err := ad.Expect(asn1.ContextPrimitive(0)); err == nil {
			n, _ := asn1.DecodeUint(sz)
			e.Size = uint32(n)
		}
		if lm, ok, _ := ad.Optional(asn1.ContextPrimitive(1)); ok {
			e.LastModified = parseGeneralizedTime(string(lm))
		}
	}
	return e, nil
}

// parseGeneralizedTime parses the ASN.1 GeneralizedTime used for file
// timestamps (YYYYMMDDHHMMSS[.sss]Z), tolerating a missing zone.
func parseGeneralizedTime(s string) time.Time {
	for _, layout := range []string{"20060102150405.000Z", "20060102150405Z", "20060102150405"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}
