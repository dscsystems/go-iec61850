package client

import (
	"context"
	"fmt"
	"strings"

	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/model"
)

// SettingGroup is a handle to a setting group control block
// ("LD/LN.SP.SGCB"), the ACSI mechanism for switching between and editing
// alternative parameter sets in protection IEDs.
type SettingGroup struct {
	c   *Client
	Ref model.ObjectReference

	NumOfSG uint8
	ActSG   uint8
	EditSG  uint8

	domain string
	item   string // "LN$SP$SGCB"
}

// SettingGroups reads the setting group control block at ref.
func (c *Client) SettingGroups(ctx context.Context, ref model.ObjectReference) (*SettingGroup, error) {
	domain := ref.LD()
	item := strings.Join(ref.Path(), "$")
	sg := &SettingGroup{c: c, Ref: ref, domain: domain, item: item}
	read := func(attr string) (*mms.Value, error) {
		v, err := c.mc.Read(ctx, domain, item+"$"+attr)
		if err != nil {
			return nil, err
		}
		if len(v) == 0 {
			return nil, fmt.Errorf("client: SGCB attribute %s missing", attr)
		}
		if code, isErr := v[0].AccessError(); isErr {
			return nil, code
		}
		return v[0], nil
	}
	if v, err := read("NumOfSG"); err == nil {
		sg.NumOfSG = uint8(v.Uint64())
	} else {
		return nil, err
	}
	if v, err := read("ActSG"); err == nil {
		sg.ActSG = uint8(v.Uint64())
	}
	if v, err := read("EditSG"); err == nil {
		sg.EditSG = uint8(v.Uint64())
	}
	return sg, nil
}

// SelectActiveSG activates setting group sg (1..NumOfSG). Its SG-scoped
// values become the ones in effect.
func (sg *SettingGroup) SelectActiveSG(ctx context.Context, group uint8) error {
	if err := sg.write(ctx, "ActSG", mms.NewUint8(group)); err != nil {
		return err
	}
	sg.ActSG = group
	return nil
}

// SelectEditSG selects the setting group to edit; subsequent reads and
// writes of SE-scoped attributes address that group.
func (sg *SettingGroup) SelectEditSG(ctx context.Context, group uint8) error {
	if err := sg.write(ctx, "EditSG", mms.NewUint8(group)); err != nil {
		return err
	}
	sg.EditSG = group
	return nil
}

// SetEditValue writes a setting value in the currently selected edit group
// (an SE-constrained attribute, e.g. "LD/PTOC1.OpDlTmms.setVal").
func (sg *SettingGroup) SetEditValue(ctx context.Context, ref model.ObjectReference, v *mms.Value) error {
	return sg.c.Write(ctx, ref, model.SE, v)
}

// EditValue reads a setting value from the currently selected edit group.
func (sg *SettingGroup) EditValue(ctx context.Context, ref model.ObjectReference) (*mms.Value, error) {
	return sg.c.Read(ctx, ref, model.SE)
}

// ConfirmEdit commits the edited values to the edit setting group.
func (sg *SettingGroup) ConfirmEdit(ctx context.Context) error {
	return sg.write(ctx, "CnfEdit", mms.NewBool(true))
}

func (sg *SettingGroup) write(ctx context.Context, attr string, v *mms.Value) error {
	results, err := sg.c.mc.Write(ctx, sg.domain, []string{sg.item + "$" + attr}, []*mms.Value{v})
	if err != nil {
		return err
	}
	if len(results) > 0 && results[0] != nil {
		return fmt.Errorf("client: SGCB write %s: %w", attr, results[0])
	}
	return nil
}
