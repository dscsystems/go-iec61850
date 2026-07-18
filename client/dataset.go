package client

import (
	"context"
	"strings"

	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/model"
)

// DataSet is the result of reading a named dataset.
type DataSet struct {
	Ref     model.ObjectReference
	Members []DataSetEntry
}

// DataSetEntry is one dataset member with its value.
type DataSetEntry struct {
	Ref   model.ObjectReference
	FC    model.FC
	Value *mms.Value
}

// datasetRefToMMS converts an IEC 61850 dataset reference "LD/LN.DataSet"
// to the MMS (domain, listName) pair "LD" + "LN$DataSet".
func datasetRefToMMS(ref model.ObjectReference) (domain, list string) {
	domain = ref.LD()
	path := ref.Path()
	return domain, strings.Join(path, "$")
}

// ReadDataSet reads all members of a dataset named "LD/LN.DataSetName".
func (c *Client) ReadDataSet(ctx context.Context, ref model.ObjectReference) (*DataSet, error) {
	domain, list := datasetRefToMMS(ref)
	refs, err := c.mc.GetNamedVariableListAttributes(ctx, domain, list)
	if err != nil {
		return nil, err
	}
	values, err := c.mc.ReadNamedVariableList(ctx, domain, list)
	if err != nil {
		return nil, err
	}
	ds := &DataSet{Ref: ref}
	for i, r := range refs {
		objRef, fc := model.FromMMS(r.Domain, r.Item)
		var v *mms.Value
		if i < len(values) {
			v = values[i]
		}
		ds.Members = append(ds.Members, DataSetEntry{Ref: objRef, FC: fc, Value: v})
	}
	return ds, nil
}

// CreateDataSet creates a dataset "LD/LN.Name" from the given members.
func (c *Client) CreateDataSet(ctx context.Context, ref model.ObjectReference, members []DataSetEntry) error {
	domain, list := datasetRefToMMS(ref)
	refs := make([]mms.VarRef, len(members))
	for i, m := range members {
		d, item := m.Ref.ToMMS(m.FC)
		refs[i] = mms.VarRef{Domain: d, Item: item}
	}
	return c.mc.DefineNamedVariableList(ctx, domain, list, refs)
}

// DeleteDataSet deletes a dataset "LD/LN.Name".
func (c *Client) DeleteDataSet(ctx context.Context, ref model.ObjectReference) error {
	domain, list := datasetRefToMMS(ref)
	return c.mc.DeleteNamedVariableList(ctx, domain, list)
}
