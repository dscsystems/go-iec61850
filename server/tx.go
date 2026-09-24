package server

import (
	"time"

	"github.com/dscsystems/go-iec61850/mms"
	"github.com/dscsystems/go-iec61850/model"
)

// Tx is an in-progress atomic model update. Its methods mutate leaf data
// attribute values; they take effect together when Update returns, and
// drive any reports whose dataset includes the changed attributes.
type Tx struct {
	s       *Server
	changed changeSet
}

// change identifies a written leaf. The same reference can exist under
// several functional constraints, and a change under CF is no change to a
// dataset member under ST.
type change struct {
	ref model.ObjectReference
	fc  model.FC
}

// changeSet records the leaves an update wrote and the trigger reasons
// each write raised.
type changeSet map[change]model.TrgOps

// record notes a write of v over old to the leaf da at ref. It raises the
// attribute's dchg or qchg when the value changed and its dupd whenever it
// was written (IEC 61850-7-2); an attribute without trigger options, a
// timestamp for one, raises nothing.
func (cs changeSet) record(ref model.ObjectReference, da *model.DataAttribute, old, v *mms.Value) {
	var r model.TrgOps
	if old == nil || !old.Equal(v) {
		r |= da.TrgOps & (model.TrgDataChange | model.TrgQualityChange)
	}
	r |= da.TrgOps & model.TrgDataUpdate
	cs[change{ref, da.FC}] |= r
}

// Get returns the current value of the leaf attribute at ref under FC fc,
// or nil. Use this instead of Server.Read inside an Update callback:
// Server.Read takes the model lock, which Update already holds, and would
// deadlock.
func (tx *Tx) Get(ref model.ObjectReference, fc model.FC) *mms.Value {
	da := tx.s.model.Attribute(ref, fc)
	if da == nil {
		return nil
	}
	return da.Value
}

// Toggle flips a boolean leaf attribute and returns the new value.
func (tx *Tx) Toggle(ref model.ObjectReference, fc model.FC) bool {
	on := true
	if v := tx.Get(ref, fc); v != nil {
		on = !v.Bool()
	}
	tx.Set(ref, fc, mms.NewBool(on))
	return on
}

// Set assigns a value to the leaf attribute at ref under FC fc. Unknown
// references are ignored (a diagnostic is logged).
func (tx *Tx) Set(ref model.ObjectReference, fc model.FC, v *mms.Value) {
	da := tx.s.model.Attribute(ref, fc)
	if da == nil || len(da.Children) != 0 {
		tx.s.log.Warn("server: Update to unknown/structured attribute", "ref", ref, "fc", fc.String())
		return
	}
	old := da.Value
	da.Value = v
	tx.changed.record(ref, da, old, v)
}

// SetFloat32 sets a float measurand (FC MX by convention).
func (tx *Tx) SetFloat32(ref model.ObjectReference, v float32) {
	tx.Set(ref, model.MX, mms.NewFloat32(v))
}

// SetBool sets a boolean status value (FC ST by convention).
func (tx *Tx) SetBool(ref model.ObjectReference, v bool) {
	tx.Set(ref, model.ST, mms.NewBool(v))
}

// SetInt32 sets an integer value under the given FC.
func (tx *Tx) SetInt32(ref model.ObjectReference, fc model.FC, v int32) {
	tx.Set(ref, fc, mms.NewInt32(v))
}

// SetQuality sets a quality attribute (FC MX or ST).
func (tx *Tx) SetQuality(ref model.ObjectReference, fc model.FC, q model.Quality) {
	tx.Set(ref, fc, q.Value())
}

// SetTimestampNow sets a UTC timestamp attribute to the current time.
func (tx *Tx) SetTimestampNow(ref model.ObjectReference, fc model.FC) {
	tx.Set(ref, fc, mms.NewUTCTime(time.Now(), mms.TimeAccuracy(10)))
}
