package asn1

import (
	"fmt"
	"strconv"
	"time"
)

// FormatTime62351 encodes t as the GeneralizedTime content octets IEC
// 62351-4 13.1.2 requires: YYYYMMDDhhmmss in UTC, then a fraction of a
// second with '.' and no trailing zeros (omitted when zero), then 'Z'. This
// is also the DER-canonical form. Precision is milliseconds.
func FormatTime62351(t time.Time) []byte {
	t = t.UTC().Truncate(time.Millisecond)
	b := []byte(t.Format("20060102150405"))
	if ms := t.Nanosecond() / int(time.Millisecond); ms != 0 {
		f := fmt.Sprintf("%03d", ms)
		for f[len(f)-1] == '0' {
			f = f[:len(f)-1]
		}
		b = append(b, '.')
		b = append(b, f...)
	}
	return append(b, 'Z')
}

// ParseTime62351 parses GeneralizedTime content octets under the IEC
// 62351-4 13.1.2 rules: YYYYMMDDhh[mm[ss[(.|,)f+]]]Z, UTC only, no 'T',
// no offsets. Hour, minute or second precision and any fraction length are
// accepted (a fraction requires seconds).
func ParseTime62351(b []byte) (time.Time, error) {
	bad := func(why string) (time.Time, error) {
		return time.Time{}, fmt.Errorf("asn1: GeneralizedTime %q: %s: %w", b, why, ErrBadValue)
	}
	n := len(b)
	if n < 11 || b[n-1] != 'Z' {
		return bad("must be UTC ending in Z")
	}
	s := b[:n-1]
	digits := func(i, j int) (int, bool) {
		if j > len(s) {
			return 0, false
		}
		v := 0
		for _, c := range s[i:j] {
			if c < '0' || c > '9' {
				return 0, false
			}
			v = v*10 + int(c-'0')
		}
		return v, true
	}
	year, ok1 := digits(0, 4)
	month, ok2 := digits(4, 6)
	day, ok3 := digits(6, 8)
	hour, ok4 := digits(8, 10)
	if !(ok1 && ok2 && ok3 && ok4) {
		return bad("bad date or hour")
	}
	minute, sec, nsec := 0, 0, 0
	rest := s[10:]
	if len(rest) > 0 {
		var ok bool
		if minute, ok = digits(10, 12); !ok {
			return bad("bad minutes")
		}
		rest = s[12:]
	}
	if len(rest) > 0 {
		var ok bool
		if sec, ok = digits(12, 14); !ok {
			return bad("bad seconds")
		}
		rest = s[14:]
	}
	if len(rest) > 0 {
		if rest[0] != '.' && rest[0] != ',' {
			return bad("unexpected characters")
		}
		frac := rest[1:]
		if len(frac) == 0 || len(frac) > 18 {
			return bad("bad fraction")
		}
		for _, c := range frac {
			if c < '0' || c > '9' {
				return bad("bad fraction")
			}
		}
		// Keep nanosecond precision.
		f := string(frac)
		for len(f) < 9 {
			f += "0"
		}
		v, err := strconv.Atoi(f[:9])
		if err != nil {
			return bad("bad fraction")
		}
		nsec = v
	}
	if month < 1 || month > 12 || day < 1 || day > 31 || hour > 23 || minute > 59 || sec > 59 {
		return bad("field out of range")
	}
	t := time.Date(year, time.Month(month), day, hour, minute, sec, nsec, time.UTC)
	if t.Day() != day {
		return bad("no such day")
	}
	return t, nil
}

// NamedBits encodes a BIT STRING of named bits the DER way: trailing zero
// bits removed (X.690 11.2.2). bits lists the set bit numbers.
func NamedBits(bits ...int) []byte {
	max := -1
	for _, b := range bits {
		if b > max {
			max = b
		}
	}
	if max < 0 {
		return []byte{0}
	}
	bs := NewBitString(max + 1)
	for _, b := range bits {
		bs.SetBit(b, true)
	}
	return AppendBitString(nil, bs)
}
