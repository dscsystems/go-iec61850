package scl

import (
	"encoding/xml"
	"fmt"
	"io"
	"os"
)

// Parse decodes an SCL document from r. It checks that the root element
// is SCL but does not validate against the XML schema.
func Parse(r io.Reader) (*SCL, error) {
	var s SCL
	if err := xml.NewDecoder(r).Decode(&s); err != nil {
		return nil, fmt.Errorf("scl: parse: %w", err)
	}
	return &s, nil
}

// ParseFile decodes the SCL document at path.
func ParseFile(path string) (*SCL, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("scl: %w", err)
	}
	defer f.Close()
	var s SCL
	if err := xml.NewDecoder(f).Decode(&s); err != nil {
		return nil, fmt.Errorf("scl: parse %s: %w", path, err)
	}
	return &s, nil
}
