package privacy

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"strings"

	"AegisPlus/CrystaL/internal/model"
)

// SanitizeCollectorRecord strips recognized secrets before raw persistence.
// It never promises to remove arbitrary secrets from unrestricted event text.
// CommandLine fields preserve benign parameters for process analytics.
func SanitizeCollectorRecord(rec model.CollectorRecord, collectCmdline, redact bool) (model.CollectorRecord, error) {
	if !redact && collectCmdline {
		return rec, nil
	}
	if rec.Process != nil {
		p := *rec.Process
		if !collectCmdline {
			p.CommandLine, p.ParentCommand = "", ""
		} else {
			p.CommandLine = RedactCommandLine(p.CommandLine).Redacted
			p.ParentCommand = RedactCommandLine(p.ParentCommand).Redacted
		}
		rec.Process = &p
	}
	if rec.Parent != nil {
		p := *rec.Parent
		if !collectCmdline {
			p.CommandLine, p.ParentCommand = "", ""
		} else {
			p.CommandLine = RedactCommandLine(p.CommandLine).Redacted
			p.ParentCommand = RedactCommandLine(p.ParentCommand).Redacted
		}
		rec.Parent = &p
	}
	if rec.XML != "" {
		data, err := SanitizeEventXML(rec.XML, collectCmdline)
		if err != nil { return rec, err }
		rec.XML = data
	}
	if len(rec.Payload) > 0 {
		// Unstructured nested payload cannot be proved safe: reject rather than
		// accidentally persisting a plaintext credential.
		return rec, fmt.Errorf("opaque payload cannot be safely redacted")
	}
	return rec, nil
}

// SanitizeEventXML runs an XML token filter, redacting sensitive EventData values.
// Namespaced UserData and unknown fields are preserved structurally.
func SanitizeEventXML(raw string, collectCmdline bool) (string, error) {
	dec := xml.NewDecoder(strings.NewReader(raw))
	var buf bytes.Buffer
	enc := xml.NewEncoder(&buf)
	var sensitive bool
	var depth int
	for {
		tok, err := dec.Token()
		if err != nil {
			if err.Error() == "EOF" { break }
			return "", fmt.Errorf("invalid event XML: %w", err)
		}
		switch x := tok.(type) {
		case xml.StartElement:
			depth++
			if x.Name.Local == "Data" {
				sensitive = false
				for _, attr := range x.Attr {
					if attr.Name.Local == "Name" {
						switch strings.ToLower(attr.Value) {
						case "commandline", "parentcommandline", "scriptblocktext", "password", "token", "authorization":
							sensitive = true
						}
					}
				}
			}
		case xml.EndElement:
			if x.Name.Local == "Data" { sensitive = false }
			depth--
		case xml.CharData:
			s := string(x)
			if sensitive {
				if collectCmdline {
					s = RedactCommandLine(s).Redacted
				} else {
					s = "[REDACTED]"
				}
			} else {
				s = RedactCommandLine(s).Redacted
			}
			tok = xml.CharData([]byte(s))
		}
		if err := enc.EncodeToken(tok); err != nil { return "", err }
	}
	if depth != 0 { return "", fmt.Errorf("invalid event XML: unbalanced element") }
	if err := enc.Flush(); err != nil { return "", err }
	return buf.String(), nil
}
