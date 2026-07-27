// Package report produce el documento JSON canónico (Principio X: la salida
// canónica es JSON; el resto son proyecciones) con serialización determinista
// (Principio IV).
package report

import (
	"bytes"
	"encoding/json"
)

// CanonicalMarshal serializa con garantías de determinismo: los structs se
// emiten en orden de declaración, los mapas con claves ordenadas (semántica de
// encoding/json), sin escape HTML, con sangría de dos espacios y LF final
// único. Prohibido serializar tipos cuyo orden de iteración no sea estable.
func CanonicalMarshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
