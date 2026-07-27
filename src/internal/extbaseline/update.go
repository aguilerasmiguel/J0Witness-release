package extbaseline

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"strings"
)

// UpdateEntry es una entrada del protocolo de update de Joomla (formato
// <updates><update>). Solo los campos que necesita la verificación.
type UpdateEntry struct {
	Element     string
	Version     string
	DownloadURL string
	SHA256      string
}

// rawUpdates mapea el XML del update server. downloadurl toma el primero de tipo
// "full" si hay varios (o el primero a secas).
type rawUpdates struct {
	Updates []struct {
		Element   string `xml:"element"`
		Version   string `xml:"version"`
		Downloads struct {
			URLs []struct {
				Type string `xml:"type,attr"`
				URL  string `xml:",chardata"`
			} `xml:"downloadurl"`
		} `xml:"downloads"`
		SHA256 string `xml:"sha256"`
	} `xml:"update"`
}

// ParseUpdates parsea el update XML SIN resolver entidades externas (XXE
// neutralizado, como manifest.Parse). Tope anti-DoS: el llamante limita el body.
func ParseUpdates(raw []byte) ([]UpdateEntry, error) {
	var ru rawUpdates
	dec := xml.NewDecoder(bytes.NewReader(raw))
	dec.Strict = false
	dec.Entity = map[string]string{} // sin entidades personalizadas → XXE off
	if err := dec.Decode(&ru); err != nil {
		return nil, fmt.Errorf("update XML inválido: %w", err)
	}
	var out []UpdateEntry
	for _, u := range ru.Updates {
		e := UpdateEntry{
			Element: strings.TrimSpace(u.Element),
			Version: strings.TrimSpace(u.Version),
			SHA256:  strings.TrimSpace(u.SHA256),
		}
		// downloadurl: preferir type="full".
		for _, d := range u.Downloads.URLs {
			if e.DownloadURL == "" || strings.EqualFold(d.Type, "full") {
				e.DownloadURL = strings.TrimSpace(d.URL)
			}
		}
		out = append(out, e)
	}
	return out, nil
}

// ErrNoMatchingVersion: el update server no ofrece la versión instalada.
var ErrNoMatchingVersion = errors.New("el update server no ofrece la versión instalada")

// ResolveUpdate devuelve la entrada cuya versión == version (y element ==
// element si el XML lo trae). Solo la versión instalada: comparar contra otra
// versión marcaría cada cambio legítimo como modificación (Principio VI).
// Si varias entradas de la MISMA versión difieren en URL de descarga
// (típicamente <targetplatform> distintos), es ambiguo: elegir una al azar
// cachearía el paquete de la plataforma equivocada → falso positivo. Falla
// ruidosamente, como SimulateComponent ante múltiples manifiestos.
func ResolveUpdate(entries []UpdateEntry, element, version string) (UpdateEntry, error) {
	if version == "" {
		// Una versión instalada vacía no debe casar con una entrada de <version>
		// también vacía: sería un comodín, no una versión instalada real.
		return UpdateEntry{}, ErrNoMatchingVersion
	}
	var matches []UpdateEntry
	for _, e := range entries {
		if e.Version != version {
			continue
		}
		if e.Element != "" && !strings.EqualFold(e.Element, element) {
			continue
		}
		matches = append(matches, e)
	}
	if len(matches) == 0 {
		return UpdateEntry{}, ErrNoMatchingVersion
	}
	first := matches[0].DownloadURL
	for _, m := range matches[1:] {
		if m.DownloadURL != first {
			return UpdateEntry{}, fmt.Errorf("el update server ofrece %d paquetes distintos para la versión %s (¿varias plataformas?): no se puede elegir sin ambigüedad", len(matches), version)
		}
	}
	return matches[0], nil
}
