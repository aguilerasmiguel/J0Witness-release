// Package corediff implementa L2: clasificación de cada archivo del árbol
// frente al baseline verificado (FR-030…FR-035).
package corediff

import "bytes"

// normalizeText elimina BOM y convierte CRLF/CR a LF: si tras normalizar dos
// contenidos coinciden, la divergencia es solo de finales de línea o
// codificación (FR-032) y su severidad es informativa.
func normalizeText(b []byte) []byte {
	b = bytes.TrimPrefix(b, []byte{0xEF, 0xBB, 0xBF}) // BOM UTF-8
	b = bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))
	b = bytes.ReplaceAll(b, []byte("\r"), []byte("\n"))
	return b
}

// EOLOnly informa de si a y b difieren exclusivamente en finales de línea,
// BOM o retorno de carro.
func EOLOnly(a, b []byte) bool {
	if bytes.Equal(a, b) {
		return false // idénticos, no "solo EOL"
	}
	return bytes.Equal(normalizeText(a), normalizeText(b))
}
