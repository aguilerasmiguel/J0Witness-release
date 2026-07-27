// Package dbscan parsea un volcado mysqldump (texto plano) en filas tipadas,
// sin ejecutar nunca el SQL (Principio IX): es análisis léxico puro sobre el
// texto del INSERT. Sirve de base para correlacionar el estado de la base de
// datos con el árbol de disco en una capa posterior.
package dbscan

import "time"

// parseMySQLDatetime convierte el formato datetime de MySQL (UTC) a unix ns.
// Determinista: time.Parse no consulta el reloj. Fechas cero/vacías → 0.
func parseMySQLDatetime(s string) int64 {
	if s == "" || s == "0000-00-00 00:00:00" {
		return 0
	}
	t, err := time.Parse("2006-01-02 15:04:05", s)
	if err != nil {
		return 0
	}
	return t.UnixNano()
}
