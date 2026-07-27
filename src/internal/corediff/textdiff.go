package corediff

import (
	"strings"

	"github.com/hexops/gotextdiff"
	"github.com/hexops/gotextdiff/myers"
	"github.com/hexops/gotextdiff/span"
)

// Hunk localiza un fragmento divergente en el archivo analizado (FR-031).
type Hunk struct {
	FromLine int      `json:"from_line"`
	ToLine   int      `json:"to_line"`
	Added    []string `json:"added,omitempty"`
	Removed  []string `json:"removed,omitempty"`
}

// DiffResult cuantifica la divergencia de un archivo de texto modificado.
type DiffResult struct {
	Hunks        []Hunk
	LinesAdded   int
	LinesRemoved int
	TotalLines   int
	Injection    bool // el fragmento añadido es ejecutable-sospechoso
}

// suspiciousFragments son construcciones típicas de inyección PHP. No es un
// motor de reglas (feature 003): solo clasifica el fragmento divergente ya
// detectado por hash, así que su tasa de falsos positivos se limita a
// archivos que YA están modificados.
var suspiciousFragments = []string{
	"eval(", "base64_decode", "system(", "exec(", "shell_exec", "passthru",
	"assert(", "$_POST", "$_GET", "$_REQUEST", "$_COOKIE", "gzinflate",
	"str_rot13", "create_function", "preg_replace_callback", "call_user_func",
}

// DiffText computa hunks entre el contenido original del baseline y el
// observado (FR-031), y clasifica si lo añadido parece inyección de código.
func DiffText(original, observed []byte) DiffResult {
	a, b := string(original), string(observed)
	edits := myers.ComputeEdits(span.URIFromPath("baseline"), a, b)
	unified := gotextdiff.ToUnified("baseline", "observed", a, edits)

	res := DiffResult{TotalLines: strings.Count(b, "\n") + 1}
	for _, h := range unified.Hunks {
		hunk := Hunk{FromLine: h.ToLine, ToLine: h.ToLine}
		line := h.ToLine
		for _, l := range h.Lines {
			switch l.Kind {
			case gotextdiff.Insert:
				content := strings.TrimRight(l.Content, "\n")
				hunk.Added = append(hunk.Added, content)
				res.LinesAdded++
				hunk.ToLine = line
				line++
				if isSuspicious(content) {
					res.Injection = true
				}
			case gotextdiff.Delete:
				hunk.Removed = append(hunk.Removed, strings.TrimRight(l.Content, "\n"))
				res.LinesRemoved++
			default:
				line++
			}
		}
		if hunk.ToLine < hunk.FromLine {
			hunk.ToLine = hunk.FromLine
		}
		res.Hunks = append(res.Hunks, hunk)
	}
	return res
}

func isSuspicious(line string) bool {
	l := strings.ToLower(line)
	for _, s := range suspiciousFragments {
		if strings.Contains(l, s) {
			return true
		}
	}
	return false
}

// Degree devuelve el grado de divergencia [0,1].
func (r DiffResult) Degree() float64 {
	if r.TotalLines == 0 {
		return 1
	}
	d := float64(r.LinesAdded+r.LinesRemoved) / float64(r.TotalLines)
	if d > 1 {
		d = 1
	}
	return d
}

// IsTextType decide si un tipo MIME admite diff de líneas.
func IsTextType(magic string) bool {
	return strings.HasPrefix(magic, "text/") ||
		strings.Contains(magic, "javascript") ||
		strings.Contains(magic, "json") ||
		strings.Contains(magic, "xml") ||
		strings.Contains(magic, "x-php")
}
