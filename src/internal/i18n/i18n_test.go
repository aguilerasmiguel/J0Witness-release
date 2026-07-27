package i18n

import "strings"
import "testing"

func TestParse(t *testing.T) {
	for in, want := range map[string]Lang{"": ES, "es": ES, "en": EN} {
		got, err := Parse(in)
		if err != nil || got != want {
			t.Fatalf("Parse(%q)=%q,%v want %q", in, got, err, want)
		}
	}
	if _, err := Parse("fr"); err == nil {
		t.Fatalf("Parse(fr) debía error")
	}
}

func TestTResolvesAndInterpolates(t *testing.T) {
	// es verbatim (ancla de byte-identidad de un mensaje representativo).
	if got := T(ES, "core001.observed", nil); got != "archivo del core con contenido distinto al distribuido" {
		t.Fatalf("es core001.observed = %q", got)
	}
	if got := T(EN, "core001.observed", nil); got != "core file whose content differs from what is distributed" {
		t.Fatalf("en core001.observed = %q", got)
	}
	// interpolación de {clave}
	if got := T(ES, "ext001.observed", map[string]any{"ext": "com_foo"}); got != "ejecutable no declarado dentro del árbol de la extensión com_foo" {
		t.Fatalf("es ext001.observed = %q", got)
	}
	if got := T(ES, "compared.baseline", map[string]any{"version": "5.4.7"}); got != "distribución oficial 5.4.7" {
		t.Fatalf("es compared.baseline = %q", got)
	}
	if got := T(EN, "core003.collapsed.observed", map[string]any{"n": 12}); got != "a baseline subtree is entirely absent (12 files)" {
		t.Fatalf("en collapsed = %q", got)
	}
}

func TestUnknownIDFallsBackToID(t *testing.T) {
	if got := T(ES, "no.such.id", nil); got != "no.such.id" {
		t.Fatalf("fallback = %q", got)
	}
}

// TestCatalogComplete: cada mensaje tiene es y en no vacíos, y ninguna
// plantilla deja placeholders {..} sin sustituir cuando se le dan los params
// declarados (aquí: render con un set de params comodín amplio no debe dejar
// '{' en el resultado para los ids sin params; los ids con params se cubren
// arriba). Además es != en salvo que sea intencional (ids-código no hay aquí).
// TestChromeVerbParity ancla la regla de verbos del chrome (text./pdf.):
// para cada id con ese prefijo, "es" y "en" deben tener la misma secuencia de
// verbos fmt (%s/%d/%-10s… en el mismo orden), o fmt.Fprintf produce
// "%!s(MISSING)" cuando cambia el idioma.
func TestChromeVerbParity(t *testing.T) {
	verbs := func(s string) string {
		var out []byte
		for i := 0; i < len(s); i++ {
			if s[i] == '%' && i+1 < len(s) {
				j := i + 1
				for j < len(s) && strings.IndexByte("-+ #0123456789.", s[j]) >= 0 {
					j++
				}
				if j < len(s) {
					out = append(out, '%')
					out = append(out, s[j])
				}
				i = j
			}
		}
		return string(out)
	}
	for id, e := range messages {
		if strings.HasPrefix(id, "text.") || strings.HasPrefix(id, "pdf.") {
			if verbs(e.es) != verbs(e.en) {
				t.Errorf("%s: verbos es=%q en=%q", id, verbs(e.es), verbs(e.en))
			}
		}
	}
}

func TestCatalogComplete(t *testing.T) {
	// "nb" cubre pdf.footer: contiene el literal "{nb}", el sentinel propio de
	// fpdf.AliasNbPages (número total de páginas, sustituido por fpdf en
	// Output(), NO por i18n.T — en producción T se llama con params=nil ahí,
	// así que la sustitución de abajo nunca se ejecuta salvo en este test).
	wildcard := map[string]any{"version": "V", "ext": "E", "src": "S", "n": 0, "found": "F", "sink": "K", "trg": "T", "nb": "N", "directive": "D", "target": "TGT", "state": "ST", "days": 0, "element": "EL", "username": "U", "reasons": "R"}
	for id, e := range messages {
		if strings.TrimSpace(e.es) == "" || strings.TrimSpace(e.en) == "" {
			t.Errorf("%s: es/en vacío", id)
		}
		for _, lang := range []Lang{ES, EN} {
			if out := T(lang, id, wildcard); strings.Contains(out, "{") || strings.Contains(out, "}") {
				t.Errorf("%s[%s]: placeholder sin sustituir: %q", id, lang, out)
			}
		}
	}
}
