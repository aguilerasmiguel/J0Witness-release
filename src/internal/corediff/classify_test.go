package corediff

import (
	"encoding/json"
	"j0witness/internal/inventory"
	"testing"

	"j0witness/internal/baseline"
)

// T025: divergencia solo-EOL vs modificación real.
func TestEOLOnly(t *testing.T) {
	lf := []byte("<?php\necho 1;\n")
	crlf := []byte("<?php\r\necho 1;\r\n")
	bom := append([]byte{0xEF, 0xBB, 0xBF}, lf...)
	modified := []byte("<?php\necho 2;\n")

	if !EOLOnly(lf, crlf) {
		t.Fatal("CRLF debe ser solo-EOL")
	}
	if !EOLOnly(lf, bom) {
		t.Fatal("BOM debe ser solo-EOL")
	}
	if EOLOnly(lf, modified) {
		t.Fatal("cambio de contenido clasificado como EOL")
	}
	if EOLOnly(lf, lf) {
		t.Fatal("idénticos no son 'solo EOL'")
	}
}

// T026: hunks, grado de divergencia y clasificación de inyección.
func TestDiffTextInjection(t *testing.T) {
	orig := []byte("<?php\ndefine('X', 1);\necho run();\n")
	inj := []byte("<?php\neval(base64_decode($_POST['x']));\ndefine('X', 1);\necho run();\n")
	d := DiffText(orig, inj)
	if !d.Injection {
		t.Fatal("inyección no clasificada")
	}
	if d.LinesAdded != 1 || len(d.Hunks) == 0 {
		t.Fatalf("hunks: %+v", d)
	}
	if d.Hunks[0].FromLine < 1 || d.Hunks[0].FromLine > 3 {
		t.Fatalf("rango de líneas fuera de lugar: %+v", d.Hunks[0])
	}

	benign := []byte("<?php\ndefine('X', 2);\necho run();\n")
	if DiffText(orig, benign).Injection {
		t.Fatal("cambio benigno clasificado como inyección")
	}
}

// T027 (R6): obsoleto con hash histórico vs obsoleto huérfano.
func TestCheckObsolete(t *testing.T) {
	known := map[string][]string{"libraries/legacy.php": {"aaa", "bbb"}}
	if got := CheckObsolete("libraries/legacy.php", "aaa", known); got != ObsoleteKnownHash {
		t.Fatalf("hash histórico: %v", got)
	}
	if got := CheckObsolete("libraries/legacy.php", "zzz", known); got != ObsoleteUnknownHash {
		t.Fatalf("hash desconocido: %v", got)
	}
	if got := CheckObsolete("otro.php", "aaa", known); got != NotObsolete {
		t.Fatalf("no listado: %v", got)
	}
}

// T028 (C5): la inspección estructural jamás captura valores.
func TestInspectConfigNeverCapturesValues(t *testing.T) {
	cfg := []byte("<?php\nclass JConfig {\n\tpublic $sitename = 'Mi Sitio';\n\tpublic $password = 'SUPERSECRETO123';\n\tpublic $secret = 'CLAVE_XYZ';\n}\n")
	s := InspectConfig(cfg)
	if !s.HasClass {
		t.Fatal("clase JConfig no detectada")
	}
	if len(s.KeysPresent) != 3 {
		t.Fatalf("claves: %v", s.KeysPresent)
	}
	if len(s.SensitiveSeen) != 2 {
		t.Fatalf("sensibles: %v", s.SensitiveSeen)
	}
	// La estructura serializada no puede contener ningún valor.
	for _, forbidden := range []string{"SUPERSECRETO123", "CLAVE_XYZ", "Mi Sitio"} {
		for _, k := range append(s.KeysPresent, s.Anomalies...) {
			if k == forbidden {
				t.Fatalf("valor capturado: %s", forbidden)
			}
		}
	}
}

func TestInspectConfigAnomalies(t *testing.T) {
	evil := []byte("<?php\nclass JConfig { public $sitename = 'x'; }\neval(base64_decode('...'));\n")
	s := InspectConfig(evil)
	if len(s.Anomalies) == 0 {
		t.Fatal("código ejecutable en configuration.php sin anomalía")
	}
	clean := []byte("<?php\nclass JConfig { public $sitename = 'x'; }\n")
	if s := InspectConfig(clean); len(s.Anomalies) != 0 {
		t.Fatalf("falso positivo en config limpia: %v", s.Anomalies)
	}
}

// installation/ ausente al completo → una sola observación esperada;
// parcialmente presente → cada ausencia cuenta.
func TestInstallerDirCollapse(t *testing.T) {
	manifest := map[string]baseline.ManifestEntry{
		"index.php":                {SHA256: "aa"},
		"installation/index.php":   {SHA256: "bb"},
		"installation/joomla.sql":  {SHA256: "cc"},
		"installation/LICENSE.txt": {SHA256: "dd"},
	}
	entries := entriesWith("index.php", "aa")

	res := Classify(Input{Entries: entries, Manifest: manifest, NowNS: 1})
	var collapsed, perFile int
	for _, o := range res.Observations {
		if o.Type != "file_missing" {
			continue
		}
		if o.SubjectDisplay == "installation" {
			collapsed++
		} else {
			perFile++
		}
	}
	if collapsed != 1 || perFile != 0 {
		t.Fatalf("ausencia total: collapsed=%d perFile=%d", collapsed, perFile)
	}

	// Parcialmente presente: los que faltan se reportan uno a uno.
	entries2 := append(entriesWith("index.php", "aa"), entriesWith("installation/index.php", "bb")...)
	res2 := Classify(Input{Entries: entries2, Manifest: manifest, NowNS: 1})
	perFile = 0
	for _, o := range res2.Observations {
		if o.Type == "file_missing" && o.SubjectDisplay != "installation" {
			perFile++
		}
	}
	if perFile != 2 {
		t.Fatalf("ausencia parcial: perFile=%d, esperaba 2", perFile)
	}
}

func entriesWith(path, sha string) []inventory.Entry {
	return []inventory.Entry{{RelPath: []byte(path), PathDisplay: path, Type: "file", SHA256: sha}}
}

// Finding 1 (revisión de rama D5): cuando el contenido original del baseline
// no está cacheado (in.Content == nil, fallback soportado por scan.go), la
// rama "sin contenido original o binario" de classifyModified se alcanza
// también para archivos de texto/markup del core modificados — no solo para
// binarios reales. La evidencia debe reflejar el tipo MIME real
// (!IsTextType), no un "binary: true" incondicional, o D5 (derive.go) degrada
// erróneamente CORE-001 de High a Low para un .js/.css/.html modificado.
func TestClassifyModifiedNoContentUsesMagicForBinaryFlag(t *testing.T) {
	manifest := map[string]baseline.ManifestEntry{
		"media/system/js/core.js": {SHA256: "aaa"},
	}
	entries := []inventory.Entry{{
		RelPath: []byte("media/system/js/core.js"), PathDisplay: "media/system/js/core.js",
		Type: "file", SHA256: "bbb", MagicType: "text/javascript",
	}}

	res := Classify(Input{Entries: entries, Manifest: manifest, Content: nil, NowNS: 1})

	var got *string
	for _, o := range res.Observations {
		if o.Type != "file_modified" {
			continue
		}
		var ev map[string]any
		if err := json.Unmarshal([]byte(o.EvidenceJSON), &ev); err != nil {
			t.Fatalf("evidencia no es JSON válido: %v", err)
		}
		bin, ok := ev["binary"].(bool)
		if !ok {
			t.Fatalf("evidencia sin campo binary: %s", o.EvidenceJSON)
		}
		if bin {
			t.Fatalf("un .js modificado sin contenido cacheado no debe marcarse binary=true (magic=text/javascript): %s", o.EvidenceJSON)
		}
		s := "ok"
		got = &s
	}
	if got == nil {
		t.Fatal("no se emitió observación file_modified")
	}
}

// T029 (FR-035): ejecutables en directorios de escritura.
func TestExecDir(t *testing.T) {
	if !IsExecutable("images/shell.php") || IsExecutable("images/foto.png") {
		t.Fatal("clasificación de ejecutables incorrecta")
	}
	if !InForbiddenExecDir("images/shell.php") || !InForbiddenExecDir("administrator/cache/x.php") {
		t.Fatal("directorios de escritura no detectados")
	}
	if InForbiddenExecDir("libraries/src/App.php") {
		t.Fatal("libraries/ no es directorio de escritura")
	}
}

func TestInCoreDir(t *testing.T) {
	core := coreDirs([]string{"libraries/src/App.php", "administrator/index.php", "media/js/app.js"})
	if !InCoreDir("libraries/extra.php", core) {
		t.Fatal("libraries/ es core")
	}
	if !InCoreDir("raiz.php", core) {
		t.Fatal("la raíz es territorio de la distribución")
	}
	if InCoreDir("images/foto.php", core) {
		t.Fatal("images/ no es core (es escritura)")
	}
	if InCoreDir("contenido-usuario/x.php", core) {
		t.Fatal("directorio no listado en el manifiesto no es core")
	}
}

// D5 Task 1: ancla la semántica de los predicados que classify.go usa para
// anotar executable/binary en la evidencia de FileModified/FileObsoleteKnown
// (derive.go, Task 2, los consume para degradar severidad de inertes).
func TestModifiedEvidenceHasExecutableAndBinary(t *testing.T) {
	// Un .php modificado (texto, ejecutable) y una imagen modificada (binaria,
	// inerte) deben llevar los flags correctos en la evidencia de FileModified.
	cases := []struct {
		rel        string
		magic      string
		executable bool
		binary     bool
	}{
		{"libraries/src/Router.php", "text/x-php", true, false},
		{"libraries/logo.gif", "image/gif", false, true},
	}
	for _, c := range cases {
		gotExec := IsExecutable(c.rel)
		gotBin := !IsTextType(c.magic)
		if gotExec != c.executable || gotBin != c.binary {
			t.Errorf("%s: executable=%v binary=%v, quiere %v/%v", c.rel, gotExec, gotBin, c.executable, c.binary)
		}
	}
}
