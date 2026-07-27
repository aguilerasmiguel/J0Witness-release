package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"j0witness/internal/corpus"
	"j0witness/internal/lab"
)

// TestScanReportsForeignRoots cubre feature 012 (Task 2, end-to-end):
// contenido de disco ajeno a la distribución de Joomla y a las extensiones
// registradas se agrega en coverage.foreign_roots, sin producir un hallazgo
// (cero severidad — es coverage, nunca un Finding).
func TestScanReportsForeignRoots(t *testing.T) {
	h := newHarness(t)

	// Replica scanCase (harness_test.go), pero inyecta la raíz ajena ANTES de
	// escanear: scanCase/scanCaseArgs no dan gancho para eso.
	r, err := corpus.Load(filepath.Join(recipesDir(t), "clean-minicms.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	// Directorio DISTINTO del que usa scanCase("clean-minicms") más abajo
	// (que materializa en "case-"+r.Case): Materialize no limpia el destino,
	// así que reusar el mismo dir dejaría "miapp" contaminando la comprobación
	// negativa (sitio limpio sin raíz ajena).
	target := filepath.Join(h.root, "case-"+r.Case+"-foreign")
	if err := r.Materialize(lab.MiniProvider{}, target); err != nil {
		t.Fatal(err)
	}
	h.cacheExtensionBaselines(t, r, target)

	miapp := filepath.Join(target, "miapp")
	if err := os.MkdirAll(miapp, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(miapp, "x.php"), []byte("<?php echo 1;"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(miapp, "y.css"), []byte("a{}"), 0o644); err != nil {
		t.Fatal(err)
	}

	args := append([]string{"scan", target}, r.ScanArgs...)
	exit, doc, stderr := h.run(t, args...)
	if exit > 1 {
		t.Fatalf("scan con raíz ajena falló: exit %d\nstderr: %s\ninforme: %s", exit, stderr, doc)
	}

	var rep struct {
		Coverage struct {
			ForeignRoots []struct {
				Root            string `json:"root"`
				Files           int    `json:"files"`
				Executables     int    `json:"executables"`
				Bytes           int64  `json:"bytes"`
				DistributionDir bool   `json:"distribution_dir"`
			} `json:"foreign_roots"`
		} `json:"coverage"`
	}
	if err := json.Unmarshal(doc, &rep); err != nil {
		t.Fatalf("informe no parsea: %v\n%s", err, doc)
	}

	var found bool
	for _, fr := range rep.Coverage.ForeignRoots {
		if fr.Root == "miapp" {
			found = true
			if fr.Files != 2 || fr.Executables != 1 {
				t.Errorf("miapp = %+v, quería files=2 executables=1", fr)
			}
			if fr.Bytes <= 0 {
				t.Errorf("miapp.bytes = %d, quería > 0 (sizeBySubject debe unir por SubjectDisplay)", fr.Bytes)
			}
			// "miapp" no existe en el manifiesto del baseline: raíz
			// genuinamente ajena, distribution_dir debe ser false.
			if fr.DistributionDir {
				t.Errorf("miapp.distribution_dir = true, quería false (raíz ausente del manifiesto): %+v", fr)
			}
		}
	}
	if !found {
		t.Fatalf("coverage.foreign_roots debe listar la raíz ajena 'miapp': %+v", rep.Coverage.ForeignRoots)
	}
	// La base minicms (lab.WriteTree) ya siembra images/banner.png — contenido
	// de usuario benigno fuera del core (Derive lo deja sin hallazgo: "return
	// nil // contenido de usuario fuera del core: cobertura, no hallazgo"),
	// exactamente el caso que foreign_roots existe para hacer visible. DEBE
	// seguir apareciendo junto a "miapp", ordenado ahora por DistributionDir
	// asc (miapp, ajena, primero) — "images" SÍ está en el manifiesto del
	// baseline (dir estándar de Joomla con contenido de usuario).
	if len(rep.Coverage.ForeignRoots) != 2 {
		t.Fatalf("coverage.foreign_roots = %+v, quería exactamente 2 raíces (miapp + images)", rep.Coverage.ForeignRoots)
	}
	if rep.Coverage.ForeignRoots[0].Root != "miapp" || rep.Coverage.ForeignRoots[1].Root != "images" {
		t.Errorf("orden = %+v, quería [miapp, images] (distribution_dir asc: ajena primero)", rep.Coverage.ForeignRoots)
	}
	if rep.Coverage.ForeignRoots[0].DistributionDir {
		t.Errorf("miapp.distribution_dir = true, quería false")
	}
	if !rep.Coverage.ForeignRoots[1].DistributionDir {
		t.Errorf("images.distribution_dir = false, quería true (dir estándar de la distribución)")
	}

	// Un hallazgo J0W-CORE-004 SÍ puede aparecer para el contenido ajeno no
	// atribuido (comportamiento pre-existente); lo que este test verifica es
	// que ADEMÁS aparezca en coverage — nunca que sustituya al hallazgo.

	// La base minicms limpia, SIN la raíz añadida, sigue declarando
	// foreign_roots — pero solo por el banner.png pre-existente ("images"),
	// nunca "miapp": omitempty únicamente se ejerce cuando NO hay contenido
	// ajeno alguno (internal/report/foreign_test.go: TestForeignRootsEmpty).
	_, cleanExit, cleanDoc, cleanStderr := h.scanCase(t, "clean-minicms")
	if cleanExit != 0 {
		t.Fatalf("clean-minicms: exit %d\nstderr: %s\ninforme: %s", cleanExit, cleanStderr, cleanDoc)
	}
	var cleanRep struct {
		Coverage struct {
			ForeignRoots []struct {
				Root string `json:"root"`
			} `json:"foreign_roots"`
		} `json:"coverage"`
	}
	if err := json.Unmarshal(cleanDoc, &cleanRep); err != nil {
		t.Fatal(err)
	}
	if len(cleanRep.Coverage.ForeignRoots) != 1 || cleanRep.Coverage.ForeignRoots[0].Root != "images" {
		t.Fatalf("clean-minicms (sin 'miapp') coverage.foreign_roots = %+v, quería solo [images]", cleanRep.Coverage.ForeignRoots)
	}
}
