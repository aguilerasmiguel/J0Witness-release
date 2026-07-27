package dbscan

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"j0witness/internal/extmap"
	"j0witness/internal/manifest"
	"j0witness/internal/observe"
)

// noDir es un oráculo de presencia que niega toda existencia de directorio
// (nada en disco): con él, la presencia solo puede provenir de diskExts (la
// anotación de correlación de terceros), aislando esos casos del oráculo de
// Fix A.
func noDir(string) bool { return false }

// dirSetOracle construye un oráculo dirExists a partir de un conjunto de
// directorios existentes (Fix A): rel existe si está en el conjunto.
func dirSetOracle(dirs ...string) func(string) bool {
	set := map[string]bool{}
	for _, d := range dirs {
		set[d] = true
	}
	return func(rel string) bool { return set[rel] }
}

func TestAnalyzePrivilegedAnomaly(t *testing.T) {
	// Cohorte: 25 usuarios en 2020; uno privilegiado plantado en 2023 (outlier).
	d := Dump{Prefix: "j_", Groups: []GroupRow{{ID: 8, Title: "Super Users"}}}
	for i := int64(1); i <= 25; i++ {
		d.Users = append(d.Users, UserRow{ID: i, Username: "u", RegisterNS: parseMySQLDatetime("2020-01-01 00:00:00")})
	}
	d.Users = append(d.Users, UserRow{ID: 99, Username: "root2", RegisterNS: parseMySQLDatetime("2023-05-05 00:00:00")})
	d.Memberships = []MembershipRow{{UserID: 99, GroupID: 8}}
	obs, sum := Analyze(d, nil, noDir, "administrator", 1)
	var got int
	for _, o := range obs {
		if o.Type == observe.DBPrivilegedAnomaly {
			got++
		}
	}
	if got != 1 {
		t.Fatalf("esperaba 1 anomalía privilegiada, got %d", got)
	}
	if len(sum.PrivilegedRoster) != 1 || sum.PrivilegedRoster[0] != "root2" {
		t.Errorf("roster = %v", sum.PrivilegedRoster)
	}
}

func TestAnalyzeLegitPrivilegedNoFinding(t *testing.T) {
	// Un único Super User, registrado dentro de la cohorte, flags coherentes → 0.
	d := Dump{Prefix: "j_", Groups: []GroupRow{{ID: 8, Title: "Super Users"}},
		Users:       []UserRow{{ID: 1, Username: "admin", RegisterNS: parseMySQLDatetime("2020-01-01 00:00:00")}},
		Memberships: []MembershipRow{{UserID: 1, GroupID: 8}}}
	obs, _ := Analyze(d, nil, noDir, "administrator", 1)
	for _, o := range obs {
		if o.Type == observe.DBPrivilegedAnomaly {
			t.Fatal("un Super User legítimo NO debe generar hallazgo (Principio VI)")
		}
	}
}

func TestAnalyzeCohortActiveNoFinding(t *testing.T) {
	// Cohorte REAL de 25 usuarios (>= minFilesForCohort, a diferencia de
	// TestAnalyzeLegitPrivilegedNoFinding, que con 1 solo usuario ni siquiera
	// llega a evaluar registerCohortUpperBound): el Super User privilegiado
	// está DENTRO de la cohorte (mismo instante de registro que el resto,
	// nunca tras un hueco) y con flags coherentes → 0 hallazgos.
	d := Dump{Prefix: "j_", Groups: []GroupRow{{ID: 8, Title: "Super Users"}}}
	for i := int64(1); i <= 24; i++ {
		d.Users = append(d.Users, UserRow{ID: i, Username: "u", RegisterNS: parseMySQLDatetime("2020-01-01 00:00:00")})
	}
	d.Users = append(d.Users, UserRow{ID: 25, Username: "admin", RegisterNS: parseMySQLDatetime("2020-01-01 00:00:00")})
	d.Memberships = []MembershipRow{{UserID: 25, GroupID: 8}}
	obs, _ := Analyze(d, nil, noDir, "administrator", 1)
	for _, o := range obs {
		if o.Type == observe.DBPrivilegedAnomaly {
			t.Fatalf("Super User dentro de la cohorte con flags coherentes NO debe generar hallazgo: %+v", o)
		}
	}
}

func TestAnalyzeMassLateCohortNoFinding(t *testing.T) {
	// Finding 1: 20 usuarios en 2018 + un lote legítimo de 10 registrados
	// juntos en 2021 (33% de la población: p.ej. relanzamiento del sitio, no
	// plantados). Uno de ese lote tardío es un Super User genuinamente
	// promovido, con flags coherentes. Existe un hueco >30 días, pero la
	// cola es demasiado grande (> maxOutlierFrac) para tratarse como
	// outliers: registerCohortUpperBound debe devolver 0 y no afirmar
	// register_outlier.
	d := Dump{Prefix: "j_", Groups: []GroupRow{{ID: 8, Title: "Super Users"}}}
	for i := int64(1); i <= 20; i++ {
		d.Users = append(d.Users, UserRow{ID: i, Username: "u2018", RegisterNS: parseMySQLDatetime("2018-01-01 00:00:00")})
	}
	for i := int64(21); i <= 30; i++ {
		d.Users = append(d.Users, UserRow{ID: i, Username: "u2021", RegisterNS: parseMySQLDatetime("2021-06-01 00:00:00")})
	}
	d.Memberships = []MembershipRow{{UserID: 25, GroupID: 8}}
	obs, _ := Analyze(d, nil, noDir, "administrator", 1)
	for _, o := range obs {
		if o.Type == observe.DBPrivilegedAnomaly {
			t.Fatalf("lote tardío legítimo (33%% de la población) NO debe tratarse como outlier: %+v", o)
		}
	}
}

func TestAnalyzeNullActivationNoFinding(t *testing.T) {
	// Finding 2: activation con el literal SQL desnudo NULL, tal y como
	// unquote() (parse.go) lo deja pasar sin comillas: la cadena Go "NULL",
	// no "". Cuenta activa (Block=0) y coherente → NO debe disparar
	// incoherent_flags.
	d := Dump{Prefix: "j_", Groups: []GroupRow{{ID: 8, Title: "Super Users"}},
		Users: []UserRow{{ID: 1, Username: "admin", Block: 0, Activation: "NULL",
			RegisterNS: parseMySQLDatetime("2020-01-01 00:00:00")}},
		Memberships: []MembershipRow{{UserID: 1, GroupID: 8}}}
	obs, _ := Analyze(d, nil, noDir, "administrator", 1)
	for _, o := range obs {
		if o.Type == observe.DBPrivilegedAnomaly {
			t.Fatalf("activation NULL literal no debe interpretarse como token pendiente: %+v", o)
		}
	}
}

func TestAnalyzeExtensionOrphan(t *testing.T) {
	d := Dump{Prefix: "j_", Extensions: []ExtRow{
		{ExtensionID: 1, Element: "com_ghost", Type: "component", Enabled: 1},
		{ExtensionID: 2, Element: "com_real", Type: "component", Enabled: 1},
	}}
	disk := []extmap.Extension{{ElementKey: "com_real"}}
	obs, _ := Analyze(d, disk, noDir, "administrator", 1)
	var orphans []string
	for _, o := range obs {
		if o.Type == observe.DBExtensionState {
			var ev map[string]any
			_ = json.Unmarshal([]byte(o.EvidenceJSON), &ev)
			if ev["present_on_disk"] == false {
				orphans = append(orphans, ev["element"].(string))
			}
		}
	}
	if len(orphans) != 1 || orphans[0] != "com_ghost" {
		t.Fatalf("esperaba com_ghost huérfana, got %v", orphans)
	}
}

// TestAnalyzeExtensionDiskPaths cubre la resolución del controlador (Task 3):
// una extensión activa en BD y presente en disco lleva sus raíces de disco en
// la evidencia (fuente del join path→element para la correlación cruzada de
// internal/finding); una huérfana (ausente en disco) no lleva disk_paths.
func TestAnalyzeExtensionDiskPaths(t *testing.T) {
	d := Dump{Prefix: "j_", Extensions: []ExtRow{
		{ExtensionID: 1, Element: "com_ghost", Type: "component", Enabled: 1},
		{ExtensionID: 2, Element: "com_real", Type: "component", Enabled: 1},
	}}
	disk := []extmap.Extension{{
		ElementKey: "com_real",
		Layout:     manifest.Layout{Roots: []string{"administrator/components/com_real", "components/com_real"}},
	}}
	obs, _ := Analyze(d, disk, noDir, "administrator", 1)
	seen := map[string]bool{}
	for _, o := range obs {
		if o.Type != observe.DBExtensionState {
			continue
		}
		var ev map[string]any
		_ = json.Unmarshal([]byte(o.EvidenceJSON), &ev)
		element, _ := ev["element"].(string)
		seen[element] = true
		switch element {
		case "com_real":
			paths, ok := ev["disk_paths"].([]any)
			if !ok || len(paths) != 2 || paths[0] != "administrator/components/com_real" || paths[1] != "components/com_real" {
				t.Fatalf("com_real (presente en disco) esperaba disk_paths con las raíces, got %v", ev["disk_paths"])
			}
		case "com_ghost":
			if _, present := ev["disk_paths"]; present {
				t.Fatalf("com_ghost (huérfana) no debe llevar disk_paths, got %v", ev["disk_paths"])
			}
		}
	}
	if !seen["com_real"] || !seen["com_ghost"] {
		t.Fatalf("faltan observaciones esperadas: %v", seen)
	}
}

func TestAnalyzeModulePayload(t *testing.T) {
	d := Dump{Prefix: "j_", Modules: []ModuleRow{
		{ID: 5, Title: "Custom", Module: "mod_custom", Content: "<?php eval(base64_decode($_POST[0])); ?>", Published: 1},
		{ID: 6, Title: "Banner", Module: "mod_custom", Content: "<p>hola</p>", Published: 1},
	}}
	obs, _ := Analyze(d, nil, noDir, "administrator", 1)
	var got int
	for _, o := range obs {
		if o.Type == observe.DBContentPayload {
			got++
		}
	}
	if got != 1 {
		t.Fatalf("esperaba 1 payload, got %d", got)
	}
}

func TestAnalyzeRedactsSecrets(t *testing.T) {
	d := Dump{Prefix: "j_", Modules: []ModuleRow{
		{ID: 1, Module: "mod_custom", Content: "<?php $k='$2y$10$SECRETHASH'; eval($_POST[0]); ?>"}}}
	obs, _ := Analyze(d, nil, noDir, "administrator", 1)
	for _, o := range obs {
		if strings.Contains(o.EvidenceJSON, "SECRETHASH") {
			t.Fatal("el hash sembrado no debe aparecer en la evidencia (FR-047)")
		}
	}
}

// --- Finding C1 (review final): guarda de protegidas + join con forma ---

// dbExtensionStateEvents extrae (element -> present_on_disk) de las
// observaciones db_extension_state emitidas, para inspección compacta en los
// tests de abajo.
func dbExtensionStateEvents(obs []observe.Observation) map[string]bool {
	out := map[string]bool{}
	for _, o := range obs {
		if o.Type != observe.DBExtensionState {
			continue
		}
		var ev map[string]any
		_ = json.Unmarshal([]byte(o.EvidenceJSON), &ev)
		element, _ := ev["element"].(string)
		present, _ := ev["present_on_disk"].(bool)
		out[element] = present
	}
	return out
}

// TestAnalyzeProtectedNeverOrphan cubre el caso (a) del Finding C1: una
// extensión CORE (protected=1) jamás se afirma huérfana, esté o no presente
// en diskExts (que por diseño excluye el core-bundled — extmap.Discover). Se
// cubren ambos sub-casos: protegida ausente del mapa de disco (el caso común:
// el core ni siquiera aparece en diskExts) y protegida que sí aparece (raro,
// pero tampoco debe tratarse como huérfana si por algún motivo faltara).
func TestAnalyzeProtectedNeverOrphan(t *testing.T) {
	d := Dump{Prefix: "j_", Extensions: []ExtRow{
		// Plugin core (system/joomla): protegido, AUSENTE de diskExts porque
		// extmap.Discover excluye el core-bundled por completo.
		{ExtensionID: 1, Element: "joomla", Type: "plugin", Folder: "system", Enabled: 1, Protected: 1},
		// Componente core (com_content): mismo caso.
		{ExtensionID: 2, Element: "com_content", Type: "component", Enabled: 1, Protected: 1},
		// Protegida que además SÍ aparece en diskExts (edge case): tampoco debe
		// generar una entrada present_on_disk=false en ningún momento.
		{ExtensionID: 3, Element: "protected_present", Type: "component", Enabled: 1, Protected: 1},
	}}
	disk := []extmap.Extension{{ElementKey: "protected_present"}}
	obs, _ := Analyze(d, disk, noDir, "administrator", 1)
	events := dbExtensionStateEvents(obs)
	for element, present := range events {
		if !present {
			t.Fatalf("extensión protegida (%q) NO debe afirmarse huérfana (Principio VI): %v", element, events)
		}
	}
	if _, ok := events["joomla"]; ok {
		t.Errorf("el plugin core ausente no debe emitir NINGUNA observación (ni siquiera present_on_disk=true falso): %v", events)
	}
	if _, ok := events["com_content"]; ok {
		t.Errorf("el componente core ausente no debe emitir NINGUNA observación: %v", events)
	}
}

// TestAnalyzeThirdPartyPluginShapedKeyJoins cubre el caso (b): un plugin de
// terceros (protected=0) cuya clave de disco lleva forma "folder/element"
// (extmap.Extension.ElementKey, vía manifest.ExtensionKey) debe encontrar su
// contraparte cuando la BD aporta folder+element — el `element` desnudo de BD
// NUNCA debía compararse directamente contra esa clave con forma.
func TestAnalyzeThirdPartyPluginShapedKeyJoins(t *testing.T) {
	d := Dump{Prefix: "j_", Extensions: []ExtRow{
		{ExtensionID: 10, Element: "myplugin", Type: "plugin", Folder: "content", Enabled: 1, Protected: 0},
	}}
	disk := []extmap.Extension{{ElementKey: "content/myplugin"}}
	obs, _ := Analyze(d, disk, noDir, "administrator", 1)
	events := dbExtensionStateEvents(obs)
	present, ok := events["myplugin"]
	if !ok {
		t.Fatalf("esperaba una observación db_extension_state para myplugin: %v", events)
	}
	if !present {
		t.Fatalf("plugin de terceros presente en disco (clave con forma folder/element) no debe marcarse huérfano: %v", events)
	}
}

// TestAnalyzeThirdPartyAdminModuleShapedKeyJoins cubre el caso (c): un módulo
// de administración (client_id=1) de terceros debe unirse contra la clave con
// forma "element@administrator".
func TestAnalyzeThirdPartyAdminModuleShapedKeyJoins(t *testing.T) {
	d := Dump{Prefix: "j_", Extensions: []ExtRow{
		{ExtensionID: 11, Element: "mod_custom_admin", Type: "module", ClientID: 1, Enabled: 1, Protected: 0},
	}}
	disk := []extmap.Extension{{ElementKey: "mod_custom_admin@administrator"}}
	obs, _ := Analyze(d, disk, noDir, "administrator", 1)
	events := dbExtensionStateEvents(obs)
	present, ok := events["mod_custom_admin"]
	if !ok {
		t.Fatalf("esperaba una observación db_extension_state para mod_custom_admin: %v", events)
	}
	if !present {
		t.Fatalf("módulo admin de terceros presente en disco (clave con forma element@administrator) no debe marcarse huérfano: %v", events)
	}
}

// TestAnalyzeGenuineThirdPartyOrphan es el caso POSITIVO exigido junto a (a)-(c):
// una extensión de terceros no protegida, con clave con forma, genuinamente
// ausente de disco → exactamente una observación J0W-DB-002-elegible
// (present_on_disk=false). Mezcla los tres tipos (component/plugin/módulo
// admin) en el mismo dump para probar que el guarda + el join con forma
// conviven sin generar ruido cruzado.
func TestAnalyzeGenuineThirdPartyOrphan(t *testing.T) {
	d := Dump{Prefix: "j_", Extensions: []ExtRow{
		{ExtensionID: 20, Element: "com_ghost", Type: "component", Enabled: 1, Protected: 0},
		{ExtensionID: 21, Element: "myplugin", Type: "plugin", Folder: "content", Enabled: 1, Protected: 0},
		{ExtensionID: 22, Element: "mod_custom_admin", Type: "module", ClientID: 1, Enabled: 1, Protected: 0},
		{ExtensionID: 23, Element: "joomla", Type: "plugin", Folder: "system", Enabled: 1, Protected: 1},
	}}
	disk := []extmap.Extension{
		{ElementKey: "content/myplugin"},
		{ElementKey: "mod_custom_admin@administrator"},
	}
	obs, _ := Analyze(d, disk, noDir, "administrator", 1)
	var orphans []string
	for _, o := range obs {
		if o.Type != observe.DBExtensionState {
			continue
		}
		var ev map[string]any
		_ = json.Unmarshal([]byte(o.EvidenceJSON), &ev)
		if ev["present_on_disk"] == false {
			orphans = append(orphans, ev["element"].(string))
		}
	}
	if len(orphans) != 1 || orphans[0] != "com_ghost" {
		t.Fatalf("esperaba exactamente 1 huérfana genuina (com_ghost), got %v", orphans)
	}
}

// --- Finding I1 (review final): incoherent_flags eliminado ---

// TestAnalyzeBlockZeroWithActivationNoFinding cubre el reseteo de contraseña
// legítimo: Joomla reutiliza #__users.activation para el token de reseteo y
// NO bloquea la cuenta durante el proceso. block=0 + activation poblado (sin
// outlier de cohorte) ya NO debe producir ninguna observación (antes disparaba
// "incoherent_flags", un falso positivo estructural sobre el flujo normal de
// "olvidé mi contraseña").
func TestAnalyzeBlockZeroWithActivationNoFinding(t *testing.T) {
	d := Dump{Prefix: "j_", Groups: []GroupRow{{ID: 8, Title: "Super Users"}},
		Users: []UserRow{{ID: 1, Username: "admin", Block: 0, Activation: "reset-token-abc123",
			RegisterNS: parseMySQLDatetime("2020-01-01 00:00:00")}},
		Memberships: []MembershipRow{{UserID: 1, GroupID: 8}}}
	obs, _ := Analyze(d, nil, noDir, "administrator", 1)
	for _, o := range obs {
		if o.Type == observe.DBPrivilegedAnomaly {
			t.Fatalf("block=0 con activation poblado (reseteo de contraseña legítimo) no debe generar hallazgo (Finding I1): %+v", o)
		}
	}
}

// --- Finding M1 (review final): dump ambiguo se degrada, no adivina ---

// TestAnalyzeAmbiguousEmitsNoObservations cubre M1: cuando Parse marcó
// d.Ambiguous (>1 prefijo candidato, posibles dos instalaciones mezcladas en
// el mismo dump), Analyze NO debe emitir NINGUNA observación de las tres
// clases — los joins (usuario↔grupo, elemento↔disco) sobre filas mezcladas
// serían una adivinanza, no una correlación. Solo el resumen (con
// Ambiguous=true) sale.
func TestAnalyzeAmbiguousEmitsNoObservations(t *testing.T) {
	d := Dump{
		Prefix:    "a_",
		Ambiguous: true,
		Groups:    []GroupRow{{ID: 8, Title: "Super Users"}},
		Users: []UserRow{
			{ID: 99, Username: "root2", RegisterNS: parseMySQLDatetime("2023-05-05 00:00:00")},
		},
		Memberships: []MembershipRow{{UserID: 99, GroupID: 8}},
		Extensions:  []ExtRow{{ExtensionID: 1, Element: "com_ghost", Type: "component", Enabled: 1}},
		Modules: []ModuleRow{
			{ID: 5, Module: "mod_custom", Content: "<?php eval(base64_decode($_POST[0])); ?>"},
		},
	}
	obs, sum := Analyze(d, nil, noDir, "administrator", 1)
	if len(obs) != 0 {
		t.Fatalf("dump ambiguo NO debe emitir ninguna observación de BD, got %d: %+v", len(obs), obs)
	}
	if !sum.Ambiguous {
		t.Fatal("sum.Ambiguous debe seguir en true (coverage.database debe registrarlo)")
	}
}

// --- Finding M2 (review final): redacción de hash hex crudo y email ---

// TestAnalyzeRedactsHexHashAndEmail siembra un hash MD5 crudo (32 hex, sin
// prefijo $2y$/$1$) y un email tanto en el content como en el title de un
// módulo sospechoso; ninguno de los dos debe sobrevivir a la evidencia
// persistida (diseño §7 / FR-047, ampliado más allá del hash-con-prefijo y
// el centinela ya cubiertos).
func TestAnalyzeRedactsHexHashAndEmail(t *testing.T) {
	const rawHash = "5f4dcc3b5aa765d61d8327deb882cf99aabbccdd" // 40 hex (sha1-like), sin prefijo de esquema
	const email = "attacker@evil-example.com"
	d := Dump{Prefix: "j_", Modules: []ModuleRow{
		{ID: 1, Module: "mod_custom",
			Title:   "contact " + email + " hash=" + rawHash,
			Content: "<?php $h='" + rawHash + "'; $e='" + email + "'; eval(base64_decode($_POST[0])); ?>"},
	}}
	obs, _ := Analyze(d, nil, noDir, "administrator", 1)
	if len(obs) == 0 {
		t.Fatal("setup: el módulo debía marcarse sospechoso (contiene eval/base64_decode)")
	}
	for _, o := range obs {
		if strings.Contains(o.EvidenceJSON, rawHash) {
			t.Fatalf("el hash hex crudo no debe aparecer en la evidencia (Finding M2): %s", o.EvidenceJSON)
		}
		if strings.Contains(o.EvidenceJSON, email) {
			t.Fatalf("el email no debe aparecer completo en la evidencia (Finding M2): %s", o.EvidenceJSON)
		}
		if strings.Contains(o.EvidenceJSON, "attacker@") {
			t.Fatalf("la parte local del email no debe sobrevivir, solo el dominio (Finding M2): %s", o.EvidenceJSON)
		}
	}
}

// --- Fix A (presencia real en disco incluye core) ---

// TestAnalyzeCoreComponentPresentNotOrphan: com_banners es core removible
// (protected=0), por diseño EXCLUIDO de diskExts (extmap.Discover), pero su
// directorio EXISTE en el disco → presente, NO huérfana. Antes del Fix A este
// era el falso positivo principal del gate de dump real.
func TestAnalyzeCoreComponentPresentNotOrphan(t *testing.T) {
	d := Dump{Prefix: "j_", Extensions: []ExtRow{
		{ExtensionID: 1, Element: "com_banners", Type: "component", Enabled: 1, Protected: 0},
	}}
	obs, _ := Analyze(d, nil, dirSetOracle("administrator/components/com_banners"), "administrator", 1)
	present, ok := dbExtensionStateEvents(obs)["com_banners"]
	if !ok || !present {
		t.Fatalf("com_banners core presente en disco NO debe marcarse huérfana (Fix A): %v", dbExtensionStateEvents(obs))
	}
}

// TestAnalyzeGenuinelyAbsentComponentOrphan: un componente localizable cuyo
// directorio NO existe en ningún candidato → huérfana genuina (present=false).
func TestAnalyzeGenuinelyAbsentComponentOrphan(t *testing.T) {
	d := Dump{Prefix: "j_", Extensions: []ExtRow{
		{ExtensionID: 1, Element: "com_absent", Type: "component", Enabled: 1, Protected: 0},
	}}
	obs, _ := Analyze(d, nil, noDir, "administrator", 1)
	present, ok := dbExtensionStateEvents(obs)["com_absent"]
	if !ok || present {
		t.Fatalf("com_absent (dir ausente) debe marcarse huérfana: %v", dbExtensionStateEvents(obs))
	}
}

// TestAnalyzeAdminModulePresentViaAdminDir: un módulo de administración
// (client_id=1) presente vía <adminDir>/modules/<element> → presente, no
// huérfana (Fix A, mapeo por tipo con client_id).
func TestAnalyzeAdminModulePresentViaAdminDir(t *testing.T) {
	d := Dump{Prefix: "j_", Extensions: []ExtRow{
		{ExtensionID: 1, Element: "mod_stats", Type: "module", ClientID: 1, Enabled: 1, Protected: 0},
	}}
	obs, _ := Analyze(d, nil, dirSetOracle("administrator/modules/mod_stats"), "administrator", 1)
	present, ok := dbExtensionStateEvents(obs)["mod_stats"]
	if !ok || !present {
		t.Fatalf("módulo admin presente vía administrator/modules NO debe marcarse huérfana: %v", dbExtensionStateEvents(obs))
	}
}

// TestAnalyzeUnknownTypeNeverOrphan: los tipos no localizables (file/language/
// package/otros) tienen presencia DESCONOCIDA → jamás huérfana, aunque estén
// ausentes de todo (Principio VI: degradar hacia el silencio, no fabricar).
func TestAnalyzeUnknownTypeNeverOrphan(t *testing.T) {
	d := Dump{Prefix: "j_", Extensions: []ExtRow{
		{ExtensionID: 1, Element: "joomla", Type: "file", Enabled: 1, Protected: 0},
		{ExtensionID: 2, Element: "en-GB", Type: "language", Enabled: 1, Protected: 0},
	}}
	obs, _ := Analyze(d, nil, noDir, "administrator", 1)
	if events := dbExtensionStateEvents(obs); len(events) != 0 {
		t.Fatalf("tipos no localizables no deben emitir NINGUNA observación de estado: %v", events)
	}
}

// --- Fix B (guarda de correspondencia dump↔disco) ---

// TestAnalyzeCorrespondenceMismatch: con población suficiente (>=10) y más del
// 30% de las extensiones habilitadas/no-protegidas/localizables ausentes del
// disco, el dump no corresponde a este árbol → CERO Clase 2 + Correspondence=
// mismatch. Las Clases 1 (usuarios) y 3 (payloads en módulos), independientes
// del disco, se conservan.
func TestAnalyzeCorrespondenceMismatch(t *testing.T) {
	d := Dump{Prefix: "j_", Groups: []GroupRow{{ID: 8, Title: "Super Users"}}}
	var presentDirs []string
	for i := 1; i <= 12; i++ {
		el := fmt.Sprintf("com_x%02d", i)
		d.Extensions = append(d.Extensions, ExtRow{ExtensionID: int64(i), Element: el, Type: "component", Enabled: 1, Protected: 0})
		if i <= 5 { // solo 5 de 12 presentes → 7 ausentes (0.58 > 0.30)
			presentDirs = append(presentDirs, "components/"+el)
		}
	}
	// Clase 3: un módulo con payload (independiente del disco).
	d.Modules = []ModuleRow{{ID: 1, Module: "mod_custom", Content: "<?php eval(base64_decode($_POST[0])); ?>"}}

	obs, sum := Analyze(d, nil, dirSetOracle(presentDirs...), "administrator", 1)
	for _, o := range obs {
		if o.Type == observe.DBExtensionState {
			t.Fatalf("mismatch debe suprimir TODA la Clase 2, got %s", o.EvidenceJSON)
		}
	}
	if sum.Correspondence != "mismatch" {
		t.Fatalf("Correspondence = %q, want mismatch", sum.Correspondence)
	}
	if sum.AbsentFraction < 0.5 {
		t.Errorf("AbsentFraction = %v, want >= 0.5", sum.AbsentFraction)
	}
	var payloads int
	for _, o := range obs {
		if o.Type == observe.DBContentPayload {
			payloads++
		}
	}
	if payloads != 1 {
		t.Errorf("la Clase 3 (payload de módulo) es independiente del disco y debe conservarse: got %d", payloads)
	}
}

// TestAnalyzeCorrespondenceOKGenuineOrphan: un dump que SÍ corresponde
// (fracción ausente baja, población >=10) no declara salvedad y una huérfana
// genuina se sigue emitiendo.
func TestAnalyzeCorrespondenceOKGenuineOrphan(t *testing.T) {
	d := Dump{Prefix: "j_"}
	var presentDirs []string
	for i := 1; i <= 10; i++ {
		el := fmt.Sprintf("com_ok%02d", i)
		d.Extensions = append(d.Extensions, ExtRow{ExtensionID: int64(i), Element: el, Type: "component", Enabled: 1})
		presentDirs = append(presentDirs, "components/"+el)
	}
	d.Extensions = append(d.Extensions, ExtRow{ExtensionID: 99, Element: "com_ghost", Type: "component", Enabled: 1})

	obs, sum := Analyze(d, nil, dirSetOracle(presentDirs...), "administrator", 1)
	if sum.Correspondence != "" {
		t.Fatalf("Correspondence = %q, want vacío (el dump corresponde)", sum.Correspondence)
	}
	var orphans []string
	for element, present := range dbExtensionStateEvents(obs) {
		if !present {
			orphans = append(orphans, element)
		}
	}
	if len(orphans) != 1 || orphans[0] != "com_ghost" {
		t.Fatalf("esperaba exactamente 1 huérfana genuina (com_ghost), got %v", orphans)
	}
}

// TestAnalyzeAdminExtensionResolvesCanonicalInventory blinda el fix de review:
// el oráculo dirExists SIEMPRE se respalda en el inventario canonicalizado
// (acquire.go canonicaliza RelPath a administrator/… aunque el árbol traiga el
// admin renombrado), así que extInstallDirs DEBE resolver contra el
// "administrator" canónico. Con el admin dir canónico, una extensión admin-side
// (client_id=1, protected=0) presente en el inventario canónico → present,
// nunca huérfana. El sub-caso demuestra el modo de fallo: pasar el nombre
// renombrado crudo (p.ej. "adm1ng") contra el MISMO inventario canónico
// marcaría la extensión ausente en falso (el FP de sitios con admin renombrado
// que motivó el fix); por eso scan.go pasa "administrator" incondicionalmente.
func TestAnalyzeAdminExtensionResolvesCanonicalInventory(t *testing.T) {
	d := Dump{Prefix: "j_", Extensions: []ExtRow{
		{ExtensionID: 1, Element: "mod_admin_x", Type: "module", ClientID: 1, Enabled: 1, Protected: 0},
	}}
	// Inventario canónico: solo la ruta administrator/… existe.
	canonical := dirSetOracle("administrator/modules/mod_admin_x")

	// Con el admin dir canónico (lo que scan.go pasa): presente, no huérfana.
	obs, _ := Analyze(d, nil, canonical, "administrator", 1)
	if present, ok := dbExtensionStateEvents(obs)["mod_admin_x"]; !ok || !present {
		t.Fatalf("con adminDir canónico, la extensión admin-side debe resolver presente: %v", dbExtensionStateEvents(obs))
	}

	// Modo de fallo documentado: con un admin dir renombrado crudo contra el
	// MISMO inventario canónico, extInstallDirs busca adm1ng/modules/… que no
	// existe → present=false (huérfana en falso). Esto PRUEBA por qué scan.go
	// NO debe pasar app.Flags.AdminDir.
	obsBug, _ := Analyze(d, nil, canonical, "adm1ng", 1)
	if present, ok := dbExtensionStateEvents(obsBug)["mod_admin_x"]; !ok || present {
		t.Fatalf("sanity: con adminDir renombrado contra inventario canónico se esperaba el FP (present=false), got %v", dbExtensionStateEvents(obsBug))
	}
}
