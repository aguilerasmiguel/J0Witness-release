package finding

import (
	"strings"
	"testing"

	"j0witness/internal/i18n"
	"j0witness/internal/observe"
)

func TestDeriveCodeFindings(t *testing.T) {
	mk := func(construct string) observe.Observation {
		o, _ := observe.New([]byte("x.php"), observe.CodeSuspicious, map[string]any{
			"construct": construct, "sink": "eval", "trigger": "base64_decode", "line": 3,
		}, observe.SrcCodescan, observe.High, 1)
		return o
	}
	cases := map[string]struct {
		rule string
		sev  Severity
	}{
		"obfuscated_eval": {"J0W-CODE-001", Critical},
		"input_to_sink":   {"J0W-CODE-002", Critical},
		"preg_e":          {"J0W-CODE-003", High},
	}
	for construct, want := range cases {
		fs := Derive([]observe.Observation{mk(construct)}, "5.4.7", map[string]bool{}, i18n.ES)
		if len(fs) != 1 || fs[0].RuleID != want.rule || fs[0].Severity != want.sev {
			t.Fatalf("%s → %+v (quiere %s %s)", construct, fs, want.rule, want.sev)
		}
		if fs[0].Alternative == "" {
			t.Errorf("%s: falta hipótesis alternativa (Principio V)", construct)
		}
	}
}

func TestDeriveDynamicCall(t *testing.T) {
	o, _ := observe.New([]byte("x.php"), observe.CodeSuspicious, map[string]any{
		"construct": "dynamic_call", "sink": "variable_function", "trigger": "$g", "line": 2, "via": "dataflow",
	}, observe.SrcCodescan, observe.High, 1)
	fs := Derive([]observe.Observation{o}, "5.4.7", map[string]bool{}, i18n.ES)
	if len(fs) != 1 || fs[0].RuleID != "J0W-CODE-004" || fs[0].Severity != Critical || fs[0].Alternative == "" {
		t.Fatalf("dynamic_call → %+v", fs)
	}
}

// derive1 corre Derive sobre una única observación y devuelve el único
// hallazgo producido (falla el test si no hay exactamente uno).
func derive1(t *testing.T, o observe.Observation) Finding {
	t.Helper()
	fs := Derive([]observe.Observation{o}, "1.1.0", map[string]bool{}, i18n.ES)
	if len(fs) != 1 {
		t.Fatalf("esperaba 1 hallazgo, hay %d: %+v", len(fs), fs)
	}
	return fs[0]
}

// TestDeriveExtVerification cubre la fase 2a: J0W-EXT-008 (modificado,
// sensible a ejecutable como D5), J0W-EXT-009 (ausente) y ext_file_verified
// (sin hallazgo — se refleja en cobertura).
func TestDeriveExtVerification(t *testing.T) {
	mk := func(typ observe.Type, ev map[string]any) observe.Observation {
		o, _ := observe.New([]byte("components/com_x/f.php"), typ, ev, observe.SrcExtmap, observe.High, 1)
		return o
	}
	// Ejecutable modificado → EXT-008 critical.
	f := derive1(t, mk(observe.ExtFileModified, map[string]any{"extension": "com_x", "verification_source": "package", "executable": true}))
	if f.RuleID != "J0W-EXT-008" || f.Severity != Critical {
		t.Fatalf("modificado exec: %+v", f)
	}
	if f.Alternative == "" {
		t.Errorf("EXT-008: falta hipótesis alternativa (Principio V)")
	}
	// Inerte modificado → EXT-008 low.
	f = derive1(t, mk(observe.ExtFileModified, map[string]any{"extension": "com_x", "verification_source": "package", "executable": false}))
	if f.Severity != Low {
		t.Fatalf("modificado inerte: %+v", f)
	}
	// Ausente → EXT-009 medium.
	f = derive1(t, mk(observe.ExtOfficialMissing, map[string]any{"extension": "com_x", "verification_source": "package"}))
	if f.RuleID != "J0W-EXT-009" || f.Severity != MediumS {
		t.Fatalf("ausente: %+v", f)
	}
	// Verificado → sin hallazgo (nil).
	if fs := Derive([]observe.Observation{mk(observe.ExtFileVerified, map[string]any{"extension": "com_x"})}, "1.1.0", map[string]bool{}, i18n.ES); len(fs) != 0 {
		t.Fatalf("verificado no debe generar hallazgo: %v", fs)
	}
}

func TestDeriveD5Degradation(t *testing.T) {
	mk := func(typ observe.Type, ev map[string]any) observe.Observation {
		o, _ := observe.New([]byte("x"), typ, ev, observe.SrcCorediff, observe.High, 1)
		return o
	}
	one := func(o observe.Observation) Finding {
		fs := Derive([]observe.Observation{o}, "1.1.0", map[string]bool{}, i18n.ES)
		if len(fs) != 1 {
			t.Fatalf("esperaba 1 hallazgo, hay %d", len(fs))
		}
		return fs[0]
	}
	// CORE-001 inerte (imagen modificada) → low, base high.
	f := one(mk(observe.FileModified, map[string]any{"degree": 1.0, "binary_or_no_content": true, "executable": false, "binary": true}))
	if f.RuleID != "J0W-CORE-001" || f.Severity != Low || f.BaseSeverity != High {
		t.Fatalf("CORE-001 inerte: %+v", f)
	}
	// CORE-001 ejecutable (.php modificado) → high, sin degradar.
	f = one(mk(observe.FileModified, map[string]any{"degree": 1.0, "executable": true, "binary": false}))
	if f.Severity != High {
		t.Fatalf("CORE-001 ejecutable no debe degradar: %+v", f)
	}
	// CORE-009 inerte (imagen huérfana) → low, base high.
	f = one(mk(observe.FileObsoleteKnown, map[string]any{"hash_matches_history": false, "executable": false, "binary": true}))
	if f.RuleID != "J0W-CORE-009" || f.Severity != Low || f.BaseSeverity != High {
		t.Fatalf("CORE-009 inerte: %+v", f)
	}
	// CORE-009 ejecutable (.php huérfano) → high.
	f = one(mk(observe.FileObsoleteKnown, map[string]any{"hash_matches_history": false, "executable": true, "binary": false}))
	if f.Severity != High {
		t.Fatalf("CORE-009 ejecutable no debe degradar: %+v", f)
	}
	// CORE-010 magic inerte (.jpg que es PNG) → info, base medium.
	f = one(mk(observe.TypeMismatch, map[string]any{"expected_for_extension": "image/jpeg", "magic": "image/png"}))
	if f.RuleID != "J0W-CORE-010" || f.Severity != Info || f.BaseSeverity != MediumS {
		t.Fatalf("CORE-010 magic inerte: %+v", f)
	}
	// CORE-010 magic peligroso (.gif que es PHP) → medium, sin degradar.
	f = one(mk(observe.TypeMismatch, map[string]any{"expected_for_extension": "image/gif", "magic": "text/x-php"}))
	if f.Severity != MediumS {
		t.Fatalf("CORE-010 magic script no debe degradar: %+v", f)
	}
	// CORE-010 magic image/png real (.jpg que es PNG) → sigue degradando a info
	// (control: el allowlist de imágenes inertes no se rompe).
	f = one(mk(observe.TypeMismatch, map[string]any{"expected_for_extension": "image/jpeg", "magic": "image/png"}))
	if f.Severity != Info {
		t.Fatalf("CORE-010 image/png debe seguir degradando a info: %+v", f)
	}
	f = one(mk(observe.TypeMismatch, map[string]any{"expected_for_extension": "image/jpeg", "magic": "image/gif"}))
	if f.Severity != Info {
		t.Fatalf("CORE-010 image/gif debe seguir degradando a info: %+v", f)
	}
	// Finding 2 (revisión de rama D5): image/svg+xml es contenido activo (SVG
	// admite <script>); isInertMagic no debe tratarlo como inerte solo por el
	// prefijo "image/". Un .png que en realidad es SVG debe quedarse en medium.
	f = one(mk(observe.TypeMismatch, map[string]any{"expected_for_extension": "image/png", "magic": "image/svg+xml"}))
	if f.RuleID != "J0W-CORE-010" || f.Severity != MediumS {
		t.Fatalf("CORE-010 SVG activo no debe degradarse a info: %+v", f)
	}
}

// TestDeriveLayoutRemap cubre la fase 2d (task 4): una observación
// layout_remap con remap_applied:false produce J0W-LAYOUT-001 en Low con
// hipótesis alternativa no vacía y rationale que sugiere --administrator-dir
// (Principio VII: declara el árbol renombrado/no reconocido en vez de fingir
// cobertura completa); con remap_applied:true no produce ningún hallazgo — el
// remapeo ya resuelve el árbol y queda declarado, no es un hallazgo.
func TestDeriveLayoutRemap(t *testing.T) {
	o, _ := observe.New(nil, observe.LayoutRemap, map[string]any{
		"admin_dir_found": "adm1ng", "remap_applied": false, "standard": false,
	}, observe.SrcAcquire, observe.High, 1)
	f := derive1(t, o)
	if f.RuleID != "J0W-LAYOUT-001" {
		t.Fatalf("RuleID = %q, quiere J0W-LAYOUT-001", f.RuleID)
	}
	if f.Severity != Low {
		t.Fatalf("Severity = %q, quiere low", f.Severity)
	}
	if f.Alternative == "" {
		t.Fatal("falta hipótesis alternativa (Principio V)")
	}
	if !strings.Contains(f.Observed, "adm1ng") {
		t.Fatalf("Observed no menciona el candidato encontrado: %q", f.Observed)
	}
	if !strings.Contains(f.Rationale, "--administrator-dir") {
		t.Fatalf("Rationale no sugiere --administrator-dir: %q", f.Rationale)
	}

	// Sin admin_dir_found (ningún candidato): el texto observado cambia pero
	// sigue siendo J0W-LAYOUT-001 low con alternativa no vacía.
	o2, _ := observe.New(nil, observe.LayoutRemap, map[string]any{
		"admin_dir_found": "", "remap_applied": false, "standard": false,
	}, observe.SrcAcquire, observe.High, 1)
	f2 := derive1(t, o2)
	if f2.RuleID != "J0W-LAYOUT-001" || f2.Severity != Low || f2.Alternative == "" {
		t.Fatalf("caso sin candidato: %+v", f2)
	}

	// remap_applied:true → remapeo aplicado y declarado: ningún hallazgo.
	o3, _ := observe.New(nil, observe.LayoutRemap, map[string]any{
		"admin_dir_found": "adm1ng", "remap_applied": true, "standard": false,
	}, observe.SrcAcquire, observe.High, 1)
	fs := Derive([]observe.Observation{o3}, "1.1.0", map[string]bool{}, i18n.ES)
	if len(fs) != 0 {
		t.Fatalf("remap_applied:true no debe producir hallazgos, hay %+v", fs)
	}
}

// TestDeriveMissingClassDegradation cubre D5b task 2: J0W-CORE-003 degrada
// por la clase de ausencia que classify.go computó (missing_class en la
// evidencia); executable/"" (desconocido) se quedan en medium, sin degradar;
// la rama expected_post_install (installation/ completo) no se toca.
func TestDeriveMissingClassDegradation(t *testing.T) {
	mk := func(ev map[string]any) observe.Observation {
		o, _ := observe.New([]byte("x"), observe.FileMissing, ev, observe.SrcCorediff, observe.High, 1)
		return o
	}
	one := func(o observe.Observation) Finding {
		fs := Derive([]observe.Observation{o}, "1.1.0", map[string]bool{}, i18n.ES)
		if len(fs) != 1 {
			t.Fatalf("esperaba 1 hallazgo, hay %d", len(fs))
		}
		return fs[0]
	}

	const genericRationale = "el ausente puede ser borrado hostil o instalación incompleta"

	// inert_asset → low, base medium; el rationale se ajusta por clase (no
	// se queda en el genérico "borrado hostil"), coherente con la severidad
	// reducida (Principio V: autoexplicación).
	f := one(mk(map[string]any{"missing_class": "inert_asset"}))
	if f.RuleID != "J0W-CORE-003" || f.Severity != Low || f.BaseSeverity != MediumS {
		t.Fatalf("inert_asset: %+v", f)
	}
	if f.Rationale == genericRationale || f.Rationale == "" {
		t.Fatalf("inert_asset: rationale no ajustado por clase: %+v", f)
	}

	// expected_absent → info, base medium; rationale también ajustado.
	f = one(mk(map[string]any{"missing_class": "expected_absent"}))
	if f.RuleID != "J0W-CORE-003" || f.Severity != Info || f.BaseSeverity != MediumS {
		t.Fatalf("expected_absent: %+v", f)
	}
	if f.Rationale == genericRationale || f.Rationale == "" {
		t.Fatalf("expected_absent: rationale no ajustado por clase: %+v", f)
	}

	// executable → medium, sin degradar (base medium); rationale es el
	// genérico de base(), sin reescribir.
	f = one(mk(map[string]any{"missing_class": "executable"}))
	if f.RuleID != "J0W-CORE-003" || f.Severity != MediumS || f.BaseSeverity != MediumS {
		t.Fatalf("executable: %+v", f)
	}
	if f.Rationale != genericRationale {
		t.Fatalf("executable: rationale debía quedarse genérico: %+v", f)
	}

	// "" (clase desconocida / sin campo) → medium, comportamiento previo.
	f = one(mk(map[string]any{"missing_class": ""}))
	if f.RuleID != "J0W-CORE-003" || f.Severity != MediumS || f.BaseSeverity != MediumS {
		t.Fatalf("clase vacía: %+v", f)
	}
	if f.Rationale != genericRationale {
		t.Fatalf("clase vacía: rationale debía quedarse genérico: %+v", f)
	}

	// Observación vieja sin missing_class en absoluto (regresión de tests
	// anteriores a esta tarea): cls="" por el type assertion fallido → medium.
	f = one(mk(map[string]any{"expected_sha256": "abc", "expected_size": 10}))
	if f.RuleID != "J0W-CORE-003" || f.Severity != MediumS || f.BaseSeverity != MediumS {
		t.Fatalf("sin missing_class en evidencia: %+v", f)
	}

	// expected_post_install (rama installation/ completo) → info, sin cambio.
	f = one(mk(map[string]any{"expected_post_install": true}))
	if f.RuleID != "J0W-CORE-003" || f.Severity != Info {
		t.Fatalf("expected_post_install: %+v", f)
	}
}

// TestDeriveConfigFindings cubre feature 002 (config-directive-analysis): la
// familia J0W-CONFIG-001/002/003 deriva de observe.ConfigDirective según
// directive_class, con la severidad calibrada por inert_media (002) y por la
// directiva peligrosa concreta (003).
func TestDeriveConfigFindings(t *testing.T) {
	mk := func(class, dir, target, state string, inert bool) observe.Observation {
		ev := map[string]any{"directive_class": class, "directive": dir, "target": target, "line": 3, "state": state, "inert_media": inert, "file": "images/.htaccess"}
		o, _ := observe.New([]byte("images/.htaccess"), observe.ConfigDirective, ev, observe.SrcConfscan, observe.High, 1)
		return o
	}
	obs := []observe.Observation{
		mk("exec_loader", "auto_prepend_file", "/tmp/s.php", "", false),
		mk("handler_widen", "AddHandler", ".jpg", "", true),
		mk("handler_widen", "AddHandler", ".inc", "", false),
		mk("php_setting", "allow_url_include", "", "on", false),
		mk("php_setting", "include_path", "/tmp", "set", false),
	}
	fs := Derive(obs, "1.1.0", map[string]bool{}, i18n.ES)
	byRule := map[string]Finding{}
	for _, f := range fs {
		byRule[f.RuleID] = f
	}
	if byRule["J0W-CONFIG-001"].Severity != Critical {
		t.Errorf("001 = %s", byRule["J0W-CONFIG-001"].Severity)
	}
	if byRule["J0W-CONFIG-001"].Alternative == "" {
		t.Errorf("001: falta hipótesis alternativa (Principio V)")
	}
	// 002 aparece dos veces (inert_media true/false); comprobamos ambas por severidad.
	var config002 []Finding
	for _, f := range fs {
		if f.RuleID == "J0W-CONFIG-002" {
			config002 = append(config002, f)
		}
	}
	if len(config002) != 2 {
		t.Fatalf("esperaba 2 hallazgos J0W-CONFIG-002, hay %d: %+v", len(config002), config002)
	}
	var gotCritical, gotHigh bool
	for _, f := range config002 {
		switch f.Severity {
		case Critical:
			gotCritical = true
		case High:
			gotHigh = true
		}
		if f.Alternative == "" {
			t.Errorf("002: falta hipótesis alternativa (Principio V): %+v", f)
		}
	}
	if !gotCritical || !gotHigh {
		t.Fatalf("002 debía tener un critical (inert_media) y un high (no inert_media): %+v", config002)
	}
	// 003 allow_url_include=on → high; include_path=set → medium.
	var config003 []Finding
	for _, f := range fs {
		if f.RuleID == "J0W-CONFIG-003" {
			config003 = append(config003, f)
		}
	}
	if len(config003) != 2 {
		t.Fatalf("esperaba 2 hallazgos J0W-CONFIG-003, hay %d: %+v", len(config003), config003)
	}
	var gotHigh003, gotMedium003 bool
	for _, f := range config003 {
		switch f.Severity {
		case High:
			gotHigh003 = true
		case MediumS:
			gotMedium003 = true
		}
		if f.Alternative == "" {
			t.Errorf("003: falta hipótesis alternativa (Principio V): %+v", f)
		}
	}
	if !gotHigh003 || !gotMedium003 {
		t.Fatalf("003 debía tener un high (allow_url_include) y un medium (include_path): %+v", config003)
	}
}

// TestDeriveConfigSuppressesFileUnexpected cubre la precedencia: un sujeto con
// observación ConfigDirective NO debe además producir el J0W-CORE-004
// genérico de "archivo inesperado" — el hallazgo J0W-CONFIG específico lo
// reemplaza (mismo patrón que handledByExt para J0W-EXT).
func TestDeriveConfigSuppressesFileUnexpected(t *testing.T) {
	subject := []byte("images/.htaccess")
	cfg, _ := observe.New(subject, observe.ConfigDirective, map[string]any{
		"directive_class": "exec_loader", "directive": "auto_prepend_file", "target": "/tmp/s.php", "line": 3, "state": "", "inert_media": false,
	}, observe.SrcConfscan, observe.High, 1)
	unexpected, _ := observe.New(subject, observe.FileUnexpected, map[string]any{
		"executable": false, "in_forbidden_exec": false, "in_core_dir": true,
	}, observe.SrcCorediff, observe.High, 2)

	fs := Derive([]observe.Observation{cfg, unexpected}, "1.1.0", map[string]bool{}, i18n.ES)
	for _, f := range fs {
		if f.RuleID == "J0W-CORE-004" {
			t.Fatalf("J0W-CORE-004 no debía derivarse para un sujeto ya cubierto por ConfigDirective: %+v", f)
		}
	}
	found := false
	for _, f := range fs {
		if f.RuleID == "J0W-CONFIG-001" {
			found = true
		}
	}
	if !found {
		t.Fatalf("esperaba J0W-CONFIG-001 en su lugar: %+v", fs)
	}
}

// TestDeriveTimeManipulation cubre la tarea 2 del feature de análisis
// temporal: una observación time_manipulation (mtime > ctime) deriva
// J0W-TIME-001 en low.
func TestDeriveTimeManipulation(t *testing.T) {
	ev := map[string]any{"mtime_ns": int64(200), "ctime_ns": int64(100), "delta_ns": int64(100)}
	o, _ := observe.New([]byte("images/x.php"), observe.TimeManipulation, ev, observe.SrcTimeline, observe.Medium, 1)
	fs := Derive([]observe.Observation{o}, "1.1.0", map[string]bool{}, i18n.ES)
	if len(fs) != 1 || fs[0].RuleID != "J0W-TIME-001" || fs[0].Severity != Low {
		t.Fatalf("J0W-TIME-001 low esperado: %+v", fs)
	}
}

// TestCtimeOutlierIsCorroborationNotFinding cubre que ctime_outlier nunca
// produce hallazgo por sí solo, pero sí anota (sin elevar severidad) un
// hallazgo existente sobre el mismo subject.
func TestCtimeOutlierIsCorroborationNotFinding(t *testing.T) {
	// una observación ctime_outlier SOLA no produce hallazgo
	oc, _ := observe.New([]byte("images/x.php"), observe.CtimeOutlier, map[string]any{"days_after_cohort": int64(120)}, observe.SrcTimeline, observe.Low, 1)
	if fs := Derive([]observe.Observation{oc}, "1.1.0", map[string]bool{}, i18n.ES); len(fs) != 0 {
		t.Fatalf("ctime_outlier solo no debe crear hallazgo: %+v", fs)
	}
	// pero SÍ anota un hallazgo existente sobre el mismo subject (p.ej. un ejecutable inesperado)
	ou, _ := observe.New([]byte("images/x.php"), observe.FileUnexpected, map[string]any{"executable": true, "in_forbidden_exec": true}, observe.SrcCorediff, observe.High, 1)
	fs := Derive([]observe.Observation{ou, oc}, "1.1.0", map[string]bool{}, i18n.ES)
	var found *Finding
	for i := range fs {
		if fs[i].Subject == "images/x.php" && fs[i].RuleID != "J0W-TIME-001" {
			found = &fs[i]
		}
	}
	if found == nil {
		t.Fatal("debe existir el hallazgo del ejecutable")
	}
	if v, _ := found.Evidence["ctime_outlier"].(bool); !v {
		t.Error("evidence.ctime_outlier debe ser true")
	}
	if !strings.Contains(found.Rationale, "corroboración temporal") {
		t.Errorf("rationale sin cláusula de corroboración: %q", found.Rationale)
	}

	// invariante Principio VI: la corroboración anota pero NUNCA eleva
	// severidad. Derivamos el MISMO hallazgo sin ctime_outlier y verificamos
	// que la severidad es idéntica con y sin la anotación.
	fsPlain := Derive([]observe.Observation{ou}, "1.1.0", map[string]bool{}, i18n.ES)
	var plain *Finding
	for i := range fsPlain {
		if fsPlain[i].Subject == "images/x.php" {
			plain = &fsPlain[i]
		}
	}
	if plain == nil {
		t.Fatal("debe existir el hallazgo del ejecutable sin corroboración")
	}
	wantSeverity := plain.Severity
	if found.Severity != wantSeverity {
		t.Errorf("severidad cambió por corroboración: sin=%s con=%s", wantSeverity, found.Severity)
	}
}

// TestDeriveSubtreeCollapsed cubre D5c task 2: una observación FileMissing
// colapsada (subtree_collapsed) deriva un único J0W-CORE-003 resumido, con
// Subject == el directorio, base medium degradado por la clase agregada del
// subárbol (mismo mapeo que missing_class per-archivo), y la evidencia
// reflejando el recuento (files_missing decodifica de JSON como float64, no
// int: Derive debe manejarlo sin type assertion directa a int).
func TestDeriveSubtreeCollapsed(t *testing.T) {
	sample := []string{"media/legacy/a.png", "media/legacy/b.png"}
	mk := func(cls string) observe.Observation {
		o, _ := observe.New([]byte("media/legacy"), observe.FileMissing, map[string]any{
			"subtree_collapsed": true,
			"files_missing":     2000,
			"missing_class":     cls,
			"sample":            sample,
		}, observe.SrcCorediff, observe.High, 1)
		return o
	}
	one := func(o observe.Observation) Finding {
		fs := Derive([]observe.Observation{o}, "1.1.0", map[string]bool{}, i18n.ES)
		if len(fs) != 1 {
			t.Fatalf("esperaba 1 hallazgo, hay %d", len(fs))
		}
		return fs[0]
	}

	// inert_asset → low, base medium.
	f := one(mk("inert_asset"))
	if f.RuleID != "J0W-CORE-003" || f.Subject != "media/legacy" || f.Severity != Low || f.BaseSeverity != MediumS {
		t.Fatalf("inert_asset: %+v", f)
	}
	if n, ok := f.Evidence["files_missing"].(float64); !ok || int(n) != 2000 {
		t.Fatalf("evidencia sin recuento: %+v", f.Evidence)
	}
	if !strings.Contains(f.Observed, "2000") {
		t.Fatalf("Observed no refleja el recuento: %q", f.Observed)
	}

	// executable → medium, base medium (sin degradar).
	f = one(mk("executable"))
	if f.RuleID != "J0W-CORE-003" || f.Severity != MediumS || f.BaseSeverity != MediumS {
		t.Fatalf("executable: %+v", f)
	}

	// expected_absent → info, base medium.
	f = one(mk("expected_absent"))
	if f.RuleID != "J0W-CORE-003" || f.Severity != Info || f.BaseSeverity != MediumS {
		t.Fatalf("expected_absent: %+v", f)
	}

	// missing_class "" (desconocido: subárbol colapsado sin ejecutable real,
	// D5c review MINOR 1) → medium, base medium (sin degradar; mismo default
	// que "executable", no se sintetiza a code).
	f = one(mk(""))
	if f.RuleID != "J0W-CORE-003" || f.Severity != MediumS || f.BaseSeverity != MediumS {
		t.Fatalf("missing_class vacía (desconocida): %+v", f)
	}
}

// L7 (dbscan, task 3): familia J0W-DB — cuentas privilegiadas anómalas,
// extensiones huérfanas en BD y payload ejecutable en #__modules.
func TestDeriveDBRules(t *testing.T) {
	mk := func(subj string, typ observe.Type, ev map[string]any) observe.Observation {
		o, _ := observe.New([]byte(subj), typ, ev, observe.SrcDB, observe.High, 1)
		return o
	}
	obs := []observe.Observation{
		mk("db://users/99", observe.DBPrivilegedAnomaly, map[string]any{"username": "root2", "reasons": []any{"register_outlier"}}),
		mk("db://extensions/com_ghost", observe.DBExtensionState, map[string]any{"element": "com_ghost", "present_on_disk": false}),
		mk("db://modules/5", observe.DBContentPayload, map[string]any{"module_id": 5.0, "patterns": []any{"eval"}}),
	}
	fs := Derive(obs, "5.1.4", nil, i18n.ES)
	want := map[string]Severity{"J0W-DB-001": High, "J0W-DB-002": High, "J0W-DB-003": Critical}
	got := map[string]Severity{}
	for _, f := range fs {
		got[f.RuleID] = f.Severity
	}
	for r, s := range want {
		if got[r] != s {
			t.Errorf("%s severidad = %q, want %q", r, got[r], s)
		}
	}
}

func TestDeriveDBExtensionPresentNoFinding(t *testing.T) {
	o, _ := observe.New([]byte("db://extensions/com_real"), observe.DBExtensionState,
		map[string]any{"element": "com_real", "present_on_disk": true}, observe.SrcDB, observe.High, 1)
	// present_on_disk true → contexto de correlación, NO hallazgo autónomo.
	fs := Derive([]observe.Observation{o}, "5.1.4", nil, i18n.ES)
	for _, f := range fs {
		if f.RuleID == "J0W-DB-002" {
			t.Fatal("una extensión presente en disco no debe producir J0W-DB-002")
		}
	}
}

func TestDeriveDBCorroborationNeverElevates(t *testing.T) {
	// Un hallazgo de disco (J0W-EXT-001) cuyo path pertenece a una extensión
	// activa en BD recibe anotación pero NO cambia de severidad.
	diskEv := map[string]any{"executable": true, "extension": "com_real"}
	extObs, _ := observe.New([]byte("components/com_real/evil.php"), observe.ExtUndeclared, diskEv, observe.SrcExtmap, observe.High, 1)
	dbObs, _ := observe.New([]byte("db://extensions/com_real"), observe.DBExtensionState,
		map[string]any{"element": "com_real", "present_on_disk": true, "disk_paths": []any{"components/com_real"}}, observe.SrcDB, observe.High, 1)
	before := Derive([]observe.Observation{extObs}, "5.1.4", nil, i18n.ES)
	after := Derive([]observe.Observation{extObs, dbObs}, "5.1.4", nil, i18n.ES)
	if len(before) != 1 || len(after) < 1 {
		t.Fatal("setup")
	}
	if before[0].Severity != after[0].Severity {
		t.Fatalf("la correlación de BD elevó la severidad: %q → %q (Principio VI)", before[0].Severity, after[0].Severity)
	}
	if after[0].Evidence["db_active_extension"] != "com_real" {
		t.Fatalf("falta anotación db_active_extension: %+v", after[0].Evidence)
	}
	if !strings.Contains(after[0].Rationale, "com_real") {
		t.Fatalf("Rationale no menciona la extensión correlacionada: %q", after[0].Rationale)
	}
}
