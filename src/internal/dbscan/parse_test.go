package dbscan

import (
	"strings"
	"testing"
)

func TestParseMySQLDatetime(t *testing.T) {
	cases := []struct {
		in   string
		want int64
	}{
		{"2020-01-02 03:04:05", 1577934245_000000000},
		{"0000-00-00 00:00:00", 0},
		{"", 0},
		{"garbage", 0},
	}
	for _, c := range cases {
		if got := parseMySQLDatetime(c.in); got != c.want {
			t.Errorf("parseMySQLDatetime(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestParsePrefixAndUsers(t *testing.T) {
	dump := `-- MySQL dump
INSERT INTO ` + "`abc12_users`" + ` (id, name, username, email, password, block, activation, registerDate, lastvisitDate) VALUES
(42, 'Root', 'admin', 'a@ex.com', '$2y$10$abcdef', 0, '', '2020-01-02 03:04:05', '2020-06-01 00:00:00'),
(43, 'Evil', 'x', 'x@ex.com', '$2y$10$zzzz', 0, 'tok123', '2021-09-09 09:09:09', '0000-00-00 00:00:00');
INSERT INTO ` + "`abc12_extensions`" + ` (extension_id, name, type, element, enabled, protected, state) VALUES
(10000, 'com_evil', 'component', 'com_evil', 1, 0, 0);
`
	d, err := Parse(strings.NewReader(dump))
	if err != nil {
		t.Fatal(err)
	}
	if d.Prefix != "abc12_" {
		t.Fatalf("prefix = %q, want abc12_", d.Prefix)
	}
	if len(d.Users) != 2 {
		t.Fatalf("users = %d, want 2", len(d.Users))
	}
	if d.Users[1].Activation != "tok123" || d.Users[1].RegisterNS == 0 {
		t.Errorf("row 43 mal parseada: %+v", d.Users[1])
	}
	if len(d.Extensions) != 1 || d.Extensions[0].Element != "com_evil" || d.Extensions[0].Enabled != 1 {
		t.Errorf("extensión mal parseada: %+v", d.Extensions)
	}
}

func TestParseEscapedQuotesAndModules(t *testing.T) {
	dump := "INSERT INTO `wp_modules` (id, title, module, content, published) VALUES " +
		`(1, 'It''s fine', 'mod_custom', '<?php echo \'x\'; ?>', 1);` + "\n"
	d, _ := Parse(strings.NewReader(dump))
	if len(d.Modules) != 1 || d.Modules[0].Title != "It's fine" {
		t.Fatalf("comilla escapada mal parseada: %+v", d.Modules)
	}
	if !strings.Contains(d.Modules[0].Content, "<?php") {
		t.Errorf("content perdido: %q", d.Modules[0].Content)
	}
}

func TestParseModuleContentControlEscapes(t *testing.T) {
	dump := "INSERT INTO `abc12_modules` (id, title, module, content, published) VALUES " +
		`(1, 't', 'mod_custom', 'a\nb\tc', 1);` + "\n"
	d, err := Parse(strings.NewReader(dump))
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Modules) != 1 {
		t.Fatalf("modules = %d, want 1", len(d.Modules))
	}
	if got, want := d.Modules[0].Content, "a\nb\tc"; got != want {
		t.Errorf("content = %q, want %q (bytes: got=%v want=%v)", got, want, []byte(got), []byte(want))
	}
	// \\ y \' deben seguir funcionando tras el fix.
	dump2 := "INSERT INTO `abc12_modules` (id, title, module, content, published) VALUES " +
		`(2, 't2', 'mod_custom', 'back\\slash and it\'s', 1);` + "\n"
	d2, err := Parse(strings.NewReader(dump2))
	if err != nil {
		t.Fatal(err)
	}
	if len(d2.Modules) != 1 {
		t.Fatalf("modules = %d, want 1", len(d2.Modules))
	}
	if got, want := d2.Modules[0].Content, `back\slash and it's`; got != want {
		t.Errorf("content = %q, want %q", got, want)
	}
}

func TestParseAmbiguousPrefix(t *testing.T) {
	dump := "INSERT INTO `a_users` (id) VALUES (1);\nINSERT INTO `b_users` (id) VALUES (2);\n"
	d, _ := Parse(strings.NewReader(dump))
	if !d.Ambiguous {
		t.Error("dos prefijos distintos deben marcar Ambiguous")
	}
}

func TestParseDeterministic(t *testing.T) {
	dump := "INSERT INTO `p_users` (id, username) VALUES (3,'c'),(1,'a'),(2,'b');\n"
	a, _ := Parse(strings.NewReader(dump))
	b, _ := Parse(strings.NewReader(dump))
	if a.Users[0].ID != 1 || a.Users[2].ID != 3 {
		t.Errorf("no ordenado por PK: %+v", a.Users)
	}
	if len(a.Users) != len(b.Users) {
		t.Error("no determinista")
	}
}

func TestParseUnsupported(t *testing.T) {
	d, _ := Parse(strings.NewReader("this is not a sql dump\n"))
	if !d.Unsupported {
		t.Error("entrada sin INSERT debe marcar Unsupported")
	}
}

// TestParseExtensionsFolderAndClientID cubre el Finding C1 (review final):
// ExtRow debe capturar folder y client_id, columnas nuevas necesarias para
// construir la clave con forma (dbExtensionKey en dbscan.go) que compara
// contra extmap.Extension.ElementKey ("system/joomla", "mod_menu@administrator").
func TestParseExtensionsFolderAndClientID(t *testing.T) {
	dump := "INSERT INTO `abc12_extensions` " +
		"(extension_id, element, type, folder, client_id, enabled, protected, state) VALUES\n" +
		"(1, 'joomla', 'plugin', 'system', 0, 1, 1, 0),\n" +
		"(2, 'mod_menu', 'module', NULL, 1, 1, 0, 0),\n" +
		"(3, 'com_content', 'component', NULL, 0, 1, 1, 0);\n"
	d, err := Parse(strings.NewReader(dump))
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Extensions) != 3 {
		t.Fatalf("extensions = %d, want 3", len(d.Extensions))
	}
	plugin := d.Extensions[0]
	if plugin.Folder != "system" || plugin.ClientID != 0 {
		t.Errorf("plugin mal parseado: folder=%q client_id=%d, want folder=system client_id=0", plugin.Folder, plugin.ClientID)
	}
	module := d.Extensions[1]
	if module.Folder != "" {
		t.Errorf("module.Folder = %q, want vacío (folder NULL debe normalizarse a \"\")", module.Folder)
	}
	if module.ClientID != 1 {
		t.Errorf("module.ClientID = %d, want 1 (administrator)", module.ClientID)
	}
	component := d.Extensions[2]
	if component.ClientID != 0 {
		t.Errorf("component.ClientID = %d, want 0", component.ClientID)
	}
}

// TestParseBareInsertCreateTableColumnOrder cubre el Defecto D1: mysqldump
// por DEFECTO (sin --complete-insert) emite `INSERT INTO `t` VALUES (...);`
// SIN lista de columnas. La única forma de mapear los valores a nombres es
// aprender el orden de columnas de su `CREATE TABLE`, que mysqldump siempre
// emite antes que el INSERT. Este dump reproduce esa forma por defecto
// (DROP TABLE + CREATE TABLE con PRIMARY KEY/KEY intercaladas que NO deben
// contarse como columnas + INSERT desnudo).
func TestParseBareInsertCreateTableColumnOrder(t *testing.T) {
	dump := "DROP TABLE IF EXISTS `p_users`;\n" +
		"CREATE TABLE `p_users` (\n" +
		"  `id` int(11) NOT NULL AUTO_INCREMENT,\n" +
		"  `username` varchar(150) NOT NULL DEFAULT '',\n" +
		"  `email` varchar(100) NOT NULL DEFAULT '',\n" +
		"  `block` tinyint(4) NOT NULL DEFAULT 0,\n" +
		"  `activation` varchar(100) NOT NULL DEFAULT '',\n" +
		"  `registerDate` datetime NOT NULL DEFAULT '0000-00-00 00:00:00',\n" +
		"  `lastvisitDate` datetime NOT NULL DEFAULT '0000-00-00 00:00:00',\n" +
		"  PRIMARY KEY (`id`),\n" +
		"  UNIQUE KEY `idx_username` (`username`),\n" +
		"  KEY `idx_email` (`email`)\n" +
		") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;\n" +
		"INSERT INTO `p_users` VALUES (1,'admin','a@b.com',0,'','2020-01-01 00:00:00','2020-06-01 00:00:00');\n"

	d, err := Parse(strings.NewReader(dump))
	if err != nil {
		t.Fatal(err)
	}
	if d.Unsupported {
		t.Fatal("Unsupported = true, want false (el INSERT desnudo debe reconocerse vía CREATE TABLE)")
	}
	if len(d.Users) != 1 {
		t.Fatalf("users = %d, want 1", len(d.Users))
	}
	u := d.Users[0]
	if u.ID != 1 || u.Username != "admin" || u.Email != "a@b.com" || u.Block != 0 {
		t.Errorf("fila mal mapeada por orden de CREATE TABLE: %+v", u)
	}
	if u.RegisterNS == 0 || u.LastVisitNS == 0 {
		t.Errorf("fechas no parseadas: registerNS=%d lastVisitNS=%d", u.RegisterNS, u.LastVisitNS)
	}
	if d.Prefix != "p_" {
		t.Errorf("prefix = %q, want p_", d.Prefix)
	}
}

// TestParseBareInsertUnknownTableDegrades cubre la mitad "degradar, no
// adivinar" del Defecto D1 combinada con el Fix P2: un INSERT desnudo sobre
// una tabla OBJETIVO cuyo CREATE TABLE nunca se vio no debe adivinar el orden
// de columnas — se salta la fila (cero filas) — pero, al ser la ÚNICA señal
// del dump y casar con una tabla objetivo, RESTAURA Unsupported=true (Fix P2:
// un dump solo-datos sobre tablas objetivo perdía todas las filas en silencio;
// ahora la pérdida total se declara ruidosamente).
func TestParseBareInsertUnknownTableDegrades(t *testing.T) {
	dump := "INSERT INTO `p_users` VALUES (1,'admin','a@b.com',0,'','2020-01-01 00:00:00','2020-06-01 00:00:00');\n"
	d, err := Parse(strings.NewReader(dump))
	if err != nil {
		t.Fatal(err)
	}
	if !d.Unsupported {
		t.Error("Unsupported = false, want true (Fix P2: bare INSERT sobre tabla objetivo sin CREATE TABLE y cero filas → señal ruidosa)")
	}
	if len(d.Users) != 0 {
		t.Errorf("users = %d, want 0 (sin CREATE TABLE no hay orden de columnas fiable)", len(d.Users))
	}
}

// TestParseSingleLineCreateTable cubre el Fix P1: un `CREATE TABLE` minificado
// (todo en UNA línea, sin saltos) seguido de un INSERT desnudo. El parser
// antiguo partía el cuerpo por "\n" y tomaba el primer identificador backtick
// por línea → con una sola línea capturaba SOLO la primera columna (`id`),
// dejando username/email sin mapear (silenciosamente vacíos). Tras el fix, el
// cuerpo se parte por comas de nivel superior y se conservan todas las
// columnas en orden.
func TestParseSingleLineCreateTable(t *testing.T) {
	dump := "CREATE TABLE `p_users` (`id` int, `username` varchar(150), `email` varchar(100), PRIMARY KEY (`id`)) ENGINE=InnoDB;\n" +
		"INSERT INTO `p_users` VALUES (7,'admin','a@b.com');\n"
	d, err := Parse(strings.NewReader(dump))
	if err != nil {
		t.Fatal(err)
	}
	if d.Unsupported {
		t.Fatal("Unsupported = true, want false")
	}
	if len(d.Users) != 1 {
		t.Fatalf("users = %d, want 1", len(d.Users))
	}
	u := d.Users[0]
	if u.ID != 7 || u.Username != "admin" || u.Email != "a@b.com" {
		t.Errorf("columnas de un CREATE TABLE de una línea mal mapeadas: %+v", u)
	}
	if d.Prefix != "p_" {
		t.Errorf("prefix = %q, want p_", d.Prefix)
	}
}

// TestParseDataOnlyDumpUnsupported cubre el Fix P2: un dump SOLO-DATOS (solo
// INSERT desnudos sobre tablas objetivo, sin ningún CREATE TABLE) perdía todas
// las filas y devolvía Unsupported=false (pérdida total silenciosa). Tras el
// fix, al casar con tablas objetivo sin orden de columnas conocido y no parsear
// ninguna fila, se restaura Unsupported=true.
func TestParseDataOnlyDumpUnsupported(t *testing.T) {
	dump := "INSERT INTO `p_users` VALUES (1,'admin');\n" +
		"INSERT INTO `p_extensions` VALUES (1,'com_x','component');\n"
	d, err := Parse(strings.NewReader(dump))
	if err != nil {
		t.Fatal(err)
	}
	if !d.Unsupported {
		t.Fatal("Unsupported = false, want true (dump solo-datos sobre tablas objetivo)")
	}
	if len(d.Users)+len(d.Extensions) != 0 {
		t.Errorf("filas = %d, want 0 (sin CREATE TABLE no hay orden de columnas fiable)", len(d.Users)+len(d.Extensions))
	}
}

// TestParseUpdateSitesExtensionsNoCollision cubre el Defecto D3: la tabla
// real de Joomla `<prefix>_update_sites_extensions` termina textualmente en
// "_extensions", el mismo sufijo que la tabla de extensiones de verdad. El
// orden en el dump (update_sites_extensions y extensions ANTES que users,
// como en un mysqldump real por orden alfabético de tabla) ejercita a
// propósito la resolución diferida: el prefijo real solo se confirma con la
// tabla ancla `p_users`, que llega al final.
func TestParseUpdateSitesExtensionsNoCollision(t *testing.T) {
	dump := "CREATE TABLE `p_extensions` (\n" +
		"  `extension_id` int(11) NOT NULL AUTO_INCREMENT,\n" +
		"  `element` varchar(100) NOT NULL DEFAULT '',\n" +
		"  `type` varchar(20) NOT NULL DEFAULT '',\n" +
		"  `folder` varchar(100) NOT NULL DEFAULT '',\n" +
		"  `client_id` tinyint(3) NOT NULL DEFAULT 0,\n" +
		"  `enabled` tinyint(3) NOT NULL DEFAULT 0,\n" +
		"  `protected` tinyint(3) NOT NULL DEFAULT 0,\n" +
		"  `state` int(11) DEFAULT 0,\n" +
		"  PRIMARY KEY (`extension_id`)\n" +
		") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;\n" +
		"INSERT INTO `p_extensions` VALUES (1,'com_content','component','',0,1,1,0);\n" +
		"CREATE TABLE `p_update_sites_extensions` (\n" +
		"  `update_site_id` int(11) NOT NULL DEFAULT 0,\n" +
		"  `extension_id` int(11) NOT NULL DEFAULT 0,\n" +
		"  PRIMARY KEY (`update_site_id`,`extension_id`)\n" +
		") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;\n" +
		"INSERT INTO `p_update_sites_extensions` VALUES (5,999),(6,998);\n" +
		"CREATE TABLE `p_users` (\n" +
		"  `id` int(11) NOT NULL AUTO_INCREMENT,\n" +
		"  `username` varchar(150) NOT NULL DEFAULT '',\n" +
		"  PRIMARY KEY (`id`)\n" +
		") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;\n" +
		"INSERT INTO `p_users` VALUES (1,'admin');\n"

	d, err := Parse(strings.NewReader(dump))
	if err != nil {
		t.Fatal(err)
	}
	if d.Unsupported {
		t.Fatal("Unsupported = true, want false")
	}
	if d.Ambiguous {
		t.Fatal("Ambiguous = true, want false: update_sites_extensions no es un segundo prefijo, es otra tabla")
	}
	if d.Prefix != "p_" {
		t.Errorf("prefix = %q, want p_", d.Prefix)
	}
	if len(d.Extensions) != 1 {
		t.Fatalf("extensions = %d, want 1 (solo la fila real de p_extensions)", len(d.Extensions))
	}
	if d.Extensions[0].ExtensionID != 1 || d.Extensions[0].Element != "com_content" {
		t.Errorf("extensión mal parseada: %+v", d.Extensions[0])
	}
	for _, e := range d.Extensions {
		if e.ExtensionID == 999 || e.ExtensionID == 998 {
			t.Fatalf("fila de update_sites_extensions se filtró en d.Extensions: %+v", e)
		}
	}
}

// TestParseRealDumpShapeCollision reproduce la forma del SEGUNDO dump real
// (forma de un volcado real): las CINCO tablas objetivo exactas con prefijo `p_` conviven
// con tablas reales de Joomla cuyo nombre TERMINA en un sufijo objetivo pero
// NO son la tabla objetivo: `p_action_logs_users`, `p_action_logs_extensions`,
// `p_j2xml_usergroups`, `p_update_sites_extensions`. Con la resolución vieja
// (anclar en users/usergroups/user_usergroup_map) esas colisiones generaban
// prefijos ancla rivales (`p_action_logs_`, `p_j2xml_`) → Ambiguous=true y
// cero filas. La resolución robusta cuenta tablas objetivo EXACTAS por
// candidato: `p_`→5, `p_action_logs_`→2, `p_j2xml_`→1, `p_update_sites_`→1 ⇒
// ganador único `p_`, no ambiguo, y ninguna fila de colisión se filtra.
func TestParseRealDumpShapeCollision(t *testing.T) {
	dump := "" +
		// --- cinco tablas objetivo EXACTAS (las reales) ---
		"CREATE TABLE `p_users` (`id` int, `username` varchar(150), `email` varchar(100), `block` tinyint, `activation` varchar(100), `registerDate` datetime, `lastvisitDate` datetime, PRIMARY KEY (`id`)) ENGINE=InnoDB;\n" +
		"INSERT INTO `p_users` VALUES (1,'admin','a@b.com',0,'','2020-01-01 00:00:00','2020-06-01 00:00:00');\n" +
		"CREATE TABLE `p_usergroups` (`id` int, `title` varchar(100), PRIMARY KEY (`id`)) ENGINE=InnoDB;\n" +
		"INSERT INTO `p_usergroups` VALUES (8,'Super Users');\n" +
		"CREATE TABLE `p_user_usergroup_map` (`user_id` int, `group_id` int, PRIMARY KEY (`user_id`,`group_id`)) ENGINE=InnoDB;\n" +
		"INSERT INTO `p_user_usergroup_map` VALUES (1,8);\n" +
		"CREATE TABLE `p_extensions` (`extension_id` int, `element` varchar(100), `type` varchar(20), `folder` varchar(100), `client_id` tinyint, `enabled` tinyint, `protected` tinyint, `state` int, PRIMARY KEY (`extension_id`)) ENGINE=InnoDB;\n" +
		"INSERT INTO `p_extensions` VALUES (100,'com_content','component','',0,1,1,0);\n" +
		"CREATE TABLE `p_modules` (`id` int, `title` varchar(100), `module` varchar(50), `content` mediumtext, `published` tinyint, PRIMARY KEY (`id`)) ENGINE=InnoDB;\n" +
		"INSERT INTO `p_modules` VALUES (200,'Main Menu','mod_menu','',1);\n" +
		// --- tablas de colisión (terminan en sufijo objetivo, NO son objetivo) ---
		"CREATE TABLE `p_action_logs_users` (`id` int, `user_id` int, `username` varchar(150), PRIMARY KEY (`id`)) ENGINE=InnoDB;\n" +
		"INSERT INTO `p_action_logs_users` VALUES (777,5,'evil');\n" +
		"CREATE TABLE `p_action_logs_extensions` (`extension_id` int, `type_alias` varchar(100), PRIMARY KEY (`extension_id`)) ENGINE=InnoDB;\n" +
		"INSERT INTO `p_action_logs_extensions` VALUES (888,'com_evil');\n" +
		"CREATE TABLE `p_j2xml_usergroups` (`id` int, `title` varchar(100), PRIMARY KEY (`id`)) ENGINE=InnoDB;\n" +
		"INSERT INTO `p_j2xml_usergroups` VALUES (999,'evil group');\n" +
		"CREATE TABLE `p_update_sites_extensions` (`update_site_id` int, `extension_id` int, PRIMARY KEY (`update_site_id`,`extension_id`)) ENGINE=InnoDB;\n" +
		"INSERT INTO `p_update_sites_extensions` VALUES (5,12345);\n"

	d, err := Parse(strings.NewReader(dump))
	if err != nil {
		t.Fatal(err)
	}
	if d.Unsupported {
		t.Fatal("Unsupported = true, want false")
	}
	if d.Ambiguous {
		t.Fatalf("Ambiguous = true, want false: las colisiones no son un segundo install, `p_` gana por 5 tablas objetivo exactas")
	}
	if d.Prefix != "p_" {
		t.Fatalf("prefix = %q, want p_", d.Prefix)
	}
	// Filas reales presentes.
	if len(d.Users) != 1 || d.Users[0].ID != 1 || d.Users[0].Username != "admin" {
		t.Fatalf("users = %+v, want 1 fila id=1 admin", d.Users)
	}
	if len(d.Groups) != 1 || d.Groups[0].ID != 8 {
		t.Fatalf("groups = %+v, want 1 fila id=8", d.Groups)
	}
	if len(d.Memberships) != 1 {
		t.Fatalf("memberships = %d, want 1", len(d.Memberships))
	}
	if len(d.Extensions) != 1 || d.Extensions[0].ExtensionID != 100 || d.Extensions[0].Element != "com_content" {
		t.Fatalf("extensions = %+v, want 1 fila id=100 com_content", d.Extensions)
	}
	if len(d.Modules) != 1 || d.Modules[0].ID != 200 {
		t.Fatalf("modules = %+v, want 1 fila id=200", d.Modules)
	}
	// NINGUNA fila de colisión se filtra.
	for _, u := range d.Users {
		if u.ID == 777 {
			t.Fatalf("fila de p_action_logs_users se filtró en d.Users: %+v", u)
		}
	}
	for _, g := range d.Groups {
		if g.ID == 999 {
			t.Fatalf("fila de p_j2xml_usergroups se filtró en d.Groups: %+v", g)
		}
	}
	for _, e := range d.Extensions {
		if e.ExtensionID == 888 || e.ExtensionID == 12345 {
			t.Fatalf("fila de tabla de colisión se filtró en d.Extensions: %+v", e)
		}
	}
}

// TestParseGenuineTwoInstallAmbiguity comprueba que la ambigüedad REAL se
// preserva: dos instalaciones Joomla mezcladas en un mismo dump, cada una con
// VARIAS tablas objetivo exactas (a_users+a_extensions y b_users+b_extensions).
// Ambos candidatos empatan en el conteo máximo (2) ⇒ Ambiguous=true, sin
// adivinar cuál install es el real ni filtrar filas.
func TestParseGenuineTwoInstallAmbiguity(t *testing.T) {
	dump := "INSERT INTO `a_users` (id, username) VALUES (1,'a');\n" +
		"INSERT INTO `a_extensions` (extension_id, element, type) VALUES (10,'com_a','component');\n" +
		"INSERT INTO `b_users` (id, username) VALUES (2,'b');\n" +
		"INSERT INTO `b_extensions` (extension_id, element, type) VALUES (20,'com_b','component');\n"
	d, err := Parse(strings.NewReader(dump))
	if err != nil {
		t.Fatal(err)
	}
	if !d.Ambiguous {
		t.Fatal("Ambiguous = false, want true: dos installs con conteo máximo empatado")
	}
	if d.Prefix != "" {
		t.Errorf("prefix = %q, want vacío ante ambigüedad", d.Prefix)
	}
	if len(d.Users)+len(d.Extensions) != 0 {
		t.Errorf("filas confirmadas = %d, want 0 ante ambigüedad", len(d.Users)+len(d.Extensions))
	}
}
