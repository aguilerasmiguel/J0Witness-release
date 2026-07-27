package cli

import (
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"j0witness/internal/extbaseline"
	"j0witness/internal/manifest"
	"j0witness/internal/report"
	"j0witness/internal/safefs"
)

func newExtensionCmd(app *App) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "extension",
		Short: "Verificación de extensiones contra su paquete oficial",
	}
	cmd.AddCommand(newExtensionAddCmd(app))
	cmd.AddCommand(newExtensionListCmd(app))
	cmd.AddCommand(newExtensionFetchCmd(app))
	return cmd
}

func newExtensionAddCmd(app *App) *cobra.Command {
	var group, client string
	cmd := &cobra.Command{
		Use:   "add <elemento> <sitio> <paquete.zip>",
		Short: "Cachea el baseline oficial de una extensión desde su paquete (offline)",
		Args:  cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			element, site, pkgPath := args[0], args[1], args[2]
			target, version, _, err := readInstalledExtension(site, element, group, client)
			if err != nil {
				return Exitf(ExitUsageError, "%v", err)
			}
			store, err := openStateStore(app)
			if err != nil {
				return Exitf(ExitInternalError, "%v", err)
			}
			defer store.Close()
			addedVersion, n, err := extbaseline.Add(store, target, version, pkgPath)
			if err != nil {
				return Exitf(ExitUsageError, "%v", err)
			}
			app.Progress("baseline de extensión añadido: %s %s (%d archivos)", target.ElementKey, addedVersion, n)
			doc, err := report.CanonicalMarshal(map[string]any{
				"added":   target.ElementKey,
				"version": addedVersion,
				"files":   n,
			})
			if err != nil {
				return Exitf(ExitInternalError, "%v", err)
			}
			_, err = app.Stdout.Write(doc)
			return err
		},
	}
	cmd.Flags().StringVar(&group, "group", "", "grupo del plugin (system, content, ...); requerido si el elemento no viene como grupo/elemento")
	cmd.Flags().StringVar(&client, "client", "", `cliente de instalación: "site" o "admin" (módulos/plantillas instalados en ambos lados)`)
	return cmd
}

func newExtensionListCmd(app *App) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "Lista los baselines de extensión cacheados",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := openStateStore(app)
			if err != nil {
				return Exitf(ExitInternalError, "%v", err)
			}
			defer store.Close()
			rows, err := store.ListExtensionBaselines()
			if err != nil {
				return Exitf(ExitInternalError, "%v", err)
			}
			type row struct {
				Element string `json:"element"`
				Version string `json:"version"`
				Source  string `json:"source"`
				Type    string `json:"type"`
			}
			out := make([]row, 0, len(rows))
			for _, r := range rows {
				out = append(out, row{Element: r.Element, Version: r.Version, Source: r.Source, Type: extensionTypeOf(r.Element)})
			}
			doc, err := report.CanonicalMarshal(map[string]any{
				"extension_baselines": out,
			})
			if err != nil {
				return Exitf(ExitInternalError, "%v", err)
			}
			_, err = app.Stdout.Write(doc)
			return err
		},
	}
}

// extensionTypeOf deriva, best-effort, el tipo de extensión a partir de la
// clave estable con la que se cacheó su baseline (manifest.ExtensionKey), sin
// tocar el esquema del store (que solo guarda `element`):
//   - com_* → component
//   - mod_* → module
//   - contiene "/" → plugin (grupo/elemento) O librería namespaced
//     (<libraryname> con "/", p.ej. "labvendor/lablib"): ambas formas son
//     indistinguibles solo por la clave, se etiqueta "plugin-or-library"
//   - termina en "@administrator" → module o template del lado admin (mejor
//     esfuerzo: se etiqueta igualmente "module" salvo que ya haya casado com_/mod_)
//   - en otro caso → template o library (indistinguibles solo por la clave;
//     se etiqueta "template-or-library")
func extensionTypeOf(element string) string {
	switch {
	case strings.HasPrefix(element, "com_"):
		return string(manifest.Component)
	case strings.HasPrefix(element, "mod_"):
		return string(manifest.Module)
	case strings.Contains(element, "/"):
		return "plugin-or-library"
	case strings.HasSuffix(element, "@administrator"):
		return string(manifest.Template)
	default:
		return "template-or-library"
	}
}

func newExtensionFetchCmd(app *App) *cobra.Command {
	var group, client string
	cmd := &cobra.Command{
		Use:   "fetch <elemento> <ruta-sitio>",
		Short: "Descarga el paquete oficial de una extensión vía su update server (requiere --allow-network)",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			element, site := args[0], args[1]
			// Localiza y parsea el manifiesto instalado de la extensión (safefs, solo lectura).
			target, version, updateURL, err := readInstalledExtension(site, element, group, client)
			if err != nil {
				return Exitf(ExitUsageError, "%v", err)
			}
			if updateURL == "" {
				return Exitf(ExitUsageError,
					"el manifiesto instalado de %s no declara update server; aporta el paquete con: j0witness extension add %s %s <paquete.zip>",
					target.ElementKey, target.ElementKey, site)
			}
			if !app.Flags.AllowNetwork {
				return Exitf(ExitUsageError,
					"la red no está autorizada. Se obtendría %s para verificar %s %s; reejecuta con --allow-network, o aporta el paquete con: j0witness extension add %s %s <paquete.zip>",
					updateURL, target.ElementKey, version, target.ElementKey, site)
			}
			store, err := openStateStore(app)
			if err != nil {
				return Exitf(ExitInternalError, "%v", err)
			}
			defer store.Close()
			v, n, err := extbaseline.Fetch(app.Stderr, store, target, site, updateURL, version)
			if err != nil {
				return Exitf(ExitUsageError, "%v", err)
			}
			app.Progress("baseline de extensión obtenido: %s %s (%d archivos, vía update server)", target.ElementKey, v, n)
			return nil
		},
	}
	cmd.Flags().StringVar(&group, "group", "", "grupo del plugin (system, content, ...); requerido si el elemento no viene como grupo/elemento")
	cmd.Flags().StringVar(&client, "client", "", `cliente de instalación: "site" o "admin" (módulos/plantillas instalados en ambos lados)`)
	return cmd
}

// manifestHit es un manifiesto instalado candidato ya parseado, con la ruta
// (relativa al sitio) donde vive.
type manifestHit struct {
	path string
	m    *manifest.Manifest
}

// readInstalledExtension localiza el manifiesto instalado de <element> en el
// árbol de <site> (solo lectura, vía safefs) buscando en TODAS las
// ubicaciones conocidas de Joomla según el tipo que <element>/<group>/
// <client> sugieren — nunca prependiendo un literal "administrator/" a una
// ruta arbitraria: cada ubicación candidata es una de las ya conocidas
// (administrator/components/, modules/, administrator/modules/, plugins/,
// templates/, administrator/templates/, administrator/manifests/libraries/).
//
// client es el valor crudo de --client: "admin" restringe la búsqueda al
// lado de administración, "site" la restringe al lado de sitio, "" (o
// cualquier otro valor) prueba ambos — simétrico en las dos direcciones, así
// que el error de ambigüedad ("desambigua con --client") es siempre
// accionable.
//
// Recorre las ubicaciones candidatas en orden determinista; el target final
// SIEMPRE se deriva de la ruta real donde el manifiesto encontrado vive:
// target = m.ResolveInstall(manifestRelPath) (nunca reconstruido a mano).
//
// Si varios candidatos (de ubicaciones distintas) casan el mismo element con
// IDENTIDAD distinta (ElementKey distinto — p.ej. un módulo instalado tanto en
// site como en administrator, o un elemento con forma "a/b" que calza TANTO
// un plugin grupo/elemento COMO una librería de <libraryname> namespaced), es
// una ambigüedad real que el operador debe resolver con --group/--client: se
// devuelve un error enumerando las rutas (Principio IV), nunca se elige una
// al azar.
//
// updateURL es m.UpdateServers[0] si el manifiesto lo declara, o "" si no: el
// llamante (fetch) decide si la ausencia de update server es un error; add la
// ignora.
func readInstalledExtension(site, element, group, client string) (manifest.InstallTarget, string, string, error) {
	// manifest.ExtensionKey sufija "@administrator" a la clave de módulos y
	// plantillas instalados en el lado admin (fix round 2, IMPORTANT 1): es la
	// clave EXACTA que `extension list` imprime, así que debe ser
	// round-trippable de vuelta a `add`/`fetch` sin que el operador tenga que
	// además recordar pasar --client admin. El sufijo es una señal explícita
	// y autoritativa del lado de instalación — la tratamos como si el
	// operador hubiese pasado --client admin (lo sobreescribe si venía
	// distinto: ningún nombre de elemento legítimo termina en
	// "@administrator", así que esto es seguro para los 5 tipos). Tras
	// despojar el sufijo, el resto de la resolución sigue igual y ahora sí
	// encuentra la extensión admin.
	if e, ok := strings.CutSuffix(element, "@administrator"); ok {
		element = e
		client = "admin"
	}

	fsys, err := safefs.New(site)
	if err != nil {
		return manifest.InstallTarget{}, "", "", err
	}
	wantSite := client != "admin"
	wantAdmin := client != "site"

	switch {
	case group != "":
		// --group explícito: fuerza el plugin sin ambigüedad posible (el
		// operador ya desambiguó a mano).
		e := element
		if idx := strings.Index(element, "/"); idx >= 0 {
			e = element[idx+1:]
		}
		dir := "plugins/" + group + "/" + e
		var hits []manifestHit
		if rel, m := findFirstInDir(fsys, dir, manifest.Plugin); m != nil {
			hits = append(hits, manifestHit{rel, m})
		}
		return resolveHits(hits, fmt.Errorf("no se encontró un manifiesto de plugin instalado para %s/%s (buscado en %s) en %s", group, e, dir, site))

	case strings.HasPrefix(element, "com_"):
		dir := "administrator/components/" + element
		var hits []manifestHit
		if rel, m := findFirstInDir(fsys, dir, manifest.Component); m != nil {
			hits = append(hits, manifestHit{rel, m})
		}
		return resolveHits(hits, fmt.Errorf("no se encontró un componente %s instalado en %s (buscado en %s)", element, site, dir))

	case strings.HasPrefix(element, "mod_"):
		var dirs []string
		if wantSite {
			dirs = append(dirs, "modules/"+element)
		}
		if wantAdmin {
			dirs = append(dirs, "administrator/modules/"+element)
		}
		var hits []manifestHit
		for _, d := range dirs {
			if rel, m := findFirstInDir(fsys, d, manifest.Module); m != nil {
				hits = append(hits, manifestHit{rel, m})
			}
		}
		return resolveHits(hits, fmt.Errorf("no se encontró un módulo %s instalado en %s (buscado en %s)", element, site, strings.Join(dirs, ", ")))

	case strings.Contains(element, "/"):
		// Sin --group pero con forma "a/b": esta forma es AMBIGUA por
		// construcción entre dos tipos reales de Joomla — un plugin
		// (grupo/elemento, p.ej. "system/foo") y una librería con
		// <libraryname> namespaced (p.ej. "eshiol/J2xml", "vendor/synthlib":
		// ambas son fixtures reales de este repo). Se prueban AMBAS
		// ubicaciones y se combinan los candidatos; si solo una calza, no hay
		// ambigüedad real y se usa esa. --group fuerza el plugin sin pasar
		// por esta rama (caso anterior).
		idx := strings.Index(element, "/")
		g, e := element[:idx], element[idx+1:]
		pluginDir := "plugins/" + g + "/" + e
		var hits []manifestHit
		if rel, m := findFirstInDir(fsys, pluginDir, manifest.Plugin); m != nil {
			hits = append(hits, manifestHit{rel, m})
		}
		libHits, err := findLibrary(fsys, element)
		if err != nil {
			return manifest.InstallTarget{}, "", "", err
		}
		hits = append(hits, libHits...)
		return resolveHits(hits, fmt.Errorf(
			"no se encontró un plugin (%s/%s) ni una librería (%s) instalados en %s (buscado en %s y administrator/manifests/libraries/**)",
			g, e, element, site, pluginDir))

	default:
		// Heurística: sin prefijo com_/mod_ y sin forma grupo/elemento o
		// libraryname namespaced, el elemento puede ser una plantilla o una
		// librería sin namespace. Las plantillas viven en una ubicación fija
		// y barata de comprobar (templates/<element>/templateDetails.xml);
		// se intentan primero. Si ninguna calza, se cae al recorrido
		// recursivo de librerías (más costoso, así que va al final).
		var tplDirs []string
		if wantSite {
			tplDirs = append(tplDirs, "templates/"+element)
		}
		if wantAdmin {
			tplDirs = append(tplDirs, "administrator/templates/"+element)
		}
		var hits []manifestHit
		for _, d := range tplDirs {
			if rel, m := findFirstInDir(fsys, d, manifest.Template); m != nil {
				hits = append(hits, manifestHit{rel, m})
			}
		}
		if len(hits) > 0 {
			return resolveHits(hits, nil)
		}

		libHits, err := findLibrary(fsys, element)
		if err != nil {
			return manifest.InstallTarget{}, "", "", err
		}
		return resolveHits(libHits, fmt.Errorf("no se encontró una plantilla ni una librería instalada para %s en %s (buscado en %s y administrator/manifests/libraries/**)", element, site, strings.Join(tplDirs, ", ")))
	}
}

// findFirstInDir devuelve, en orden determinista (nombre de archivo
// ordenado), el primer .xml de dirRel que parsee con Type == want. Si dirRel
// no existe o ningún .xml calza, devuelve ("", nil): "sin candidato aquí", no
// un error — el llamante prueba la siguiente ubicación conocida.
func findFirstInDir(fsys *safefs.FS, dirRel string, want manifest.Type) (string, *manifest.Manifest) {
	entries, err := fsys.ReadDir(dirRel)
	if err != nil {
		return "", nil
	}
	names := make([]string, 0, len(entries))
	for _, de := range entries {
		if de.IsDir() || !strings.HasSuffix(de.Name(), ".xml") {
			continue
		}
		names = append(names, de.Name())
	}
	sort.Strings(names)
	for _, name := range names {
		rel := dirRel + "/" + name
		f, err := fsys.Open(rel)
		if err != nil {
			continue
		}
		m, perr := manifest.Parse(f)
		f.Close()
		if perr != nil || m.Type != want {
			continue
		}
		return rel, m
	}
	return "", nil
}

// findLibrary recorre administrator/manifests/libraries/** (única ubicación
// conocida de manifiestos de librería, posiblemente anidada) y devuelve TODOS
// los .xml que parseen como librería cuya identidad (manifest.ExtensionKey,
// derivada de <libraryname> o, en su ausencia, del nombre) sea exactamente
// element. Orden determinista (rutas ordenadas).
func findLibrary(fsys *safefs.FS, element string) ([]manifestHit, error) {
	root := "administrator/manifests/libraries"
	paths, err := walkXMLFiles(fsys, root)
	if err != nil {
		// El directorio de librerías no existe en este árbol: no es un error,
		// simplemente no hay candidatos.
		return nil, nil
	}
	var hits []manifestHit
	for _, rel := range paths {
		f, err := fsys.Open(rel)
		if err != nil {
			continue
		}
		m, perr := manifest.Parse(f)
		f.Close()
		if perr != nil || m.Type != manifest.Library {
			continue
		}
		if manifest.ExtensionKey(manifest.Library, rel, m) != element {
			continue
		}
		hits = append(hits, manifestHit{rel, m})
	}
	return hits, nil
}

// walkXMLFiles recorre root recursivamente (vía safefs.ReadDir, sin seguir
// enlaces simbólicos como directorios: os.DirEntry reporta el tipo del propio
// enlace) y devuelve las rutas de los .xml encontrados, en orden determinista.
func walkXMLFiles(fsys *safefs.FS, root string) ([]string, error) {
	var out []string
	var walk func(rel string) error
	walk = func(rel string) error {
		entries, err := fsys.ReadDir(rel)
		if err != nil {
			return err
		}
		for _, de := range entries {
			childRel := rel + "/" + de.Name()
			if de.IsDir() {
				if err := walk(childRel); err != nil {
					return err
				}
				continue
			}
			if strings.HasSuffix(de.Name(), ".xml") {
				out = append(out, childRel)
			}
		}
		return nil
	}
	if err := walk(root); err != nil {
		return nil, err
	}
	sort.Strings(out)
	return out, nil
}

// resolveHits decide el resultado final a partir de los candidatos ya
// filtrados por tipo/identidad para una ubicación (o grupo de ubicaciones):
//   - 0 candidatos → notFound (si no es nil; los llamantes que encadenan un
//     fallback, como plantilla→librería, pasan nil aquí y arman su propio
//     error tras agotar todas las ubicaciones).
//   - 1 candidato → éxito.
//   - >1 candidatos → si todos comparten la misma identidad (mismo Type Y
//     mismo ElementKey), no hay ambigüedad real: se toma el primero en orden
//     determinista. Si difieren en Type O en ElementKey — incluido el caso
//     de un plugin "grupo/elem" y una librería <libraryname> que coinciden en
//     el TEXTO de su clave pero son extensiones de tipo distinto (p.ej.
//     "sys/tool" como plugin Y como libraryname) — es una ambigüedad genuina
//     (Principio IV): error enumerando las rutas, el operador desambigua con
//     --group/--client.
func resolveHits(hits []manifestHit, notFound error) (manifest.InstallTarget, string, string, error) {
	if len(hits) == 0 {
		if notFound != nil {
			return manifest.InstallTarget{}, "", "", notFound
		}
		return manifest.InstallTarget{}, "", "", fmt.Errorf("no se encontró ningún manifiesto instalado que calzara")
	}
	targets := make([]manifest.InstallTarget, len(hits))
	for i, h := range hits {
		targets[i] = h.m.ResolveInstall(h.path)
	}
	key := targets[0].ElementKey
	typ := targets[0].Type
	for _, t := range targets[1:] {
		if t.ElementKey != key || t.Type != typ {
			paths := make([]string, len(hits))
			for i, h := range hits {
				paths[i] = h.path
			}
			return manifest.InstallTarget{}, "", "", fmt.Errorf(
				"varios manifiestos instalados casan con identidad distinta: %s; desambigua con --group/--client",
				strings.Join(paths, ", "))
		}
	}
	m := hits[0].m
	updateURL := ""
	if len(m.UpdateServers) > 0 {
		updateURL = m.UpdateServers[0]
	}
	return targets[0], m.Version, updateURL, nil
}
