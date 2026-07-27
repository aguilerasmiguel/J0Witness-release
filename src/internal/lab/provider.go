package lab

import "fmt"

// MiniProvider implementa corpus.BaseProvider con la mini-distribución.
type MiniProvider struct{}

// WriteBase materializa la instalación base.
func (MiniProvider) WriteBase(dir, version string) error { return WriteTree(dir, version) }

// FileContent devuelve el contenido de un archivo de la distribución.
func (MiniProvider) FileContent(version, rel string) ([]byte, bool) {
	c, ok := MiniFiles(version)[rel]
	return []byte(c), ok
}

// InstallExtension instala el componente sintético com_labext (implementa
// corpus.ExtProvider para la feature 002).
func (MiniProvider) InstallExtension(dir string) error { return InstallLabExt(dir) }

// ExtManifestPath devuelve la ruta del manifiesto de com_labext.
func (MiniProvider) ExtManifestPath() string { return LabExtManifestPath() }

// ExtPackage devuelve el "paquete oficial" sintético de com_labext (implementa
// corpus.ExtBaselineProvider para `add_extension_baseline`, fase 2a). Con
// version vacío, declara la versión real (2.3.1, la misma que instala
// InstallLabExt); con version no vacío, sustituye la declarada (recipe de
// versión no coincidente).
func (MiniProvider) ExtPackage(version string) []byte {
	if version == "" {
		return LabExtPackage()
	}
	return LabExtPackageWithVersion(version)
}

// InstallDisplayExtension instala el componente sintético com_dispname, cuyo
// `<name>` de display difiere del directorio (implementa
// corpus.DisplayExtProvider; regresión de D1).
func (MiniProvider) InstallDisplayExtension(dir string) error { return InstallDispExt(dir) }

// InstallD2Fixtures instala las fixtures de D2: librería por <libraryname>, pack
// de idioma y componente que comparte la carpeta de idioma (implementa
// corpus.D2Provider).
func (MiniProvider) InstallD2Fixtures(dir string) error { return InstallD2Fixtures(dir) }

// InstallScriptExtension instala el componente com_scripted con <scriptfile>
// (implementa corpus.ScriptExtProvider; regresión de D3).
func (MiniProvider) InstallScriptExtension(dir string) error { return InstallScriptExt(dir) }

// Kinds reconocidos por los métodos *Kind (implementan corpus.MultiExtProvider,
// fase 2c Task 7): generalizan add_extension/add_extension_baseline a los 5
// tipos verificables, en vez de duplicar operaciones por tipo. "" y
// "component" son EQUIVALENTES y preservan el comportamiento 2a exacto
// (com_labext); las recetas existentes que no declaran `kind` no cambian.
const (
	KindComponent = "component"
	KindModule    = "module"
	KindPlugin    = "plugin"
	KindTemplate  = "template"
	KindLibrary   = "library"
)

// InstallExtensionKind instala la fixture de laboratorio del tipo kind
// (implementa corpus.MultiExtProvider).
func (MiniProvider) InstallExtensionKind(kind, dir string) error {
	switch kind {
	case "", KindComponent:
		return InstallLabExt(dir)
	case KindModule:
		return InstallLabMod(dir)
	case KindPlugin:
		return InstallLabPlg(dir)
	case KindTemplate:
		return InstallLabTpl(dir)
	case KindLibrary:
		return InstallLabLib(dir)
	default:
		return fmt.Errorf("kind de extensión desconocido: %q", kind)
	}
}

// ExtPackageKind devuelve el "paquete oficial" de la fixture de kind
// (implementa corpus.MultiExtProvider); version, si no está vacío, sustituye
// la versión declarada (recipe de "versión no coincidente"), igual que
// ExtPackage para el componente.
func (MiniProvider) ExtPackageKind(kind, version string) ([]byte, error) {
	switch kind {
	case "", KindComponent:
		return MiniProvider{}.ExtPackage(version), nil
	case KindModule:
		if version == "" {
			return LabModPackage(), nil
		}
		return LabModPackageWithVersion(version), nil
	case KindPlugin:
		if version == "" {
			return LabPlgPackage(), nil
		}
		return LabPlgPackageWithVersion(version), nil
	case KindTemplate:
		if version == "" {
			return LabTplPackage(), nil
		}
		return LabTplPackageWithVersion(version), nil
	case KindLibrary:
		if version == "" {
			return LabLibPackage(), nil
		}
		return LabLibPackageWithVersion(version), nil
	default:
		return nil, fmt.Errorf("kind de extensión desconocido: %q", kind)
	}
}

// ElementKeyKind devuelve la clave estable (manifest.ExtensionKey) de la
// fixture de kind: el `elemento` con el que el harness invoca
// `extension add <elemento> <sitio> <paquete>` (implementa
// corpus.MultiExtProvider).
func (MiniProvider) ElementKeyKind(kind string) string {
	switch kind {
	case "", KindComponent:
		return LabExtName
	case KindModule:
		return LabModElementKey()
	case KindPlugin:
		return LabPlgElementKey()
	case KindTemplate:
		return LabTplElementKey()
	case KindLibrary:
		return LabLibElementKey()
	default:
		return ""
	}
}
