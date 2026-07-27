package lab

import (
	"os"
	"path/filepath"
)

// D3 fixture: un componente con <scriptfile> (script de instalación). El script
// es un ejecutable declarado por el manifiesto; sin reconocer <scriptfile> sale
// como ejecutable no declarado (J0W-EXT-001 High falso). Reproduce el patrón
// real de com_j2xml/script.php y com_sppagebuilder/installer.script.php.

const scriptComManifestPath = "administrator/components/com_scripted/scripted.xml"

const scriptComManifest = `<?xml version="1.0" encoding="UTF-8"?>
<extension type="component" method="upgrade">
	<name>Scripted Component</name>
	<version>1.0.0</version>
	<scriptfile>installer.script.php</scriptfile>
	<administration>
		<files folder="admin"><filename>scripted.php</filename></files>
	</administration>
</extension>
`

func scriptExtFiles() map[string]string {
	return map[string]string{
		scriptComManifestPath:                                scriptComManifest,
		"administrator/components/com_scripted/scripted.php": "<?php\n// com_scripted admin\n",
		// El script de instalación, declarado por <scriptfile>.
		"administrator/components/com_scripted/installer.script.php": "<?php\nclass Com_ScriptedInstallerScript { public function install($p) { return true; } }\n",
	}
}

// InstallScriptExt escribe el componente con <scriptfile> en un árbol existente.
func InstallScriptExt(root string) error {
	for rel, content := range scriptExtFiles() {
		full := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			return err
		}
	}
	return nil
}
