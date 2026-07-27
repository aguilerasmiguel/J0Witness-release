package manifest

import "testing"

func TestExtensionKey(t *testing.T) {
	lib := &Manifest{Type: Library, LibraryName: "vendor/synthlib"}
	cases := []struct {
		name string
		typ  Type
		path string
		m    *Manifest
		want string
	}{
		{"component", Component, "administrator/components/com_x/x.xml", &Manifest{Type: Component}, "com_x"},
		{"module-site", Module, "modules/mod_x/mod_x.xml", &Manifest{Type: Module}, "mod_x"},
		{"module-admin", Module, "administrator/modules/mod_x/mod_x.xml", &Manifest{Type: Module}, "mod_x@administrator"},
		{"plugin", Plugin, "plugins/system/foo/foo.xml", &Manifest{Type: Plugin}, "system/foo"},
		{"template-site", Template, "templates/cassiopeia/templateDetails.xml", &Manifest{Type: Template}, "cassiopeia"},
		{"template-admin", Template, "administrator/templates/atum/templateDetails.xml", &Manifest{Type: Template}, "atum@administrator"},
		{"library", Library, "administrator/manifests/libraries/synthlib.xml", lib, "vendor/synthlib"},
	}
	for _, c := range cases {
		if got := ExtensionKey(c.typ, c.path, c.m); got != c.want {
			t.Errorf("%s: ExtensionKey = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestResolveInstall(t *testing.T) {
	comp := &Manifest{Type: Component}
	target := comp.ResolveInstall("administrator/components/com_x/com_x.xml")
	if target.FilesRoot != "components/com_x" {
		t.Errorf("component FilesRoot = %q, want %q", target.FilesRoot, "components/com_x")
	}
	if target.AdminFilesRoot != "administrator/components/com_x" {
		t.Errorf("component AdminFilesRoot = %q, want %q", target.AdminFilesRoot, "administrator/components/com_x")
	}
	if target.ManifestDir != "administrator/components/com_x" {
		t.Errorf("component ManifestDir = %q, want %q", target.ManifestDir, "administrator/components/com_x")
	}
	if target.ElementKey != "com_x" {
		t.Errorf("component ElementKey = %q, want %q", target.ElementKey, "com_x")
	}

	plug := &Manifest{Type: Plugin}
	pTarget := plug.ResolveInstall("plugins/system/foo/foo.xml")
	if pTarget.FilesRoot != "plugins/system/foo" {
		t.Errorf("plugin FilesRoot = %q, want %q", pTarget.FilesRoot, "plugins/system/foo")
	}
	if pTarget.AdminFilesRoot != "" {
		t.Errorf("plugin AdminFilesRoot = %q, want empty", pTarget.AdminFilesRoot)
	}
	if pTarget.ManifestDir != "plugins/system/foo" {
		t.Errorf("plugin ManifestDir = %q, want %q", pTarget.ManifestDir, "plugins/system/foo")
	}
	if pTarget.ElementKey != "system/foo" {
		t.Errorf("plugin ElementKey = %q, want %q", pTarget.ElementKey, "system/foo")
	}
}
