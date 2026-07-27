package fingerprint

import "testing"

// T039: lector tolerante de la versión declarada.
func TestParseDeclared(t *testing.T) {
	cases := map[string]string{
		"<?php class Version { const MAJOR_VERSION = 5; const MINOR_VERSION = 1; const PATCH_VERSION = 4; }": "5.1.4",
		"<?php class JVersion { public $RELEASE = '3.10'; public $DEV_LEVEL = '12'; }":                       "3.10.12",
		"<extension><version>4.4.0</version></extension>":                                                    "4.4.0",
		"<?php // manipulado, sin constantes":                                                                "",
		"":                                                                                                   "",
	}
	for content, want := range cases {
		if got := parseDeclared([]byte(content)); got != want {
			t.Errorf("parseDeclared(%.40q) = %q, quiere %q", content, got, want)
		}
	}
}
