package corediff

import "testing"

func TestClassifyMissing(t *testing.T) {
	cases := []struct{ rel, want string }{
		// ejecutable / código → nunca se degrada
		{"libraries/src/Session/Session.php", "executable"},
		{"components/com_x/x.phar", "executable"},
		// ausencia esperada: defaults dist/doc
		{"LICENSE.txt", "expected_absent"},
		{"README.txt", "expected_absent"},
		{"htaccess.txt", "expected_absent"},
		{"web.config.txt", "expected_absent"},
		{"robots.txt.dist", "expected_absent"},
		// ausencia esperada: runtime (cacheLogDirs + tmp), NO images
		{"tmp/index.html", "expected_absent"},
		{"cache/foo.php", "executable"}, // .php gana (ejecutable) aunque sea runtime
		{"administrator/cache/x.txt", "expected_absent"},
		{"media/cache/asset.css", "expected_absent"}, // media/cache es runtime (gana antes que media/)
		// asset inerte: images/ y media/ (no-cache) + exts imagen/fuente
		{"images/sampledata/apple.jpg", "inert_asset"},
		{"images/banners/osmbanner1.png", "inert_asset"},
		{"media/vendor/tinymce/skin.css", "inert_asset"},  // media/ (no cache) → asset
		{"templates/x/fonts/roboto.woff2", "inert_asset"}, // extensión de fuente
		{"foo.ico", "inert_asset"},
		// desconocido no-código → "" (se quedará medium): conservador
		{"administrator/manifests/files/joomla.xml", ""},
		{"language/en-GB/en-GB.ini", ""},
		{"index.html", ""},
	}
	for _, c := range cases {
		if got := ClassifyMissing(c.rel); got != c.want {
			t.Errorf("ClassifyMissing(%q) = %q, want %q", c.rel, got, c.want)
		}
	}
}
