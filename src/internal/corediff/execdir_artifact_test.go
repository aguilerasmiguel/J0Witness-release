package corediff

import "testing"

func TestIsJoomlaRuntimeArtifact(t *testing.T) {
	cases := []struct {
		name string
		rel  string
		head string
		want bool
	}{
		{"cache serializado", "administrator/cache/com_x/abc.php", `<?php die("Access Denied"); ?>#x#a:1:{}`, true},
		{"log con almohadilla", "administrator/logs/joomla_update.php", "#\n#<?php die('Forbidden.'); ?>\n#Date", true},
		{"log con contenido antes de la guarda no es artefacto", "administrator/logs/x.php", "#Foo\n#<?php die('x');", false},
		{"autoload jexec", "administrator/cache/autoload_psr4.php", "<?php\ndefined('_JEXEC') or die;\nreturn [];", true},
		{"cache raiz del sitio", "cache/foo.php", `<?php die("x"); ?>`, true},
		{"media cache", "media/cache/bar.php", `<?php die("x"); ?>`, true},
		{"webshell sin guarda en cache", "administrator/cache/evil.php", "<?php system($_GET['c']);", false},
		{"php en images NO es artefacto", "images/cache.php", `<?php die("x"); ?>`, false},
		{"php en tmp NO es artefacto", "tmp/x.php", `<?php die("x"); ?>`, false},
		{"cabecera vacia", "administrator/cache/x.php", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := IsJoomlaRuntimeArtifact(c.rel, []byte(c.head)); got != c.want {
				t.Fatalf("IsJoomlaRuntimeArtifact(%q) = %v, quiero %v", c.rel, got, c.want)
			}
		})
	}
}
