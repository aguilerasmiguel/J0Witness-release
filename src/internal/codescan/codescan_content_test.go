package codescan

import "testing"

func TestSuspiciousContent(t *testing.T) {
	if _, ok := SuspiciousContent([]byte("<h1>hola</h1>")); ok {
		t.Error("HTML inocuo no debe marcarse")
	}
	if pats, ok := SuspiciousContent([]byte("<?php eval(base64_decode($_POST['x'])); ?>")); !ok || len(pats) == 0 {
		t.Error("webshell PHP debe marcarse con patrón")
	}
}
