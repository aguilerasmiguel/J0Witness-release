// j0witness — analizador de integridad y forense offline para instalaciones
// Joomla. Observa y testifica; no repara, no limpia, no restaura.
package main

import (
	"os"

	"j0witness/internal/cli"
)

func main() {
	os.Exit(cli.Main(os.Args[1:], os.Stdout, os.Stderr))
}
