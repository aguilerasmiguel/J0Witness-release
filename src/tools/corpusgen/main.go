// corpusgen materializa el corpus de laboratorio desde las recetas
// declarativas (Principio XI): make corpus.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"j0witness/internal/corpus"
	"j0witness/internal/lab"
)

func main() {
	recipes := flag.String("recipes", "testdata/corpus", "directorio de recetas YAML")
	out := flag.String("out", "build/corpus", "directorio de salida")
	flag.Parse()

	rs, err := corpus.LoadDir(*recipes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "corpusgen: %v\n", err)
		os.Exit(1)
	}
	if len(rs) == 0 {
		fmt.Fprintln(os.Stderr, "corpusgen: sin recetas")
		os.Exit(1)
	}
	// Catálogo y paquetes de laboratorio junto al corpus: permiten ejercitar
	// el binario real contra los casos (quickstart de laboratorio).
	if _, err := lab.WriteCatalog(*out); err != nil {
		fmt.Fprintf(os.Stderr, "corpusgen: catálogo: %v\n", err)
		os.Exit(1)
	}
	for _, v := range lab.MiniVersions {
		if _, err := lab.WritePackage(*out, v); err != nil {
			fmt.Fprintf(os.Stderr, "corpusgen: paquete %s: %v\n", v, err)
			os.Exit(1)
		}
	}
	provider := lab.MiniProvider{}
	for _, r := range rs {
		dir := filepath.Join(*out, r.Case)
		if err := os.RemoveAll(dir); err != nil {
			fmt.Fprintf(os.Stderr, "corpusgen: %v\n", err)
			os.Exit(1)
		}
		if err := r.Materialize(provider, dir); err != nil {
			fmt.Fprintf(os.Stderr, "corpusgen: caso %s: %v\n", r.Case, err)
			os.Exit(1)
		}
		fmt.Printf("corpusgen: %s → %s (%d mutaciones)\n", r.Case, dir, len(r.Mutations))
	}
}
