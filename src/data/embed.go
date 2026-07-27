// Package data embebe el catálogo de releases y las listas de obsoletos en el
// binario (R2: el binario siempre sabe qué necesita y cómo verificarlo, sin
// red).
package data

import _ "embed"

//go:embed catalog/catalog.json
var CatalogJSON []byte
