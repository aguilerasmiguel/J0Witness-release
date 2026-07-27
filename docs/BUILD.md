# Building J0Witness · Compilar J0Witness

*English below · Español más abajo.*

---

## English

### Requirements

- **Go 1.25 or newer.** No other toolchain is needed.
- No C compiler, no CGO, no system libraries. SQLite is provided by a pure-Go
  driver (`modernc.org/sqlite`), so the default binary has **zero** non-Go
  dependencies.
- Linux is the primary target (amd64 and arm64). The code is portable Go; other
  platforms are untested.

### Build the single static binary

From the `src/` directory of this release:

```sh
cd src
CGO_ENABLED=0 go build -trimpath -ldflags "-buildid=" -o j0witness ./cmd/j0witness
```

That produces a self-contained static binary. Copy `j0witness` to the target host
and run it — nothing else to install.

A `Makefile` is included with convenience targets:

```sh
make build                 # build ./build/j0witness (stamps the version)
make build-all             # linux/amd64 + linux/arm64 static binaries
make test                  # full test suite (includes the hermetic corpus)
make verify-reproducible   # double-build → identical SHA-256 (determinism gate)
```

### Verify the build is reproducible

Determinism is a forensic property here, so the release ships a gate for it:

```sh
make verify-reproducible
```

It builds the binary twice, independently, and asserts the two SHA-256 hashes are
identical. If they diverge, the build is not reproducible and the output should not
be trusted as evidence — investigate before shipping.

### Run the tests

```sh
go test ./...
```

Every detector ships with positive and negative corpus cases (`testdata/corpus/`),
so a green suite exercises both "should fire" and "must stay silent" paths.

### First run

```sh
# Ingest an official Joomla package once (downloaded separately; offline):
./j0witness baseline add Joomla_5.1.4-Stable-Full_Package.zip

# Scan a target tree:
./j0witness scan /var/www/mysite --format text
```

---

## Español

### Requisitos

- **Go 1.25 o superior.** No se necesita ningún otro toolchain.
- Sin compilador de C, sin CGO, sin librerías del sistema. SQLite lo provee un
  driver en Go puro (`modernc.org/sqlite`), así que el binario por defecto tiene
  **cero** dependencias fuera de Go.
- Linux es el objetivo primario (amd64 y arm64). El código es Go portable; otras
  plataformas no están probadas.

### Compilar el binario estático único

Desde el directorio `src/` de este release:

```sh
cd src
CGO_ENABLED=0 go build -trimpath -ldflags "-buildid=" -o j0witness ./cmd/j0witness
```

Eso produce un binario estático autocontenido. Copia `j0witness` al host objetivo y
ejecútalo — no hay nada más que instalar.

Se incluye un `Makefile` con targets de conveniencia:

```sh
make build                 # compila ./build/j0witness (sella la versión)
make build-all             # binarios estáticos linux/amd64 + linux/arm64
make test                  # suite completa (incluye el corpus hermético)
make verify-reproducible   # doble build → mismo SHA-256 (gate de determinismo)
```

### Verificar que el build es reproducible

Aquí el determinismo es una propiedad forense, así que el release trae un gate:

```sh
make verify-reproducible
```

Compila el binario dos veces, de forma independiente, y asegura que los dos hashes
SHA-256 son idénticos. Si divergen, el build no es reproducible y la salida no
debería tomarse como evidencia — investígalo antes de distribuir.

### Correr los tests

```sh
go test ./...
```

Cada detector nace con casos de corpus positivo y negativo (`testdata/corpus/`), así
que una suite verde ejercita tanto el camino "debe disparar" como el "debe quedar
en silencio".

### Primer uso

```sh
# Incorporar un paquete oficial de Joomla una vez (descargado aparte; offline):
./j0witness baseline add Joomla_5.1.4-Stable-Full_Package.zip

# Escanear un árbol objetivo:
./j0witness scan /var/www/mi-sitio --format text
```
