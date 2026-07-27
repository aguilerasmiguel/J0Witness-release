#!/usr/bin/env python3
"""cataloggen — genera el catálogo real de baselines Joomla (R5/R6/R7).

Herramienta auxiliar de mantenimiento: corre en la máquina del mantenedor o en
CI, NUNCA en el host analizado. Descarga cada release oficial, verifica su
SHA-256 contra el que publica el propio proyecto Joomla, deriva el manifiesto
ruta→hash, selecciona el conjunto testigo por rama (R7) y acumula la tabla de
archivos conocidos (R6 enmendado). Emite data/catalog/catalog.json listo para
embeber.

Uso:
    python3 tools/cataloggen/cataloggen.py --series 3.9 3.10 4 5 --out data
    python3 tools/cataloggen/cataloggen.py --only 5.4.7 --out /tmp/cat --verify

La cobertura de v1 (R1): series 4.x y 5.x completas + 3.9/3.10.

R6 enmendado (ver specs/001-*/design-catalogo-real.md): la fuente de los
obsoletos ya no son los arrays de administrator/components/com_admin/script.php
sino el diff de manifiestos. El catálogo emite una tabla `known_files`
(ruta → todos los hashes con los que alguna release la distribuyó) y j0witness
deriva los obsoletos de una versión restándole el manifiesto de su baseline.
Almacenarlos versión a versión duplicaba tanto que el catálogo pasaba de 50 MB.
"""

import argparse
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
import zipfile
from collections import defaultdict

GITHUB_RELEASES = "https://api.github.com/repos/joomla/joomla-cms/releases?per_page=100&page={page}"
PACKAGE_URL = (
    "https://github.com/joomla/joomla-cms/releases/download/"
    "{tag}/Joomla_{tag}-Stable-Full_Package.zip"
)
# Firmas publicadas por el propio proyecto Joomla: segunda fuente independiente
# de GitHub, disponible para todas las series (verificado hasta 3.9).
SIGNATURES_URL = "https://downloads.joomla.org/api/v1/signatures/cms/{dashed}"
PACKAGE_NAME = "Joomla_{tag}-Stable-Full_Package.zip"

WITNESS_TARGET = 48  # tamaño objetivo del conjunto testigo por rama (R7)
WITNESS_DIR_HINTS = ("libraries/src/", "administrator/", "media/", "language/", "includes/")


def vkey(tag: str) -> tuple:
    """Orden por componentes numéricos: 3.9.0 antes que 3.10.0, nunca por cadena."""
    return tuple(int(x) for x in tag.split("."))


def branch(tag: str) -> str:
    """La rama de una versión es su major: 3.9 y 3.10 comparten árbol."""
    return tag.split(".")[0]


def fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "j0witness-cataloggen"})
    with urllib.request.urlopen(req, timeout=300) as r:
        return r.read()


def list_stable_tags(series: list[str]) -> list[str]:
    tags, page = [], 1
    while True:
        releases = json.loads(fetch(GITHUB_RELEASES.format(page=page)))
        if not releases:
            break
        for rel in releases:
            tag = rel.get("tag_name", "")
            if rel.get("prerelease") or rel.get("draft"):
                continue
            if re.fullmatch(r"\d+\.\d+\.\d+", tag) and any(
                tag.startswith(s + ".") or tag == s for s in series
            ):
                tags.append(tag)
        page += 1
    return sorted(set(tags), key=vkey)


def cached_download(tag: str, cache: str) -> bytes:
    """Descarga el paquete oficial o lo lee del caché. Con 2,74 GB en juego, un
    fallo tardío no puede obligar a repetir las descargas anteriores."""
    path = os.path.join(cache, "pkg", f"{tag}.zip")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if os.path.exists(path) and os.path.getsize(path) > 0:
        with open(path, "rb") as f:
            return f.read()
    url = PACKAGE_URL.format(tag=tag)
    print(f"cataloggen: descargando {url}", file=sys.stderr)
    data = fetch(url)
    tmp = path + ".part"
    with open(tmp, "wb") as f:
        f.write(data)
    os.replace(tmp, path)
    return data


def published_sha256(tag: str, cache: str) -> str | None:
    """SHA-256 que el proyecto Joomla publica para el paquete completo de esta
    release. None si la API no la cubre: se registra como no verificada en vez
    de afirmar una verificación que no ocurrió."""
    path = os.path.join(cache, "sig", f"{tag}.json")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if os.path.exists(path) and os.path.getsize(path) > 0:
        with open(path, "rb") as f:
            raw = f.read()
    else:
        try:
            raw = fetch(SIGNATURES_URL.format(dashed=tag.replace(".", "-")))
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError) as e:
            print(f"cataloggen: sin firmas para {tag}: {e}", file=sys.stderr)
            return None
        with open(path, "wb") as f:
            f.write(raw)
    try:
        files = json.loads(raw).get("files", [])
    except json.JSONDecodeError:
        return None
    want = PACKAGE_NAME.format(tag=tag)
    for entry in files:
        if entry.get("filename") == want:
            return entry.get("sha256")
    return None


def manifest(pkg: bytes) -> dict[str, str]:
    """Manifiesto ruta→sha256 de todas las entradas de archivo del paquete."""
    out = {}
    with zipfile.ZipFile(io.BytesIO(pkg)) as z:
        for info in z.infolist():
            if info.is_dir():
                continue
            out[info.filename] = hashlib.sha256(z.read(info)).hexdigest()
    return out


def select_witnesses(manifests: dict[str, dict[str, str]]) -> dict[str, list[str]]:
    """Criterios R7, aplicados por rama: presente en todas las releases *de la
    rama*, máxima discriminación entre versiones adyacentes, disperso, acotado.

    Por rama y no globalmente: los archivos que sobreviven de 3.9 a 5.4 son
    pocos y no son los que mejor distinguen 5.4.6 de 5.4.7, que es donde la
    inferencia de versión se juega la precisión. Medido: la selección global
    da 39 testigos con margen mediano 7, insuficiente en las tres ramas.

    Devuelve ruta → ramas que la seleccionaron. Una ruta puede servir a varias;
    j0witness acota la votación a la rama de la candidata líder, así que los
    testigos de otras ramas no inflan el denominador de la confianza.
    """
    picked_all: dict[str, list[str]] = defaultdict(list)
    for br, tags in group_by_branch(manifests).items():
        common = set.intersection(*(set(manifests[t]) for t in tags))
        scored = []
        for path in common:
            if not path.startswith(WITNESS_DIR_HINTS):
                continue
            distinct = sum(
                1
                for a, b in zip(tags, tags[1:])
                if manifests[a][path] != manifests[b][path]
            )
            if distinct:
                scored.append((distinct, path))
        scored.sort(reverse=True)
        picked, per_dir = [], defaultdict(int)
        for _, path in scored:
            top = path.split("/", 1)[0]
            if per_dir[top] >= WITNESS_TARGET // 4:
                continue
            picked.append(path)
            per_dir[top] += 1
            if len(picked) >= WITNESS_TARGET:
                break
        print(
            f"cataloggen: rama {br}.x — {len(tags)} releases, {len(common)} rutas "
            f"comunes, {len(scored)} discriminantes, {len(picked)} testigos",
            file=sys.stderr,
        )
        for p in picked:
            picked_all[p].append(br)
    return {p: picked_all[p] for p in sorted(picked_all)}


def group_by_branch(manifests: dict[str, dict[str, str]]) -> dict[str, list[str]]:
    by: dict[str, list[str]] = defaultdict(list)
    for tag in sorted(manifests, key=vkey):
        by[branch(tag)].append(tag)
    return dict(by)


def margins(manifests: dict[str, dict[str, str]],
            witnesses: dict[str, list[str]]) -> dict[str, dict]:
    """Por rama: cuántos de sus testigos distinguen cada par de versiones
    adyacentes, y el umbral de confianza alta que aplicará j0witness
    (margen >= testigos_de_la_rama / 3, con la votación acotada a la rama)."""
    out = {}
    for br, tags in group_by_branch(manifests).items():
        own = [p for p, brs in witnesses.items() if br in brs]
        pairs = {}
        for a, b in zip(tags, tags[1:]):
            pairs[b] = sum(
                1
                for w in own
                if w in manifests[a] and w in manifests[b]
                and manifests[a][w] != manifests[b][w]
            )
        out[br] = {"witnesses": len(own), "threshold": len(own) // 3, "pairs": pairs}
    return out


def report_margins(data: dict[str, dict]) -> None:
    """Informativo, no bloqueante: hay transiciones donde ningún conjunto puede
    llegar al umbral (Joomla 3.9.17 y 3.9.18 difieren en 7 archivos del
    conjunto común), y ahí la confianza media es la respuesta honesta."""
    print("cataloggen: margen de testigos entre versiones adyacentes", file=sys.stderr)
    for br, d in data.items():
        if not d["pairs"]:
            continue
        worst_tag = min(d["pairs"], key=lambda t: d["pairs"][t])
        bajo = sum(1 for n in d["pairs"].values() if n < d["threshold"])
        print(
            f"  rama {br}.x — {d['witnesses']} testigos, umbral {d['threshold']}; "
            f"margen mínimo {d['pairs'][worst_tag]} (→ {worst_tag}); "
            f"{bajo}/{len(d['pairs'])} transiciones bajo el umbral",
            file=sys.stderr,
        )


def known_files(manifests: dict[str, dict[str, str]]) -> list[dict]:
    """Tabla global ruta → todos los hashes con los que alguna release la
    distribuyó (R6 enmendado)."""
    hist: dict[str, set[str]] = defaultdict(set)
    for m in manifests.values():
        for path, sha in m.items():
            hist[path].add(sha)
    return [
        {"path": p, "hashes": sorted(hist[p])} for p in sorted(hist)
    ]


def build_catalog(tags: list[str], manifests: dict[str, dict[str, str]],
                  releases: list[dict]) -> tuple[dict, dict[str, dict]]:
    witnesses = select_witnesses(manifests)
    marg = margins(manifests, witnesses)
    report_margins(marg)
    return {
        "catalog_version": "joomla-" + tags[-1] if tags else "empty",
        "cms": "joomla",
        "releases": releases,
        "witnesses": [
            {
                "path": p,
                "branches": sorted(brs),
                "hashes": {t: manifests[t][p] for t in tags if p in manifests[t]},
            }
            for p, brs in witnesses.items()
        ],
        "known_files": known_files(manifests),
    }, marg


def verify(catalog_path: str, cache: str, tags: list[str], binary: str,
           marg: dict[str, dict]) -> int:
    """Auto-validación: por cada rama, extraer su última release y comprobar que
    j0witness infiere exactamente su versión.

    La versión exacta es innegociable. La confianza se exige alta solo cuando el
    margen de esa transición llega al umbral: hay pares de releases de Joomla
    que difieren en tan pocos archivos que ningún conjunto testigo puede
    distinguirlos con holgura, y ahí la confianza media es el resultado
    correcto, no un fallo del catálogo.
    """
    by_branch = defaultdict(list)
    for t in tags:
        by_branch[branch(t)].append(t)
    failures = 0
    for br in sorted(by_branch):
        tag = sorted(by_branch[br], key=vkey)[-1]
        pkg = os.path.join(cache, "pkg", f"{tag}.zip")
        tmp = tempfile.mkdtemp(prefix=f"cataloggen-verify-{tag}-")
        try:
            tree, state = os.path.join(tmp, "tree"), os.path.join(tmp, "state")
            os.makedirs(tree)
            with zipfile.ZipFile(pkg) as z:
                z.extractall(tree)
            # --cache-dir dentro del temporal: la verificación no debe tocar el
            # caché de baselines real del usuario.
            common = ["--catalog", catalog_path, "--workdir", state,
                      "--cache-dir", os.path.join(tmp, "cache")]
            add = subprocess.run(
                [binary, "baseline", "add", pkg] + common,
                capture_output=True, text=True)
            if add.returncode != 0:
                print(f"cataloggen: verify {tag} — baseline add falló: "
                      f"{add.stderr.strip()}", file=sys.stderr)
                failures += 1
                continue
            scan = subprocess.run(
                [binary, "scan", tree] + common,
                capture_output=True, text=True)
            try:
                doc = json.loads(scan.stdout)
            except json.JSONDecodeError:
                print(f"cataloggen: verify {tag} — scan no emitió JSON: "
                      f"{scan.stderr.strip()[:400]}", file=sys.stderr)
                failures += 1
                continue
            ver = doc.get("version_inference") or {}
            inferred, conf = ver.get("inferred"), ver.get("confidence")
            d = marg.get(br, {})
            margen = d.get("pairs", {}).get(tag)
            umbral = d.get("threshold", 0)
            # Alcanzable: alta si el margen llega al umbral; media si no.
            esperada = "high" if margen is None or margen >= umbral else "medium"
            ok = inferred == tag and conf in (
                ("high",) if esperada == "high" else ("high", "medium"))
            print(f"cataloggen: verify rama {br}.x ({tag}) — inferida={inferred} "
                  f"confianza={conf} (margen {margen}/{umbral}, esperada "
                  f"{esperada}) {'OK' if ok else 'FALLO'}", file=sys.stderr)
            if not ok:
                failures += 1
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    return 1 if failures else 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--series", nargs="+", default=["3.9", "3.10", "4", "5"])
    ap.add_argument(
        "--only",
        nargs="+",
        help="versiones exactas (omite el listado de la API); para catálogos parciales de validación",
    )
    ap.add_argument("--out", default="data")
    ap.add_argument("--cache", default=".cache/cataloggen",
                    help="caché de paquetes y firmas; reanudable")
    ap.add_argument("--verify", action="store_true",
                    help="tras generar, escanear una release por rama y comprobar la inferencia")
    ap.add_argument("--binary", default="build/j0witness",
                    help="binario j0witness usado por --verify")
    args = ap.parse_args()

    tags = sorted(set(args.only), key=vkey) if args.only else list_stable_tags(args.series)
    print(f"cataloggen: {len(tags)} releases en cobertura", file=sys.stderr)

    releases, manifests, unverified = [], {}, []
    for i, tag in enumerate(tags, 1):
        pkg = cached_download(tag, args.cache)
        got = hashlib.sha256(pkg).hexdigest()
        want = published_sha256(tag, args.cache)
        if want is None:
            source = "unverified"
            unverified.append(tag)
        elif want != got:
            print(f"cataloggen: CHECKSUM NO COINCIDE en {tag}\n"
                  f"  publicado por joomla.org: {want}\n"
                  f"  del paquete descargado:   {got}", file=sys.stderr)
            return 1
        else:
            source = "joomla-signatures"
        releases.append({"version": tag, "package_sha256": got,
                         "checksum_source": source})
        manifests[tag] = manifest(pkg)
        del pkg
        if i % 10 == 0 or i == len(tags):
            print(f"cataloggen: [{i}/{len(tags)}] {tag}", file=sys.stderr)

    if unverified:
        print(f"cataloggen: {len(unverified)} releases sin checksum publicado: "
              f"{', '.join(unverified)}", file=sys.stderr)

    catalog, marg = build_catalog(tags, manifests, releases)
    os.makedirs(f"{args.out}/catalog", exist_ok=True)
    out = f"{args.out}/catalog/catalog.json"
    with open(out, "w", encoding="utf-8") as f:
        json.dump(catalog, f, indent=2, sort_keys=True)
        f.write("\n")
    size = os.path.getsize(out)
    pairs = sum(len(k["hashes"]) for k in catalog["known_files"])
    print(f"cataloggen: catálogo escrito en {out} — {len(releases)} releases, "
          f"{len(catalog['witnesses'])} testigos, {len(catalog['known_files'])} "
          f"rutas conocidas ({pairs} pares ruta-hash), {size / 1e6:.1f} MB",
          file=sys.stderr)

    if args.verify:
        return verify(out, args.cache, tags, args.binary, marg)
    return 0


if __name__ == "__main__":
    sys.exit(main())
