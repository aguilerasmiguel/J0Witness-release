package acquire

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"path/filepath"
	"strings"
	"sync"

	"github.com/gabriel-vasile/mimetype"
	"github.com/glaslos/tlsh"
	"golang.org/x/sync/errgroup"

	"j0witness/internal/safefs"
)

// tlshMinSize es el mínimo que exige el algoritmo para un digest estable (R3).
const tlshMinSize = 50

// HashResult completa un Item de tipo file con sus hashes y tipo real.
type HashResult struct {
	SHA256      string
	TLSH        string
	TLSHSkipped string // motivo de omisión ("" = calculado)
	MagicType   string
	ExtType     string
	ReadError   string
	BytesHashed int64
}

// extExpectations mapea extensiones cuyo contenido real debe coincidir; una
// discrepancia aquí es señal clásica de webshell disfrazado (FR-005).
var extExpectations = map[string]string{
	".png":  "image/png",
	".jpg":  "image/jpeg",
	".jpeg": "image/jpeg",
	".gif":  "image/gif",
	".webp": "image/webp",
	".ico":  "image/x-icon",
	".zip":  "application/zip",
	".gz":   "application/gzip",
	".pdf":  "application/pdf",
}

// HashFiles calcula hashes en paralelo (I/O-bound; FR-003/004/005). La
// memoria está acotada por jobs×fuzzyThreshold, independiente del archivo más
// grande (FR-051).
func HashFiles(fsys *safefs.FS, items []Item, jobs int, fuzzyThreshold int64) map[string]*HashResult {
	if jobs < 1 {
		jobs = 1
	}
	results := make(map[string]*HashResult, len(items))
	var mu sync.Mutex
	g := new(errgroup.Group)
	g.SetLimit(jobs)

	for i := range items {
		it := items[i]
		if it.Type != "file" || it.ReadError != "" || it.HardlinkDup {
			continue
		}
		g.Go(func() error {
			r := hashOne(fsys, it, fuzzyThreshold)
			mu.Lock()
			results[it.RelPath] = r
			mu.Unlock()
			return nil
		})
	}
	_ = g.Wait() // los errores por archivo viajan en HashResult.ReadError
	return results
}

func hashOne(fsys *safefs.FS, it Item, fuzzyThreshold int64) *HashResult {
	r := &HashResult{ExtType: extExpectations[strings.ToLower(filepath.Ext(it.RelPath))]}
	f, err := fsys.Open(it.RelPath)
	if err != nil {
		r.ReadError = err.Error()
		return r
	}
	defer f.Close()

	if it.Size <= fuzzyThreshold {
		// Lectura única en memoria (acotada por el umbral): SHA-256 + TLSH +
		// magic bytes de la misma pasada.
		buf, err := io.ReadAll(io.LimitReader(f, fuzzyThreshold+1))
		if err != nil {
			r.ReadError = err.Error()
			return r
		}
		sum := sha256.Sum256(buf)
		r.SHA256 = hex.EncodeToString(sum[:])
		r.BytesHashed = int64(len(buf))
		r.MagicType = mimetype.Detect(buf).String()
		if len(buf) >= tlshMinSize {
			if t, err := tlsh.HashBytes(buf); err == nil {
				r.TLSH = t.String()
			} else {
				r.TLSHSkipped = "tlsh: " + err.Error()
			}
		} else {
			r.TLSHSkipped = "below-min-size"
		}
		return r
	}

	// Streaming para archivos grandes: SHA-256 por streaming sin límite,
	// magic de los primeros bytes, TLSH omitido y registrado (R3).
	head := make([]byte, 3072)
	n, err := io.ReadFull(f, head)
	if err != nil && err != io.ErrUnexpectedEOF && err != io.EOF {
		r.ReadError = err.Error()
		return r
	}
	head = head[:n]
	r.MagicType = mimetype.Detect(head).String()
	h := sha256.New()
	h.Write(head)
	copied, err := io.Copy(h, f)
	if err != nil {
		r.ReadError = err.Error()
		return r
	}
	r.SHA256 = hex.EncodeToString(h.Sum(nil))
	r.BytesHashed = int64(n) + copied
	r.TLSHSkipped = "above-threshold"
	return r
}

// MagicMismatch informa de si el tipo real contradice lo que promete la
// extensión (solo para extensiones con expectativa registrada).
func (r *HashResult) MagicMismatch() bool {
	if r.ExtType == "" || r.MagicType == "" {
		return false
	}
	return !strings.HasPrefix(r.MagicType, r.ExtType)
}
