package timeline

import (
	"reflect"
	"testing"

	"j0witness/internal/inventory"
	"j0witness/internal/observe"
)

func file(rel string, mtime, ctime int64) inventory.Entry {
	return inventory.Entry{Type: "file", PathDisplay: rel, RelPath: []byte(rel), MtimeNS: mtime, CtimeNS: ctime}
}

func countType(obs []observe.Observation, t observe.Type) int {
	n := 0
	for _, o := range obs {
		if o.Type == t {
			n++
		}
	}
	return n
}

func TestManipulationFutureMtime(t *testing.T) {
	base := int64(1_000_000_000_000_000_000)
	e := []inventory.Entry{file("a.php", base+10*nsPerDay, base)} // mtime 10 días futuro vs ctime
	obs, sum := Analyze(e, 1)
	if countType(obs, observe.TimeManipulation) != 1 {
		t.Fatal("debe marcar mtime>ctime")
	}
	if sum.ManipulationCount != 1 {
		t.Fatalf("summary manip=%d", sum.ManipulationCount)
	}
}

func TestNormalMtimeNoManipulation(t *testing.T) {
	base := int64(1_000_000_000_000_000_000)
	e := []inventory.Entry{file("a.php", base-100*nsPerDay, base)} // mtime viejo (extracción normal)
	obs, _ := Analyze(e, 1)
	if countType(obs, observe.TimeManipulation) != 0 {
		t.Fatal("mtime<ctime es normal, no marca")
	}
}

func TestCtimeOutlierAfterGap(t *testing.T) {
	base := int64(1_600_000_000) * 1_000_000_000
	var e []inventory.Entry
	for i := 0; i < 40; i++ { // cohorte densa
		e = append(e, file("core/f", base+int64(i)*3600*1_000_000_000, base+int64(i)*3600*1_000_000_000))
	}
	// un archivo con ctime 120 días DESPUÉS de la cohorte (tras hueco > 30d), cola pequeña (1/41 < 5%)
	late := base + 120*nsPerDay
	e = append(e, file("images/shell.php", late, late))
	obs, sum := Analyze(e, 1)
	if countType(obs, observe.CtimeOutlier) != 1 {
		t.Fatalf("debe marcar 1 outlier, got %d", countType(obs, observe.CtimeOutlier))
	}
	if sum.OutlierCount != 1 {
		t.Fatalf("summary outliers=%d", sum.OutlierCount)
	}
}

func TestTightCohortNoOutliers(t *testing.T) {
	base := int64(1_600_000_000) * 1_000_000_000
	var e []inventory.Entry
	for i := 0; i < 40; i++ {
		e = append(e, file("core/f", base+int64(i)*3600*1_000_000_000, base+int64(i)*3600*1_000_000_000))
	}
	obs, sum := Analyze(e, 1)
	if countType(obs, observe.CtimeOutlier) != 0 {
		t.Fatal("cohorte densa no tiene outliers")
	}
	if sum.OutlierCount != 0 {
		t.Fatal("summary outliers debe ser 0")
	}
}

func TestFewFilesNoCohort(t *testing.T) { // < minFilesForCohort → sin análisis de outliers
	base := int64(1_600_000_000) * 1_000_000_000
	e := []inventory.Entry{file("a", base, base), file("b", base+200*nsPerDay, base+200*nsPerDay)}
	obs, _ := Analyze(e, 1)
	if countType(obs, observe.CtimeOutlier) != 0 {
		t.Fatal("pocos archivos → sin outliers")
	}
}

func TestBulkUpdateNotOutliers(t *testing.T) { // cola grande tras el hueco = update masivo, NO outliers
	base := int64(1_600_000_000) * 1_000_000_000
	var e []inventory.Entry
	for i := 0; i < 40; i++ {
		e = append(e, file("core/f", base+int64(i)*3600*1_000_000_000, base+int64(i)*3600*1_000_000_000))
	}
	late := base + 120*nsPerDay
	for i := 0; i < 20; i++ {
		e = append(e, file("upd/f", late+int64(i)*3600*1_000_000_000, late+int64(i)*3600*1_000_000_000))
	} // 20/60 = 33% > 5%
	obs, _ := Analyze(e, 1)
	if countType(obs, observe.CtimeOutlier) != 0 {
		t.Fatal("update masivo (cola grande) no son outliers")
	}
}

func TestDeterministic(t *testing.T) {
	base := int64(1_600_000_000) * 1_000_000_000
	var e []inventory.Entry
	for i := 0; i < 40; i++ {
		e = append(e, file("core/f", base+int64(i)*3600*1_000_000_000, base+int64(i)*3600*1_000_000_000))
	}
	e = append(e, file("late", base+120*nsPerDay, base+120*nsPerDay))
	a, _ := Analyze(e, 1)
	b, _ := Analyze(e, 1)
	if len(a) != len(b) {
		t.Fatalf("no determinista: len(a)=%d len(b)=%d", len(a), len(b))
	}
	type projected struct {
		Type           observe.Type
		SubjectDisplay string
		EvidenceJSON   string
	}
	project := func(obs []observe.Observation) []projected {
		p := make([]projected, len(obs))
		for i, o := range obs {
			p[i] = projected{Type: o.Type, SubjectDisplay: o.SubjectDisplay, EvidenceJSON: o.EvidenceJSON}
		}
		return p
	}
	if !reflect.DeepEqual(project(a), project(b)) {
		t.Fatal("no determinista: observaciones difieren en tipo/subject/evidencia entre corridas")
	}
}
