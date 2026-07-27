package drift

import (
	"reflect"
	"testing"

	"j0witness/internal/finding"
	"j0witness/internal/inventory"
)

// --- helpers sintéticos ---

func entry(rel, sha string, mtime, ctime int64, typ string) inventory.Entry {
	return inventory.Entry{PathDisplay: rel, SHA256: sha, MtimeNS: mtime, CtimeNS: ctime, Type: typ}
}

func ent(rel, sha string) inventory.Entry {
	return entry(rel, sha, 0, 0, "file")
}

func fnd(id, rule, subject string, sev finding.Severity) finding.Finding {
	return finding.Finding{ID: id, RuleID: rule, Subject: subject, Severity: sev}
}

func snap(target string, entries []inventory.Entry, findings []finding.Finding) Snapshot {
	return Snapshot{Ref: RunRef{Target: target}, Entries: entries, Findings: findings}
}

func TestCompareAddedRemovedChanged(t *testing.T) {
	old := snap("s", []inventory.Entry{ent("a.php", "AAA"), ent("b.php", "BBB")}, nil)
	neu := snap("s", []inventory.Entry{ent("a.php", "AAA"), ent("c.php", "CCC")}, nil)
	d, err := Compare(old, neu)
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	if len(d.Entries.Added) != 1 || d.Entries.Added[0].Path != "c.php" {
		t.Fatalf("added = %+v, quiere [c.php]", d.Entries.Added)
	}
	if len(d.Entries.Removed) != 1 || d.Entries.Removed[0].Path != "b.php" {
		t.Fatalf("removed = %+v, quiere [b.php]", d.Entries.Removed)
	}
	if len(d.Entries.Changed) != 0 {
		t.Fatalf("changed = %+v, quiere vacío", d.Entries.Changed)
	}
	if d.Summary.Added != 1 || d.Summary.Removed != 1 || d.Summary.Changed != 0 {
		t.Fatalf("summary = %+v", d.Summary)
	}
}

func TestCompareChangedByHash(t *testing.T) {
	old := snap("s", []inventory.Entry{ent("x.php", "AAA")}, nil)
	neu := snap("s", []inventory.Entry{ent("x.php", "ZZZ")}, nil)
	d, err := Compare(old, neu)
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	if len(d.Entries.Changed) != 1 {
		t.Fatalf("changed = %+v, quiere 1 entrada", d.Entries.Changed)
	}
	c := d.Entries.Changed[0]
	if c.Path != "x.php" || c.OldSHA256 != "AAA" || c.NewSHA256 != "ZZZ" {
		t.Fatalf("changed[0] = %+v, quiere x.php AAA→ZZZ", c)
	}
}

func TestCompareMoveUnambiguous(t *testing.T) {
	old := snap("s", []inventory.Entry{ent("a.php", "SHA1")}, nil)
	neu := snap("s", []inventory.Entry{ent("b.php", "SHA1")}, nil)
	d, err := Compare(old, neu)
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	if len(d.Entries.Moved) != 1 || d.Entries.Moved[0].OldPath != "a.php" || d.Entries.Moved[0].Path != "b.php" {
		t.Fatalf("moved = %+v, quiere [a.php→b.php]", d.Entries.Moved)
	}
	if len(d.Entries.Added) != 0 || len(d.Entries.Removed) != 0 {
		t.Fatalf("added/removed deberían quedar vacíos tras mover: added=%+v removed=%+v", d.Entries.Added, d.Entries.Removed)
	}
}

func TestCompareMoveAmbiguousStaysAddRemove(t *testing.T) {
	old := snap("s", []inventory.Entry{ent("a.php", "DUP"), ent("b.php", "DUP")}, nil)
	neu := snap("s", []inventory.Entry{ent("c.php", "DUP")}, nil)
	d, err := Compare(old, neu)
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	if len(d.Entries.Moved) != 0 {
		t.Fatalf("moved = %+v, quiere vacío (sha ambiguo)", d.Entries.Moved)
	}
	if len(d.Entries.Removed) != 2 || d.Entries.Removed[0].Path != "a.php" || d.Entries.Removed[1].Path != "b.php" {
		t.Fatalf("removed = %+v, quiere [a.php,b.php] ordenado", d.Entries.Removed)
	}
	if len(d.Entries.Added) != 1 || d.Entries.Added[0].Path != "c.php" {
		t.Fatalf("added = %+v, quiere [c.php]", d.Entries.Added)
	}
}

func TestCompareMoveAmbiguousReverse(t *testing.T) {
	old := snap("s", []inventory.Entry{ent("a.php", "DUP")}, nil)
	neu := snap("s", []inventory.Entry{ent("b.php", "DUP"), ent("c.php", "DUP")}, nil)
	d, err := Compare(old, neu)
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	if len(d.Entries.Moved) != 0 {
		t.Fatalf("moved = %+v, quiere vacío (sha ambiguo)", d.Entries.Moved)
	}
	if len(d.Entries.Removed) != 1 || d.Entries.Removed[0].Path != "a.php" {
		t.Fatalf("removed = %+v, quiere [a.php]", d.Entries.Removed)
	}
	if len(d.Entries.Added) != 2 || d.Entries.Added[0].Path != "b.php" || d.Entries.Added[1].Path != "c.php" {
		t.Fatalf("added = %+v, quiere [b.php,c.php] ordenado", d.Entries.Added)
	}
}

func TestCompareRuntimeChurnSegregated(t *testing.T) {
	old := snap("s", []inventory.Entry{ent("index.php", "A")}, nil)
	neu := snap("s", []inventory.Entry{ent("index.php", "A"), ent("cache/x.php", "NEW"), ent("logs/y", "L")}, nil)
	d, err := Compare(old, neu)
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	if len(d.Entries.Added) != 0 {
		t.Fatalf("added = %+v, quiere vacío (churn segregado)", d.Entries.Added)
	}
	if d.Entries.RuntimeChurn != 2 {
		t.Fatalf("runtime_churn = %d, quiere 2", d.Entries.RuntimeChurn)
	}
	if d.Summary.RuntimeChurn != 2 {
		t.Fatalf("summary.runtime_churn = %d, quiere 2", d.Summary.RuntimeChurn)
	}
}

func TestCompareMetadataChanged(t *testing.T) {
	oldE := ent("a.php", "AAA")
	oldE.Mode = 0o644
	newE := ent("a.php", "AAA")
	newE.Mode = 0o755
	old := snap("s", []inventory.Entry{oldE}, nil)
	neu := snap("s", []inventory.Entry{newE}, nil)
	d, err := Compare(old, neu)
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	if len(d.Entries.MetadataChanged) != 1 || d.Entries.MetadataChanged[0].Path != "a.php" {
		t.Fatalf("metadata_changed = %+v, quiere [a.php]", d.Entries.MetadataChanged)
	}
	if len(d.Entries.Changed) != 0 {
		t.Fatalf("mismo sha no debe ir a changed: %+v", d.Entries.Changed)
	}
}

func TestCompareFindingsNewResolved(t *testing.T) {
	old := snap("s", nil, []finding.Finding{{ID: "id1", RuleID: "J0W-CORE-004", Subject: "x", Severity: "high"}})
	neu := snap("s", nil, []finding.Finding{{ID: "id2", RuleID: "J0W-CONFIG-001", Subject: "y", Severity: "critical"}})
	d, err := Compare(old, neu)
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	if len(d.Findings.New) != 1 || d.Findings.New[0].ID != "id2" {
		t.Fatalf("new = %+v, quiere [id2]", d.Findings.New)
	}
	if len(d.Findings.Resolved) != 1 || d.Findings.Resolved[0].ID != "id1" {
		t.Fatalf("resolved = %+v, quiere [id1]", d.Findings.Resolved)
	}
	if d.Findings.Persistent != 0 {
		t.Fatalf("persistent = %d, quiere 0", d.Findings.Persistent)
	}
}

func TestCompareTargetMismatchErrors(t *testing.T) {
	_, err := Compare(snap("A", nil, nil), snap("B", nil, nil))
	if err == nil {
		t.Fatal("objetivos distintos debe error")
	}
}

func TestCompareVersionMismatchCaveat(t *testing.T) {
	old := Snapshot{Ref: RunRef{Target: "s", BaselineVersion: "4.4.0"}}
	neu := Snapshot{Ref: RunRef{Target: "s", BaselineVersion: "4.4.1"}}
	d, err := Compare(old, neu)
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	if len(d.Caveats) == 0 {
		t.Fatal("esperaba una salvedad por versiones de baseline distintas")
	}

	same := Snapshot{Ref: RunRef{Target: "s", BaselineVersion: "4.4.0"}}
	d2, err := Compare(same, same)
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	if len(d2.Caveats) != 0 {
		t.Fatalf("sin diferencia de versión no debería haber salvedad: %v", d2.Caveats)
	}
}

func TestCompareDeterministic(t *testing.T) {
	old := snap("s", []inventory.Entry{
		ent("a.php", "AAA"),
		ent("b.php", "BBB"),
		ent("moved-old.php", "MOV"),
		ent("cache/x.php", "C1"),
	}, []finding.Finding{
		fnd("id1", "J0W-CORE-004", "x", "high"),
		fnd("id2", "J0W-CORE-004", "y", "high"),
	})
	neu := snap("s", []inventory.Entry{
		ent("a.php", "AAA"),
		ent("c.php", "CCC"),
		ent("moved-new.php", "MOV"),
		ent("cache/x.php", "C2"),
	}, []finding.Finding{
		fnd("id2", "J0W-CORE-004", "y", "high"),
		fnd("id3", "J0W-CONFIG-001", "z", "critical"),
	})
	d1, err1 := Compare(old, neu)
	d2, err2 := Compare(old, neu)
	if err1 != nil || err2 != nil {
		t.Fatalf("Compare: %v / %v", err1, err2)
	}
	if !reflect.DeepEqual(d1, d2) {
		t.Fatalf("Compare no es determinista:\n%+v\n%+v", d1, d2)
	}
	// sanity: cubre las cinco clases a la vez
	if len(d1.Entries.Removed) != 1 || len(d1.Entries.Added) != 1 || len(d1.Entries.Moved) != 1 {
		t.Fatalf("mezcla esperada de clases no vista: %+v", d1.Entries)
	}
	if d1.Entries.RuntimeChurn != 1 {
		t.Fatalf("runtime_churn = %d, quiere 1 (cache/x.php cambiado)", d1.Entries.RuntimeChurn)
	}
	if len(d1.Findings.New) != 1 || len(d1.Findings.Resolved) != 1 || d1.Findings.Persistent != 1 {
		t.Fatalf("findings = %+v", d1.Findings)
	}
}
