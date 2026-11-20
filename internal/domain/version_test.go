package domain

import (
	"errors"
	"testing"
	"testing/quick"
)

func TestParseVersion(t *testing.T) {
	cases := []struct {
		in     string
		want   string
		suffix string
		ok     bool
	}{
		{"nginx version: nginx/1.30.6", "1.30.6", "", true},
		{"nginx version: nginx/1.24.0 (Ubuntu)\nbuilt with OpenSSL", "1.24.0", "Ubuntu", true},
		{"Server: nginx/1.31.9", "1.31.9", "", true},
		{"nginx/1.9.5", "1.9.5", "", true},
		{"1.31.8", "1.31.8", "", true},
		{" v1.30.7 \n", "1.30.7", "", true},
		{"nginx", "", "", false},
		{"openresty/1.25.3.1", "", "", false},
		{"1.30", "", "", false},
		{"", "", "", false},
		{"nginx/1.9999999.0", "", "", false},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			v, err := ParseVersion(c.in)
			if !c.ok {
				if !errors.Is(err, ErrInvalidVersion) {
					t.Fatalf("want ErrInvalidVersion, got %v", err)
				}
				var ve *VersionError
				if !errors.As(err, &ve) || ve.Error() == "" {
					t.Fatalf("want *VersionError, got %T", err)
				}
				return
			}
			if err != nil || v.String() != c.want || v.Suffix != c.suffix {
				t.Fatalf("got %v %q %v", v, v.Suffix, err)
			}
		})
	}
}

func TestParseRunning(t *testing.T) {
	if _, hidden, err := ParseRunning("Server: nginx"); err != nil || !hidden {
		t.Fatalf("hidden=%v err=%v", hidden, err)
	}
	if v, hidden, err := ParseRunning("nginx/1.30.6"); err != nil || hidden || v.String() != "1.30.6" {
		t.Fatal("parse failed")
	}
	if _, _, err := ParseRunning("Apache"); err == nil {
		t.Fatal("expected error")
	}
}

func TestBranchAndModule(t *testing.T) {
	if v(1, 30, 6).Branch() != "stable" || v(1, 31, 8).Branch() != "mainline" {
		t.Fatal("branch")
	}
	if p, k := HasHTTP2Module("configure arguments: --with-http_v2_module"); !p || !k {
		t.Fatal("module present")
	}
	if p, k := HasHTTP2Module("configure arguments: --with-http_ssl_module"); p || !k {
		t.Fatal("module absent")
	}
	if _, k := HasHTTP2Module("1.30.6"); k {
		t.Fatal("unknown")
	}
}

func TestAdvisoryBoundaries(t *testing.T) {
	adv := map[string]Advisory{}
	for _, a := range Advisories() {
		adv[a.ID] = a
	}
	cases := []struct {
		id   string
		ver  Version
		want bool
	}{
		{"CVE-2026-123007", v(1, 9, 4), false},
		{"CVE-2026-123007", v(1, 9, 5), true},
		{"CVE-2026-123007", v(1, 18, 0), true},
		{"CVE-2026-123007", v(1, 30, 6), true},
		{"CVE-2026-123007", v(1, 30, 7), false},
		{"CVE-2026-123007", v(1, 30, 8), false},
		{"CVE-2026-123007", v(1, 31, 0), true},
		{"CVE-2026-123007", v(1, 31, 8), true},
		{"CVE-2026-123007", v(1, 31, 9), false},
		{"CVE-2026-123007", v(1, 32, 0), false},
		{"CVE-2026-123007", v(2, 0, 0), false},
		{"CVE-2026-123633", v(1, 19, 6), false},
		{"CVE-2026-123633", v(1, 19, 7), true},
		{"CVE-2026-123633", v(1, 24, 0), true},
		{"CVE-2026-123633", v(1, 30, 6), true},
		{"CVE-2026-123633", v(1, 30, 7), false},
		{"CVE-2026-123633", v(1, 31, 8), true},
		{"CVE-2026-123633", v(1, 31, 9), false},
	}
	for _, c := range cases {
		if got := adv[c.id].Affects(c.ver); got != c.want {
			t.Errorf("%s %s: got %v want %v", c.id, c.ver, got, c.want)
		}
	}
	a := adv["CVE-2026-123007"]
	if f, ok := a.FixFor(v(1, 31, 2)); !ok || f != v(1, 31, 9) {
		t.Fatal("mainline fix")
	}
	if f, ok := a.FixFor(v(1, 30, 0)); !ok || f != v(1, 30, 7) {
		t.Fatal("stable fix")
	}
	if _, ok := a.FixFor(v(1, 24, 0)); ok {
		t.Fatal("old branch has no fix")
	}
}

func small(a, b, c uint8) Version {
	return Version{Major: int(a % 3), Minor: int(b % 40), Patch: int(c % 20)}
}

var qc = &quick.Config{MaxCount: 5000}

func TestPropCompareAntisymmetricAndReflexive(t *testing.T) {
	f := func(a1, a2, a3, b1, b2, b3 uint8) bool {
		x, y := small(a1, a2, a3), small(b1, b2, b3)
		return x.Compare(x) == 0 && x.Compare(y) == -y.Compare(x)
	}
	if err := quick.Check(f, qc); err != nil {
		t.Fatal(err)
	}
}

func TestPropCompareTransitive(t *testing.T) {
	f := func(a1, a2, a3, b1, b2, b3, c1, c2, c3 uint8) bool {
		x, y, z := small(a1, a2, a3), small(b1, b2, b3), small(c1, c2, c3)
		if x.Compare(y) <= 0 && y.Compare(z) <= 0 {
			return x.Compare(z) <= 0
		}
		return true
	}
	if err := quick.Check(f, qc); err != nil {
		t.Fatal(err)
	}
}

func TestPropStringRoundTrip(t *testing.T) {
	f := func(a, b, c uint16) bool {
		x := Version{Major: int(a), Minor: int(b), Patch: int(c)}
		y, err := ParseVersion(x.String())
		return err == nil && y.Compare(x) == 0
	}
	if err := quick.Check(f, qc); err != nil {
		t.Fatal(err)
	}
}

// Propiedad del invariante I2: vulnerable sii en rango y no en rama corregida;
// todo lo que está fuera del rango o en una rama corregida es seguro.
func TestPropAffectsMatchesSpec(t *testing.T) {
	for _, a := range Advisories() {
		a := a
		f := func(p1, p2, p3 uint8) bool {
			x := small(p1, p2, p3)
			want := x.Compare(a.From) >= 0 && x.Compare(a.To) <= 0
			if (x.Minor == 30 && x.Major == 1 && x.Patch >= 7) || (x.Major == 1 && x.Minor == 31 && x.Patch >= 9) {
				want = false
			}
			return a.Affects(x) == want
		}
		if err := quick.Check(f, qc); err != nil {
			t.Fatalf("%s: %v", a.ID, err)
		}
	}
}

// Monotonía dentro de una rama: si x es seguro por fix, todo patch mayor también.
func TestPropFixedMonotonicInBranch(t *testing.T) {
	for _, a := range Advisories() {
		for _, fx := range a.Fixed {
			for p := fx.Patch; p < fx.Patch+50; p++ {
				if a.Affects(Version{Major: fx.Major, Minor: fx.Minor, Patch: p}) {
					t.Fatalf("%s: %d.%d.%d should be fixed", a.ID, fx.Major, fx.Minor, p)
				}
			}
			if !a.Affects(Version{Major: fx.Major, Minor: fx.Minor, Patch: fx.Patch - 1}) {
				t.Fatalf("%s: patch before fix should be vulnerable", a.ID)
			}
		}
	}
}

func FuzzParseVersion(f *testing.F) {
	for _, s := range []string{"nginx version: nginx/1.30.6", "1.31.9", "nginx/1.24.0 (Ubuntu)", "nginx", "", "nginx/9.9.9999999999"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		v, err := ParseVersion(s)
		if err != nil {
			if !errors.Is(err, ErrInvalidVersion) {
				t.Fatalf("untyped error %v", err)
			}
			return
		}
		w, err := ParseVersion(v.String())
		if err != nil || w.Compare(v) != 0 {
			t.Fatalf("round trip failed for %q -> %v", s, v)
		}
	})
}
