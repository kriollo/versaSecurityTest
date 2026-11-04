package version

import "testing"

func TestGetNoVacio(t *testing.T) {
	if v := Get(); v == "" {
		t.Fatal("Get() no debe devolver vacío")
	}
}

func TestNormalize(t *testing.T) {
	cases := map[string]string{
		"v2.2.0": "2.2.0",
		"2.2.0":  "2.2.0",
		"":       "dev",
	}
	for in, want := range cases {
		if got := normalize(in); got != want {
			t.Errorf("normalize(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLabel(t *testing.T) {
	old := Version
	defer func() { Version = old }()

	cases := map[string]string{
		"2.2.0":       "v2.2.0",
		"v2.2.0":      "v2.2.0",
		"dev-abc1234": "dev-abc1234",
	}
	for in, want := range cases {
		Version = in
		if got := Label(); got != want {
			t.Errorf("Label() con Version=%q = %q, want %q", in, got, want)
		}
	}
}

func TestIsPseudoVersion(t *testing.T) {
	cases := map[string]bool{
		"v0.0.0-20261104024103-c74603fef2de":       true,
		"v0.0.0-20261104024103-c74603fef2de+dirty": true,
		"0.0.0-20261104024103-c74603fef2de":        true,
		"v1.2.4-0.20261104024103-c74603fef2de":     true,
		"v2.2.0":                                   false,
		"2.2.0":                                    false,
		"v1.2.3-beta.1":                            false,
		"dev-c74603f":                              false,
		"(devel)":                                  false,
	}
	for in, want := range cases {
		if got := isPseudoVersion(in); got != want {
			t.Errorf("isPseudoVersion(%q) = %v, want %v", in, got, want)
		}
	}
}
