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
