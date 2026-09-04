package svcboot

import "testing"

func TestDBDsn(t *testing.T) {
	cases := []struct {
		name         string
		specificEnv  string
		specificVal  string
		sharedVal    string
		want         string
	}{
		{
			name:        "specific wins over shared",
			specificEnv: "TEST_SVC_DB_DSN",
			specificVal: "postgres://specific",
			sharedVal:   "postgres://shared",
			want:        "postgres://specific",
		},
		{
			name:        "fallback to shared",
			specificEnv: "TEST_SVC_DB_DSN",
			specificVal: "",
			sharedVal:   "postgres://shared",
			want:        "postgres://shared",
		},
		{
			name:        "both empty returns empty",
			specificEnv: "TEST_SVC_DB_DSN",
			specificVal: "",
			sharedVal:   "",
			want:        "",
		},
		{
			name:        "whitespace-only treated as unset",
			specificEnv: "TEST_SVC_DB_DSN",
			specificVal: "   ",
			sharedVal:   "postgres://shared",
			want:        "postgres://shared",
		},
		{
			name:        "specific env name empty skips first lookup",
			specificEnv: "",
			specificVal: "",
			sharedVal:   "postgres://shared",
			want:        "postgres://shared",
		},
		{
			name:        "specific value is trimmed before return",
			specificEnv: "TEST_SVC_DB_DSN",
			specificVal: "  postgres://specific  ",
			sharedVal:   "",
			want:        "postgres://specific",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.specificEnv != "" {
				t.Setenv(c.specificEnv, c.specificVal)
			}
			t.Setenv("CALABI_DB_DSN", c.sharedVal)
			if got := DBDsn(c.specificEnv); got != c.want {
				t.Fatalf("DBDsn(%q)=%q, want %q", c.specificEnv, got, c.want)
			}
		})
	}
}
