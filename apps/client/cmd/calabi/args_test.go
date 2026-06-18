package main

import (
	"reflect"
	"testing"
)

func TestReorderArgs(t *testing.T) {
	cases := []struct {
		name       string
		input      []string
		valueFlags []string
		want       []string
	}{
		{
			name:       "flags already at front, positional last",
			input:      []string{"--remote-port", "16080", "9090"},
			valueFlags: []string{"remote-port"},
			want:       []string{"--remote-port", "16080", "9090"},
		},
		{
			name:       "positional first, flag with value last",
			input:      []string{"9090", "--remote-port", "16080"},
			valueFlags: []string{"remote-port"},
			want:       []string{"--remote-port", "16080", "9090"},
		},
		{
			name:       "equals form is self-contained",
			input:      []string{"9090", "--remote-port=16080"},
			valueFlags: []string{"remote-port"},
			want:       []string{"--remote-port=16080", "9090"},
		},
		{
			name:       "short-dash form treated as flag",
			input:      []string{"9090", "-name", "foo"},
			valueFlags: []string{"name"},
			want:       []string{"-name", "foo", "9090"},
		},
		{
			name:       "boolean flag not in valueFlags",
			input:      []string{"9090", "--verbose"},
			valueFlags: []string{"name", "remote-port"},
			want:       []string{"--verbose", "9090"},
		},
		{
			name:       "interleaved flags and positionals",
			input:      []string{"--name", "alpha", "9090", "--remote-port", "16080"},
			valueFlags: []string{"name", "remote-port"},
			want:       []string{"--name", "alpha", "--remote-port", "16080", "9090"},
		},
		{
			name:       "empty input",
			input:      []string{},
			valueFlags: []string{"name"},
			want:       nil,
		},
		{
			name:       "single dash is positional (stdin convention)",
			input:      []string{"9090", "-"},
			valueFlags: []string{"name"},
			want:       []string{"9090", "-"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := reorderArgs(tc.input, tc.valueFlags)
			if len(got) == 0 && len(tc.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("reorderArgs(%v) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}
