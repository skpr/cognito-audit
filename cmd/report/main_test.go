package main

import (
	"testing"
	"time"
)

func TestReplaceTokens(t *testing.T) {
	want := time.Now().Format(DateFormat)

	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "token replaced",
			in:   "Report generated on [date]",
			want: "Report generated on " + want,
		},
		{
			name: "no token present",
			in:   "Report generated",
			want: "Report generated",
		},
		{
			name: "multiple occurrences",
			in:   "[date] - [date]",
			want: want + " - " + want,
		},
		{
			name: "empty string",
			in:   "",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := replaceTokens(tt.in)
			if got != tt.want {
				t.Errorf("replaceTokens(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}
