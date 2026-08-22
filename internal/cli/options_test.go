package cli

import (
	"io"
	"reflect"
	"testing"
)

func TestParse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args []string
		want Options
	}{
		{
			name: "defaults",
			want: Options{
				Host:      "localhost",
				Workers:   10000,
				StartPort: 1,
				EndPort:   65535,
			},
		},
		{
			name: "custom scan",
			args: []string{"-host", "127.0.0.1", "-workers", "20", "-start", "80", "-end", "443"},
			want: Options{
				Host:      "127.0.0.1",
				Workers:   20,
				StartPort: 80,
				EndPort:   443,
			},
		},
		{
			name: "highest verbosity wins",
			args: []string{"-v", "-vv", "-vvv"},
			want: Options{
				Host:      "localhost",
				Workers:   10000,
				StartPort: 1,
				EndPort:   65535,
				Verbosity: 3,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := Parse(tt.args, io.Discard)
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Parse() = %#v, want %#v", got, tt.want)
			}
		})
	}
}
