package report

import (
	"reflect"
	"testing"
)

func TestFilterWorking(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		document Document
		check    func(*testing.T, Document)
	}{
		{
			name:     "mixed results",
			document: testDocument(),
			check: func(t *testing.T, filtered Document) {
				t.Helper()
				if !reflect.DeepEqual(filtered.RequestedTargets, []string{"host-a", "host-b"}) ||
					!reflect.DeepEqual(filtered.ScannedTargets, []string{"host-a", "host-b"}) {
					t.Errorf("filtered targets = %v / %v", filtered.RequestedTargets, filtered.ScannedTargets)
				}
				if len(filtered.Discovery) != 1 || filtered.Discovery[0].Target != "host-a" ||
					filtered.Discovery[0].Error != "" {
					t.Errorf("filtered discovery = %#v", filtered.Discovery)
				}
				if len(filtered.OpenPorts) != 2 || len(filtered.OpenPorts[0].Probes) != 0 ||
					len(filtered.OpenPorts[1].Probes) != 1 || filtered.OpenPorts[1].Probes[0].Protocol != "http" {
					t.Errorf("filtered open ports = %#v", filtered.OpenPorts)
				}
				wantSummary := Summary{Total: 2, Completed: 2, Open: 2}
				if filtered.Summary != wantSummary {
					t.Errorf("filtered summary = %#v, want %#v", filtered.Summary, wantSummary)
				}
			},
		},
		{
			name: "no working results",
			document: Document{
				Status:           "interrupted",
				Error:            "deadline exceeded",
				RequestedTargets: []string{"down"},
				ScannedTargets:   []string{"down"},
				Discovery: []DiscoveryResult{
					{Target: "down", Available: false, Error: "timeout"},
				},
				Summary: Summary{Total: 1, Completed: 1, Closed: 1, Timeouts: 1},
			},
			check: func(t *testing.T, filtered Document) {
				t.Helper()
				if len(filtered.RequestedTargets) != 0 || len(filtered.ScannedTargets) != 0 ||
					len(filtered.Discovery) != 0 || len(filtered.OpenPorts) != 0 || filtered.Summary != (Summary{}) {
					t.Errorf("filtered document = %#v, want no working results", filtered)
				}
				if filtered.Status != "interrupted" || filtered.Error != "deadline exceeded" {
					t.Errorf("filtered interruption metadata = status %q, error %q", filtered.Status, filtered.Error)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			original := tt.document
			filtered := FilterWorking(tt.document)
			tt.check(t, filtered)
			if tt.name == "mixed results" && len(original.OpenPorts[1].Probes) != 2 {
				t.Errorf("FilterWorking() mutated source document: %#v", original.OpenPorts)
			}
		})
	}
}
