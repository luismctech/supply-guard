package report

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/AlbertoMZCruz/supply-guard/internal/types"
)

// StreamEvent represents a single event in the stream-json output format.
type StreamEvent struct {
	Event     string         `json:"event"`
	Timestamp string         `json:"timestamp"`
	Finding   *types.Finding `json:"finding,omitempty"`
	Summary   *types.Summary `json:"summary,omitempty"`
	Duration  string         `json:"duration,omitempty"`
	Error     string         `json:"error,omitempty"`
}

// StreamReporter emits newline-delimited JSON events for real-time consumption.
type StreamReporter struct{}

func (r *StreamReporter) Report(w io.Writer, result *types.ScanResult) error {
	r.writeEvent(w, StreamEvent{
		Event:     "scan_started",
		Timestamp: result.Timestamp.Format(time.RFC3339),
	})

	for i := range result.Findings {
		r.writeEvent(w, StreamEvent{
			Event:     "finding",
			Timestamp: time.Now().Format(time.RFC3339),
			Finding:   &result.Findings[i],
		})
	}

	r.writeEvent(w, StreamEvent{
		Event:     "scan_complete",
		Timestamp: time.Now().Format(time.RFC3339),
		Summary:   &result.Summary,
		Duration:  result.Duration,
	})

	return nil
}

func (r *StreamReporter) writeEvent(w io.Writer, evt StreamEvent) {
	data, err := json.Marshal(evt)
	if err != nil {
		return
	}
	fmt.Fprintf(w, "%s\n", data)
}
