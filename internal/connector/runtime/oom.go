package runtime

import (
	"math"
	"sort"
	"strings"
	"time"
)

// OOMWindowObservation is an estimate for the five-minute range ending at
// EvaluationTime (exclusive start, inclusive end), not a lifecycle event.
// Ranges can overlap: estimates must not
// be summed, differenced or rounded to infer event counts or occurrence times.
// ContainerID identifies the observed cgroup, not a particular incarnation.
type OOMWindowObservation struct {
	ContainerID       string    `json:"container_id"`
	WindowStart       time.Time `json:"window_start"`
	EvaluationTime    time.Time `json:"evaluation_time"`
	EstimatedOOMCount float64   `json:"estimated_oom_count"`
	SourceReference   string    `json:"source_reference"`
}

// The fixed v1 PromQL template uses increase(...[5m]). Keep this range aligned
// with that template; a different range requires a new template version.
const oomObservationWindow = 5 * time.Minute

func summarizeOOMWindows(container Container, request Request, result *Result) []OOMWindowObservation {
	observations := make([]OOMWindowObservation, 0)
	for _, sample := range container.OOMEvents.Samples {
		if math.IsNaN(sample.Value) || math.IsInf(sample.Value, 0) || sample.Value < 0 ||
			sample.Timestamp.IsZero() || sample.Timestamp.Before(request.Start) || sample.Timestamp.After(request.End) {
			result.Gaps = append(result.Gaps, "container_oom_window_samples_invalid")
			result.Partial = true
			continue
		}
		if sample.Value == 0 {
			continue
		}
		if strings.TrimSpace(container.OOMEvents.SourceReference) == "" {
			result.Gaps = append(result.Gaps, "container_oom_window_source_missing")
			result.Partial = true
			continue
		}
		evaluation := sample.Timestamp.UTC()
		observations = append(observations, OOMWindowObservation{
			ContainerID: container.ID, WindowStart: evaluation.Add(-oomObservationWindow),
			EvaluationTime: evaluation, EstimatedOOMCount: sample.Value,
			SourceReference: container.OOMEvents.SourceReference,
		})
	}
	sort.Slice(observations, func(i, j int) bool { return observations[i].EvaluationTime.Before(observations[j].EvaluationTime) })
	return observations
}
