package evidence

import (
	"math"
	"strings"
	"time"

	runtimeconnector "github.com/Weiki886/relythra/internal/connector/runtime"
)

// canonicalRuntimeOOMWindows validates supplied derivatives against their raw
// samples. It does not invent missing summaries or assign windows to an
// incarnation: a rolling range may include observations before a restart.
func canonicalRuntimeOOMWindows(container runtimeconnector.Container, start, end time.Time) ([]runtimeconnector.OOMWindowObservation, error) {
	type sampleKey struct {
		evaluation time.Time
		estimate   float64
	}
	samples := make(map[sampleKey]int, len(container.OOMEvents.Samples))
	for _, sample := range container.OOMEvents.Samples {
		samples[sampleKey{sample.Timestamp.UTC(), sample.Value}]++
	}
	observations := make([]runtimeconnector.OOMWindowObservation, 0, len(container.OOMWindowObservations))
	for _, observation := range container.OOMWindowObservations {
		observation.WindowStart = observation.WindowStart.UTC()
		observation.EvaluationTime = observation.EvaluationTime.UTC()
		key := sampleKey{observation.EvaluationTime, observation.EstimatedOOMCount}
		if observation.ContainerID != container.ID || strings.TrimSpace(observation.SourceReference) == "" ||
			observation.SourceReference != container.OOMEvents.SourceReference ||
			observation.EvaluationTime.IsZero() || observation.WindowStart.IsZero() ||
			observation.EvaluationTime.Before(start) || observation.EvaluationTime.After(end) ||
			!observation.WindowStart.Equal(observation.EvaluationTime.Add(-5*time.Minute)) ||
			math.IsNaN(observation.EstimatedOOMCount) || math.IsInf(observation.EstimatedOOMCount, 0) || observation.EstimatedOOMCount <= 0 || samples[key] == 0 {
			return nil, ErrInvalidInput
		}
		samples[key]--
		observations = append(observations, observation)
	}
	return observations, nil
}
