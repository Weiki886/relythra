package api

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/Weiki886/relythra/internal/store"
)

const (
	defaultTimelinePageSize = 50
	maxTimelinePageSize     = 100
	maxTimelineOffset       = 10000
	maxTimelineEntityID     = 256
)

func (handler *handler) getInvestigationTimeline(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	id, ok := requireID(w, r)
	if !ok {
		return
	}
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_request", "timeline query is invalid")
		return
	}
	for key := range values {
		switch key {
		case "source_type", "entity_id", "completeness", "stance", "limit", "offset":
		default:
			writeError(w, r, http.StatusBadRequest, "invalid_request", "timeline query is invalid")
			return
		}
		if len(values[key]) != 1 {
			writeError(w, r, http.StatusBadRequest, "invalid_request", "timeline query is invalid")
			return
		}
	}
	filter, err := parseInvestigationTimelineFilter(values)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_request", "timeline filters are invalid")
		return
	}
	page, err := ParsePagination(r, defaultTimelinePageSize, maxTimelinePageSize)
	if err != nil || page.Offset > maxTimelineOffset {
		writeError(w, r, http.StatusBadRequest, "invalid_request", "timeline pagination is invalid")
		return
	}
	timeline, err := handler.reader.GetInvestigationTimeline(
		r.Context(), id, filter, page.Limit, page.Offset,
	)
	if err != nil {
		handler.writeStoreError(w, r, err)
		return
	}
	handler.writeData(w, r, http.StatusOK, timeline)
}

func parseInvestigationTimelineFilter(values url.Values) (store.InvestigationTimelineFilter, error) {
	var filter store.InvestigationTimelineFilter
	for key, target := range map[string]*string{
		"source_type":  &filter.SourceType,
		"entity_id":    &filter.EntityID,
		"completeness": &filter.Completeness,
		"stance":       &filter.Stance,
	} {
		items, exists := values[key]
		if !exists {
			continue
		}
		if len(items) != 1 || strings.TrimSpace(items[0]) != items[0] || items[0] == "" {
			return store.InvestigationTimelineFilter{}, store.ErrInvalidInput
		}
		*target = items[0]
	}
	if filter.EntityID != "" && len(filter.EntityID) > maxTimelineEntityID {
		return store.InvestigationTimelineFilter{}, store.ErrInvalidInput
	}
	if err := store.ValidateInvestigationTimelineFilter(filter); err != nil {
		return store.InvestigationTimelineFilter{}, err
	}
	return filter, nil
}
