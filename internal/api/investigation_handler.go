package api

import "net/http"

func (handler *handler) getInvestigationContext(w http.ResponseWriter, r *http.Request) {
	if !requireGET(w, r) {
		return
	}
	id, ok := requireID(w, r)
	if !ok {
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		writeError(w, r, http.StatusBadRequest, "invalid_request", "investigation context does not accept query parameters")
		return
	}
	result, err := handler.reader.GetInvestigationContext(r.Context(), id)
	if err != nil {
		handler.writeStoreError(w, r, err)
		return
	}
	handler.writeData(w, r, http.StatusOK, result)
}
