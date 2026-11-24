package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/Weiki886/relythra/internal/store"
)

const investigationContextPath = "/api/v1/investigations/" + reportID

func TestInvestigationContextRejectsInvalidRequestsBeforeStore(t *testing.T) {
	for _, test := range []struct {
		method, path string
		status       int
	}{
		{http.MethodPost, investigationContextPath, http.StatusMethodNotAllowed},
		{http.MethodGet, "/api/v1/investigations/invalid", http.StatusBadRequest},
		{http.MethodGet, investigationContextPath + "?query=arbitrary", http.StatusBadRequest},
		{http.MethodGet, investigationContextPath + "?", http.StatusBadRequest},
		{http.MethodGet, investigationContextPath + "?%zz", http.StatusBadRequest},
	} {
		t.Run(test.method+test.path, func(t *testing.T) {
			reader := &fakeReader{}
			response := serve(NewHandler(reader, discardLogger()), test.method, test.path)
			if response.Code != test.status || reader.calls != 0 {
				t.Fatalf("status=%d calls=%d body=%s", response.Code, reader.calls, response.Body.String())
			}
			if test.status == http.StatusMethodNotAllowed && response.Header().Get("Allow") != http.MethodGet {
				t.Fatal("missing Allow header")
			}
		})
	}
}

func TestInvestigationContextPassesIDAndUsesStableErrors(t *testing.T) {
	reader := &fakeReader{context: store.InvestigationContext{InvestigationID: reportID}}
	response := serve(NewHandler(reader, discardLogger()), http.MethodGet, investigationContextPath)
	var envelope struct {
		Data      store.InvestigationContext `json:"data"`
		RequestID string                     `json:"request_id"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusOK || reader.calls != 1 || reader.contextID != reportID ||
		envelope.Data.InvestigationID != reportID || envelope.RequestID == "" || envelope.RequestID != response.Header().Get("X-Request-ID") {
		t.Fatalf("status=%d reader=%+v envelope=%+v", response.Code, reader, envelope)
	}
	for _, test := range []struct {
		err    error
		status int
		code   string
	}{
		{store.ErrNotFound, http.StatusNotFound, "not_found"},
		{errors.New("private-database-connection-string"), http.StatusInternalServerError, "internal_error"},
	} {
		reader := &fakeReader{err: test.err}
		response := serve(NewHandler(reader, discardLogger()), http.MethodGet, investigationContextPath)
		assertErrorResponse(t, response, test.status, test.code)
		if reader.calls != 1 || strings.Contains(response.Body.String(), "private-database") {
			t.Fatalf("calls=%d body=%s", reader.calls, response.Body.String())
		}
	}
}

func TestInvestigationContextRejectsInvalidStoreIDWithoutDatabase(t *testing.T) {
	_, err := store.NewPostgres(nil).GetInvestigationContext(context.Background(), "invalid")
	if !errors.Is(err, store.ErrInvalidInput) {
		t.Fatalf("invalid store ID error = %v", err)
	}
}
