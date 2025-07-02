package handlers

import (
	"github.com/gorilla/mux"
	"net/http"
)

func (h *Handler) Router() http.Handler {
	r := mux.NewRouter()

	r.HandleFunc("/users", h.Register).Methods("POST")
	r.HandleFunc("/sessions", h.Login).Methods("POST")
	r.HandleFunc("/sessions", h.Refresh).Methods("PATCH")
	r.HandleFunc("/sessions", h.Logout).Methods("DELETE")

	return r
}
