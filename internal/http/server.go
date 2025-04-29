// Copyright 2021 Google LLC. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package http contains private implementation details for the witness server.
package http

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/transparency-dev/witness/api"
	"github.com/transparency-dev/witness/internal/witness"
	"k8s.io/klog/v2"
)

// Server is the core handler implementation of the witness.
type Server struct {
	w *witness.Witness
}

// NewServer creates a new server.
func NewServer(witness *witness.Witness) *Server {
	return &Server{
		w: witness,
	}
}

// getCheckpoint returns a checkpoint stored for a given log.
func (s *Server) getCheckpoint(w http.ResponseWriter, r *http.Request) {
	v := mux.Vars(r)
	logID := v["logid"]
	// Get the signed checkpoint from the witness.
	chkpt, err := s.w.GetCheckpoint(logID)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to get checkpoint: %v", err), http.StatusInternalServerError)
		return
	} else if chkpt == nil {
		http.Error(w, "unknown log", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if _, err := w.Write(chkpt); err != nil {
		klog.Warningf("Error writing response: %v", err)
	}
}

// getLogs returns a list of all logs the witness is aware of.
func (s *Server) getLogs(w http.ResponseWriter, r *http.Request) {
	logs, err := s.w.GetLogs()
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to get log list: %v", err), http.StatusInternalServerError)
		return
	}
	logList, err := json.Marshal(logs)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to convert log list to JSON: %v", err), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/json")
	if _, err := w.Write(logList); err != nil {
		klog.Warningf("Error writing response: %v", err)
	}
}

// RegisterHandlers registers HTTP handlers for witness endpoints.
func (s *Server) RegisterHandlers(r *mux.Router) {
	logStr := "{logid:[a-zA-Z0-9-]+}"
	r.HandleFunc(fmt.Sprintf(api.HTTPGetCheckpoint, logStr), s.getCheckpoint).Methods(http.MethodGet)
	r.HandleFunc(api.HTTPGetLogs, s.getLogs).Methods(http.MethodGet)
}
