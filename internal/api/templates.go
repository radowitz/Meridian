package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/radowitz/meridian/internal/defaults"
	"github.com/radowitz/meridian/internal/model"
	"github.com/radowitz/meridian/internal/validate"
)

// Topology templates (defaults.Templates): the wizard lists them, posts
// the operator's answers and gets back a topology it can show, edit and
// save with PUT /api/topology. A preview never saves anything.

// templatePreview is the answer of POST /api/templates/{id}/preview.
type templatePreview struct {
	Template string                `json:"template"`
	Topology model.Topology        `json:"topology"`
	Valid    bool                  `json:"valid"`
	Issues   []validate.Issue      `json:"issues"`
	Paths    []validate.PathReport `json:"paths"`
}

func (s *Server) registerTemplates(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/templates", s.getTemplates)
	mux.HandleFunc("POST /api/templates/{id}/preview", s.postTemplatePreview)
}

func (s *Server) getTemplates(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"templates": defaults.Templates()})
}

func (s *Server) postTemplatePreview(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, ok := defaults.TemplateByID(id); !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "没有这个模板", "field": "template"})
		return
	}
	var in defaults.TemplateInput
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "请求格式不对：" + err.Error()})
		return
	}
	topo, err := defaults.GenerateTemplate(id, in)
	if err != nil {
		var te *defaults.TemplateError
		if errors.As(err, &te) {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": te.Message, "field": te.Field})
			return
		}
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	res := validate.Run(topo)
	writeJSON(w, http.StatusOK, templatePreview{Template: id, Topology: topo, Valid: !res.HasErrors(), Issues: res.Issues, Paths: res.Paths})
}
