package admin

import (
	_ "embed"
	"net/http"
	"text/template"

	"github.com/movsb/gun/admin/tests/speeds"
)

type Server struct {
	mux *http.ServeMux
}

type IndexData struct {
}

func NewServer() *Server {
	s := &Server{
		mux: http.NewServeMux(),
	}

	s.mux.HandleFunc(`/`, func(w http.ResponseWriter, r *http.Request) {
		indexTmpl.Execute(w, r)
	})

	s.mux.Handle(`GET /api/speed/icons/`, http.StripPrefix(`/api/speed/icons`, http.FileServerFS(speeds.Icons())))

	return s
}

//go:embed index.html
var _indexHTML []byte
var indexTmpl = template.Must(template.New(`index.html`).Parse(string(_indexHTML)))

func (s *Server) Handler() http.Handler {
	return s.mux
}
