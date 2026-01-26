package admin

import (
	"net/http"
	"text/template"
)

type Server struct {
	mux *http.ServeMux
}

func NewServer() *Server {
	s := &Server{
		mux: http.NewServeMux(),
	}

	s.mux.HandleFunc(`/`, func(w http.ResponseWriter, r *http.Request) {
		t.Execute(w, r)
	})

	return s
}

var t = template.Must(template.New(`test`).Parse(`test`))

func (s *Server) Handler() http.Handler {
	return s.mux
}
