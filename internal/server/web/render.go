package web

import (
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"time"

	"github.com/Soup9x/Lake-Effect-Buoy/internal/protocol"
	"github.com/Soup9x/Lake-Effect-Buoy/internal/server/auth"
	"github.com/Soup9x/Lake-Effect-Buoy/internal/server/store"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

func staticFiles() http.Handler {
	sub, _ := fs.Sub(staticFS, "static")
	return http.FileServer(http.FS(sub))
}

var funcs = template.FuncMap{
	"ago": func(t *time.Time) string {
		if t == nil {
			return ""
		}
		return ago(time.Since(*t))
	},
	"fmtTime": func(v any) string {
		switch t := v.(type) {
		case time.Time:
			return t.UTC().Format("2006-01-02 15:04 UTC")
		case *time.Time:
			if t == nil {
				return ""
			}
			return t.UTC().Format("2006-01-02 15:04 UTC")
		}
		return ""
	},
	"deref": func(s *string) string {
		if s == nil {
			return ""
		}
		return *s
	},
	"derefInt": func(i *int) string {
		if i == nil {
			return ""
		}
		return fmt.Sprint(*i)
	},
	// sigClass colours signature age: amber after 2 days, red after 7.
	"sigClass": func(t *time.Time) string {
		if t == nil {
			return "muted"
		}
		switch age := time.Since(*t); {
		case age > 7*24*time.Hour:
			return "bad"
		case age > 2*24*time.Hour:
			return "warn"
		}
		return "ok"
	},
	"clamdClass": func(s string) string {
		switch s {
		case protocol.ClamdRunning:
			return "ok"
		case protocol.ClamdNotResponding, protocol.ClamdNotInstalled:
			return "bad"
		}
		return "muted"
	},
	"actionLabel":   actionLabel,
	"actionSummary": actionSummary,
	"statusClass":   statusClass,
	"scanInfected":  scanInfected,
	"paramPath":     paramPath,
	"json": func(v any) string {
		b, _ := json.Marshal(v)
		return string(b)
	},
}

func ago(d time.Duration) string {
	switch {
	case d < 0:
		return "just now"
	case d < time.Minute:
		return fmt.Sprintf("%ds ago", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	}
	return fmt.Sprintf("%dd ago", int(d.Hours()/24))
}

type templates map[string]*template.Template

func loadTemplates() templates {
	pages := []string{"login", "mfa", "tenants", "tenant", "agent", "audit", "users", "account", "run", "job", "jobs", "action"}
	t := templates{}
	for _, p := range pages {
		t[p] = template.Must(template.New(p).Funcs(funcs).ParseFS(templateFS, "templates/layout.html", "templates/tenants.html", "templates/"+p+".html"))
	}
	return t
}

// page is the data passed to every full-page template.
type page struct {
	Title   string
	Session *store.Session
	Flash   string
	Error   string
	Data    any
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, status int, name string, p page) {
	p.Session = auth.SessionFrom(r)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := s.tmpl[name].ExecuteTemplate(w, "layout", p); err != nil {
		s.Log.Error("render failed", "template", name, "err", err)
	}
}

func (s *Server) renderFragment(w http.ResponseWriter, name, block string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := s.tmpl[name].ExecuteTemplate(w, block, data); err != nil {
		s.Log.Error("render failed", "template", name, "block", block, "err", err)
	}
}
