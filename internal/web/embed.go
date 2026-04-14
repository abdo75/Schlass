package web

import (
	"embed"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed all:dist
var distFS embed.FS

func SPAHandler() http.Handler {
	dist, err := fs.Sub(distFS, "dist")
	if err != nil {
		panic("failed to create sub filesystem for dist: " + err.Error())
	}

	fileServer := http.FileServerFS(dist)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/")

		if path == "" {
			fileServer.ServeHTTP(w, r)
			return
		}

		if _, err := fs.Stat(dist, path); err != nil {
			r.URL.Path = "/"
			fileServer.ServeHTTP(w, r)
			return
		}

		fileServer.ServeHTTP(w, r)
	})
}
