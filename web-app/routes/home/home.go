package home

import (
	"html/template"
	"net/http"
)

var homeTemplate, _ = template.ParseFiles("routes/home/home.html")

func HomeHandler(w http.ResponseWriter, r *http.Request) {
	homeTemplate.Execute(w, nil)
}
