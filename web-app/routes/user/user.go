package user

import (
	"helseid-webapp/sessionstorage"
	"net/http"
	"text/template"
)

var userTemplate, _ = template.ParseFiles("routes/user/user.html")

func UserHandler(w http.ResponseWriter, r *http.Request) {

	session, err := sessionstorage.Store.Get(r, "auth-session")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	claims := session.Values["claims"]

	userTemplate.Execute(w, claims)
}
