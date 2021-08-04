package middlewares

import (
	"helseid-webapp/sessionstorage"
	"net/http"
)

func IsAuthenticated(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {

	session, err := sessionstorage.Store.Get(r, "auth-session")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if _, ok := session.Values["claims"]; !ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
	} else {
		next(w, r)
	}
}

func IsNotAuthenticated(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {

	session, err := sessionstorage.Store.Get(r, "auth-session")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if _, ok := session.Values["claims"]; !ok {
		next(w, r)
	} else {
		http.Redirect(w, r, "/user", http.StatusSeeOther)
	}
}
