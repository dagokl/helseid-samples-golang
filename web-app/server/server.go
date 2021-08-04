package server

import (
	"helseid-webapp/routes/callapi"
	"helseid-webapp/routes/callback"
	"helseid-webapp/routes/home"
	"helseid-webapp/routes/login"
	"helseid-webapp/routes/logout"
	"helseid-webapp/routes/middlewares"
	"helseid-webapp/routes/user"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/urfave/negroni"
)

func StartServer() {
	r := mux.NewRouter()
	// redirects to userpage if user is already authenticated
	r.Handle("/", negroni.New(
		negroni.HandlerFunc(middlewares.IsNotAuthenticated),
		negroni.Wrap(http.HandlerFunc(home.HomeHandler)),
	))
	r.HandleFunc("/", home.HomeHandler)
	r.HandleFunc("/login", login.LoginHandler)
	r.HandleFunc("/callback", callback.CallbackHandler)
	// redirects to homepage if user is not authenticated
	r.Handle("/user", negroni.New(
		negroni.HandlerFunc(middlewares.IsAuthenticated),
		negroni.Wrap(http.HandlerFunc(user.UserHandler)),
	))
	r.HandleFunc("/logout", logout.LogoutHandler)
	r.HandleFunc("/callapi", callapi.CallApiHandler)

	// Important note:
	// Do not use ListenAndServe(http) use ListenAndServeTLS(https) instead
	// All client using HelseID must use TLS 1.2 or greater
	http.ListenAndServe(":44123", r)
}
