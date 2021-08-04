package server

import (
	"hello-go-rest-api/auth"
	"hello-go-rest-api/routes"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/urfave/negroni"
)

func StartServer() {
	auth.RefreshHelseidMetadata()

	r := mux.NewRouter()

	r.Handle("/foo", negroni.New(
		negroni.HandlerFunc(auth.IsAuthenticatedAndAuthorizedMiddleware("norsk-helsenett:golang-sample-api/foo")),
		negroni.Wrap(http.HandlerFunc(routes.Foo)),
	)).Methods("GET")

	http.ListenAndServe(":3123", r)
}
