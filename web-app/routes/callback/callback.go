package callback

import (
	"context"
	"helseid-webapp/auth"
	"helseid-webapp/sessionstorage"
	"log"
	"net/http"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

func CallbackHandler(w http.ResponseWriter, r *http.Request) {

	// get the session to retrive values stored at login
	session, err := sessionstorage.Store.Get(r, "auth-session")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// check that state matches state generated when initiating login
	if r.URL.Query().Get("state") != session.Values["state"] {
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		return
	}

	// get code verifier from session and create a AuthCodeOption for the token exchange request
	codeVerifier := session.Values["code-verifier"].(string)
	codeVerifierOpt := oauth2.SetAuthURLParam("code_verifier", codeVerifier)

	// generate a jwt to authenticate client with client assertion
	clientAssertionToken, err := auth.GenerateClientAssertionToken()
	if err != nil {
		http.Error(w, "Failed to create client assertion token", http.StatusInternalServerError)
		return
	}
	clientAssertionTokenOpt := oauth2.SetAuthURLParam("client_assertion", clientAssertionToken)
	clientAssertionTypeOpt := oauth2.SetAuthURLParam("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")

	// create new authenticator
	authenticator, err := auth.NewAuthenticator()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// exchange authorization code for access token
	token, err := authenticator.Config.Exchange(context.TODO(), r.URL.Query().Get("code"), codeVerifierOpt, clientAssertionTokenOpt, clientAssertionTypeOpt)
	if err != nil {
		log.Printf("no token found: %v\n", err)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// extract ID token string from auth token
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "No id_token field in oauth2 token.", http.StatusInternalServerError)
		return
	}

	// verify the ID token and convert to oidc.IDToken type
	oidcConfig := &oidc.Config{
		ClientID: auth.ClientId,
	}
	idToken, err := authenticator.Provider.Verifier(oidcConfig).Verify(context.TODO(), rawIDToken)
	if err != nil {
		http.Error(w, "Failed to verify ID Token"+err.Error(), http.StatusInternalServerError)
		return
	}

	// check that the nonce in idToken matches the nonce of the session
	if idToken.Nonce != session.Values["nonce"] {
		http.Error(w, "Invalid nonce", http.StatusBadRequest)
		return
	}

	// getting the claims from the id token
	var claims map[string]interface{}
	if err := idToken.Claims(&claims); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// save ID token, access token and claims
	session.Values["id_token"] = rawIDToken
	session.Values["access_token"] = token.AccessToken
	session.Values["claims"] = claims

	// save content of session
	err = session.Save(r, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// redirect to user page
	http.Redirect(w, r, "/user", http.StatusSeeOther)
}
