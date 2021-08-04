package login

import (
	"helseid-webapp/auth"
	"helseid-webapp/sessionstorage"
	"net/http"

	"golang.org/x/oauth2"
)

func LoginHandler(w http.ResponseWriter, r *http.Request) {

	// create session to save values to
	session, err := sessionstorage.Store.Get(r, "auth-session")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// generate state
	state, err := auth.GenerateState()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// save state
	session.Values["state"] = state

	// generate code cerifier and code challenge
	codeVerifier, codeChallenge, err := auth.GenerateCodeVerifierAndChallenge()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// save code verifier
	session.Values["code-verifier"] = codeVerifier

	// generate nonce
	nonce, err := auth.GenerateNonce()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	// save nonce
	session.Values["nonce"] = nonce

	// save the content in session
	err = session.Save(r, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// create AuthCodeOptions to append code challenge and nonce to auth code request
	codeChallengeOpt := oauth2.SetAuthURLParam("code_challenge", codeChallenge)
	codeChallengeMethodOpt := oauth2.SetAuthURLParam("code_challenge_method", "S256")
	nonceOpt := oauth2.SetAuthURLParam("nonce", nonce)

	// create new authenticator
	authenticator, err := auth.NewAuthenticator()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	requestObject, _ := auth.GenerateRequestObject(state, nonce, codeChallenge)
	requestObjectOpt := oauth2.SetAuthURLParam("request", requestObject)

	// redirect to HelseID login page
	http.Redirect(w, r, authenticator.Config.AuthCodeURL(state, codeChallengeOpt, codeChallengeMethodOpt, nonceOpt, requestObjectOpt), http.StatusTemporaryRedirect)
}
