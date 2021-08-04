package logout

import (
	"fmt"
	"helseid-webapp/auth"
	"helseid-webapp/sessionstorage"
	"net/http"
	"net/url"
)

// Redirects user to helse id logout to logout of helseid globaly.
// Afterwards the user is redirect back to the provided redirect url.
// If redirect is not requierd simply delete the cookie "auth-session"
// and redirect to https://helseid-sts.utvikling.nhn.no/connect/endsession
// without any parameters.
func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	// get the session to retrive id token stored at token exchange
	session, err := sessionstorage.Store.Get(r, "auth-session")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	logoutUrl, err := url.ParseRequestURI(auth.HelseidMetadata.End_session_endpoint)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// get the id token
	idToken := fmt.Sprintf("%v", session.Values["id_token"])

	// delete cookie associated with auth session
	c := http.Cookie{
		Name:   "auth-session",
		MaxAge: -1,
	}
	http.SetCookie(w, &c)

	// add the parameters id_token_hint and post_logout_redirect_uri
	// both are only required for the user to be redirected after logout
	// if either is omited the user have to confirm logout at helseID site
	// and will not be redirected afterwards
	parameters := url.Values{}
	parameters.Add("id_token_hint", idToken)
	parameters.Add("post_logout_redirect_uri", auth.RedirectLogoutUrl)
	logoutUrl.RawQuery = parameters.Encode()

	http.Redirect(w, r, logoutUrl.String(), http.StatusTemporaryRedirect)
}
