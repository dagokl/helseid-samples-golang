package callapi

import (
	"fmt"
	"helseid-webapp/auth"
	"helseid-webapp/sessionstorage"
	"io/ioutil"
	"net/http"
	"text/template"
)

var responseTemplate, _ = template.ParseFiles("routes/callapi/callapi.html")

func CallApiHandler(w http.ResponseWriter, r *http.Request) {

	// retrieve access token from session
	session, err := sessionstorage.Store.Get(r, "auth-session")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	accessToken, ok := session.Values["access_token"].(string)
	if !ok {
		http.Error(w, "No access token found in session", http.StatusForbidden)
		return
	}

	// make a request to the api with a client that automatically adds
	// Authorization header with content: Bearer (the encoded access token)
	resourceEndpoint := "http://localhost:3123/foo"
	client := auth.NewClient(accessToken)
	resp, err := client.Get(resourceEndpoint)
	if err != nil {
		http.Error(w, "Making a request to the api failed, error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	data := map[string]string{
		"status":           fmt.Sprint(resp.StatusCode, " ", http.StatusText(resp.StatusCode)),
		"body":             string(body),
		"resourceEndpoint": resourceEndpoint,
	}

	responseTemplate.Execute(w, data)
}
