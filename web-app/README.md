# HelseID sample web app in Golang

To run code in terminal
```
go run main.go
```

To build project
```
go build main.go
```

## Before using snipets of this in your own code:
 - This is NOT meant as an example of how to create a safe web app. It is only intended to give a gist of how to you can implement helseID in your application.
 - This application does NOT use https and is therefore unsafe.
 - The configuration options are at the top of auth.go.
 - In this sample all private keys are stored in source code because we want the program to work without any configuration. When using any of the code in your own application DO NOT store any private keys in source code. One alternative is to store them in environment variables and access them with os.Getenv.
	 - Change the key in sessionsstorage.go to a secret and cryptographically random string (e.g. use the crypto/rand package) and DO NOT store this in source code.
	 - In auth.getJwtSigner there is stored a JWK, create your own and store it safely.


## A quick overview
This section is a quick overview of what happens at the endpoints of the app in the order they are used when starting at homepage, logging in, using the access token to request a resource from an API and logging out. When referring to endpoints at helseID we shorten them to helseid followed by the last part. e.g. https://helseid-sts.utvikling.nhn.no/connect/token becomes helseid/token.

### /
The home page only contains a link redirecting to /login.

### /login
When a user makes a request to /login our response is a redirect to helseid/auth. Here the user logs in with IDporten, bankID or something similar. After this the user is redirected back to the redirect_uri we specified in the redirect to /connect/auth, in our case the redirect_uri is /callback.

### /callback
The user is redirected here by helseID, and the user’s request comes with some params, like authorization code. We use this code to make a request to helseid/connect/token. HelseID responds with an access token and an id token. We verify the authenticity of the id token and save them for later use. Then we redirect the user to /user.

### /user
Here we retrieve the claims in the id token of the logged in user. We display a simple page with the name of the logged in user. There are also links to the /callapi and /logout.

### /callapi
For this endpoint to work you must run the golang sample api and be logged in to this web app. Here we use the access token to request a resource from an resource api. To do this we send a request htt://localhost:3123/foo with “Bearer {the access token}” in the Authorization header. The information from the response will be displayed on the web page.

### /logout
First, we retrieve the saved id token. Then we delete the cookie "auth-session", then we redirect the user to helseid/auth/endsession with the id token and a redirect uri as params. After a successful logout helseID will redirect to /.


## Security features

### State
State is a random string generated at /login. It is saved and then appended to the redirect to helseid/connect/auth. When the user is sent back to /callback this request should contain the same state that we created earlier, if not, we abort the authentication process. State is a security measurement to prevent Cross-site request forgery(CSRF).

### Nonce
Nonce is very similar to state. The only difference is that it is not in the params of the request to /callback, it is instead inside the payload of the id token which is in the params of the request to /callback. Just as with state, if it does not match the nonce created earlier, we abort the authentication process.

### PKCE
First, we create a code verifier, which is just a random string. Then we create a code challenge which is a hashed version of the code verifier. We redirect to helseid/connect/auth and append the code challenge. And when we make a request to helseid/connect/token we append the code verifier. This makes it possible for helseid to confirm that the program making the request to helseid/connect/token is the same program that redirected the user to helseid/connect/auth.

### Request Object
At /login we send a request to helseid/auth to receive an authorization code. To ensure that the parameters of this request are not tampered with we add the parameters to the claims of an JWT and sign it.

### Client assertion
In the context of OAuth 2.0 a client assertion is a signed JWT used to authenticate a client to the authorization server. We use this mechanism when requesting an access token and an id token from helseid/token. The most normal alternative to a client assertion is use a "client secret", which is a secret shared between the client and the authorization server and added to the request were the client need to be authenticated. Using a client assertion is safer because the private key is only stored in the client, and only used to sign a client assertion which has a limited lifetime.
