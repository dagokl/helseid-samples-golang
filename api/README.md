# HelseID sample API

To run code in terminal
```
go run main.go
```

To build project
```
go build main.go
```

The only endpoint of the API is /foo. It requires that the user/client that send the request add an access token to the Authorization header. The access token must be valid, and some of the requirements for the claims is that the audience of the token is the API-name and scope must contain the scope foo (norsk-helsenett:golang-sample-api/foo).
