# HelseID machine to machine app
This app demonstrated how to use the client credentials flow to obtain a access token from helseID, and use the access token to request a resource from an API. Since the access token is obtained with the client credentials flow it is an access token that authenticates a client, not a user.
One extra secret precaution that is implemented in this app that is required to use helseID is to use a client assertion to authenticate the client to helseID, this is an alternative to using a secret shared with helseID. Since we use a asymmetric key to sign the client assertion token we keep the private key only on this machine, and we only to store a public key at helseID to verify the signature.

Requires that the [API](../api) is running to get a response.  
To run code in terminal
```
go run main.go
```

To build project
```
go build main.go
```
