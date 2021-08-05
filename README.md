# HelseID Samples in Golang

## [Web app](web-app)
The web app demonstrates the authorization code flow (openID connect). It uses the id token to verify the identity of the user. It also gets an access token, which it uses to retrieve a resource from the API.

## [m2m app](m2m-app)
The m2m app uses the client credentials flow (OAuth 2.0) to get an access token, and uses the access token retrieve a resource from the API.

## [API](api)
The API is very simple and only have one endpoint. To get the resource from this endpoint the user/client must add an access token to the header of the request.
