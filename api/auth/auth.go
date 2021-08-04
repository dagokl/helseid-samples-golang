package auth

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

const apiName = "norsk-helsenett:golang-sample-api"
const authorizationServerMetadataUrl = "https://helseid-sts.utvikling.nhn.no/.well-known/openid-configuration"

// Middleware that will only redirect to next if the token in the request is valid.
// If the token is not found or is not valid it will respond with http error 401 unauthorized.
func IsAuthenticatedMiddleware(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	_, err := getTokenFromAuthHeaderAndValidate(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	next(w, r)
}

// Middleware that will only redirect to next if the token in the request
// is valid and the required scope is in the scopes in token.
// If the token is not found, is not valid, or the token did not have
// the required scope it will respond with http error 401 unauthorized.
func IsAuthenticatedAndAuthorizedMiddleware(requiredScope string) func(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	return func(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
		token, err := getTokenFromAuthHeaderAndValidate(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		var claims struct {
			Scopes []string `json:"scope"`
		}
		// signature already verified in getTokenFromAuthHeaderAndValidate
		token.UnsafeClaimsWithoutVerification(&claims)

		for _, scope := range claims.Scopes {
			if scope == requiredScope {
				next(w, r)
				return
			}
		}

		http.Error(w, "access token did not contain the required scope", http.StatusUnauthorized)
	}
}

func getTokenFromAuthHeaderAndValidate(r *http.Request) (*jwt.JSONWebToken, error) {
	authHeader := r.Header.Get("Authorization")

	authHeaderParts := strings.Fields(authHeader)
	if len(authHeaderParts) != 2 || strings.ToLower(authHeaderParts[0]) != "bearer" {
		return nil, errors.New("authorization header format must be: Bearer {the base64 url encoded access token without curly braces}")
	}

	tokenString := authHeaderParts[1]

	token, err := jwt.ParseSigned(tokenString)
	if err != nil {
		return nil, err
	}

	claims := jwt.Claims{}
	err = token.Claims(helseidMetadata.Jwks, &claims)
	if err != nil {
		return nil, err
	}

	// validate the claims: issuer, audience, notBefore, issuedAt and expiry
	err = claims.ValidateWithLeeway(jwt.Expected{
		Issuer:   helseidMetadata.Issuer,
		Audience: jwt.Audience{apiName},
		Time:     time.Now(),
	}, 0)
	if err != nil {
		return nil, err
	}

	// check that access token does not have multiple audiences
	// see: https://helseid.atlassian.net/wiki/spaces/HELSEID/pages/278102040/Our+policy+regarding+access+tokens+and+audiences
	if len(claims.Audience) > 1 {
		return nil, errors.New("access token contained multiple audiences")
	}

	/*
		// here you can extract any claims from the access token
		extraClaims := struct {
			AssuranceLevel string `json:"helseid://claims/identity/assurance_level"`
			SecurityLevel  string `json:"helseid://claims/identity/security_level"`
			Pid            string `json:"helseid://claims/identity/pid"`
			Hpr            string `json:"helseid://claims/hpr/hpr_number"`
			OrgNrParent    string `json:"helseid://claims/client/claims/orgnr_parent"`
			OrgNrChild     string `json:"helseid://claims/client/claims/orgnr_child"`
		}{}
		err = token.UnsafeClaimsWithoutVerification(&extraClaims)
		if err != nil {
			return nil, err
		}

		// always check assurance level or security level
		// check assurance level
		if extraClaims.AssuranceLevel != "high" {
			return nil, fmt.Errorf("authenticated with assurance level: %v, requieres: %v", extraClaims.AssuranceLevel, "high")
		}

		// check security level
		if securityLevel, _ := strconv.Atoi(extraClaims.SecurityLevel); securityLevel < 4 {
			return nil, fmt.Errorf("authenticated with security level: %v, requieres: %v", extraClaims.AssuranceLevel, 4)
		}

		// consider validating and verifying the claims Pid, Hpr, OrgNrParent and OrnNrChild
	*/

	return token, nil
}

type authorizationServerMetadata struct {
	Issuer   string
	Jwks_uri string
	Jwks     jose.JSONWebKeySet
}

var helseidMetadata authorizationServerMetadata

// Fetches all the data required from wellknownUri.
// Including issuer, jwks uri and jwks.
func RefreshHelseidMetadata() {
	resp, err := http.Get(authorizationServerMetadataUrl)
	if err != nil {
		log.Fatalf("Failed to get the authorization server metadata from %v\n    Error: %s\n", authorizationServerMetadataUrl, err.Error())
		return
	}

	err = json.NewDecoder(resp.Body).Decode(&helseidMetadata)
	resp.Body.Close()
	if err != nil {
		log.Fatalf("Failed to parse respone from authorization server metadata\n    Error: %s\n", err.Error())
	}

	// fetch the JWKs used to autheticate the signature in tokens and save it in helseIdMetadata
	resp, err = http.Get(helseidMetadata.Jwks_uri)
	if err != nil {
		log.Fatalf("Failed to get the JWKs from %v\n    Error: %s\n", helseidMetadata.Jwks_uri, err.Error())
		return
	}

	var rawJsonKeys struct {
		Keys []json.RawMessage
	}
	err = json.NewDecoder(resp.Body).Decode(&rawJsonKeys)
	resp.Body.Close()
	if err != nil {
		log.Fatalf("Failed to parse JWKs from %v\n    Error: %s\n", helseidMetadata.Jwks_uri, err.Error())
	}

	keySet := []jose.JSONWebKey{}
	for _, rawKey := range rawJsonKeys.Keys {
		key := jose.JSONWebKey{}
		key.UnmarshalJSON(rawKey)
		keySet = append(keySet, key)
	}
	helseidMetadata.Jwks = jose.JSONWebKeySet{Keys: keySet}
}
