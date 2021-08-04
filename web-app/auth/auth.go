package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log"
	"math"
	"net/http"
	"strings"
	"time"

	oidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

// settings

const ClientId = "golang-web-app"

var scopes = []string{"openid", "profile", "norsk-helsenett:golang-sample-api/foo"}

const redirectLoginUrl = "http://localhost:44123/callback"
const RedirectLogoutUrl = "http://localhost:44123"
const authorizationServerMetadataUrl = "https://helseid-sts.utvikling.nhn.no/.well-known/openid-configuration"

const stateLength = 64
const nonceLength = 64
const codeVerifierLength = 64

// add fields to this struct to fetch the corresponding value from the well-known endpoint
type authorizationServerMetadata struct {
	Issuer                 string
	Authorization_endpoint string
	Token_endpoint         string
	End_session_endpoint   string
}

var HelseidMetadata authorizationServerMetadata
var jwtSigner jose.Signer

// Fetches all the data required from wellKnownUrl.
// What values to fetch is defines in the wellKnown struct.
func RefreshHelseidMetadata() {
	resp, err := http.Get(authorizationServerMetadataUrl)
	if err != nil {
		log.Fatalf("Failed to get the well-known from %v\n    Error: %s\n", authorizationServerMetadataUrl, err.Error())
	}

	err = json.NewDecoder(resp.Body).Decode(&HelseidMetadata)
	if err != nil {
		log.Fatalf("Failed to parse respone from well-known\n    Error: %s\n", err.Error())
	}
}

type Authenticator struct {
	Provider *oidc.Provider
	Config   oauth2.Config
	Ctx      context.Context
}

func NewAuthenticator() (*Authenticator, error) {
	ctx := context.Background()

	provider, err := oidc.NewProvider(ctx, HelseidMetadata.Issuer)
	if err != nil {
		log.Printf("failed to get provider: %v", err)
		return nil, err
	}

	conf := oauth2.Config{
		ClientID:    ClientId,
		RedirectURL: redirectLoginUrl,
		Endpoint:    provider.Endpoint(),
		Scopes:      scopes,
	}

	return &Authenticator{
		Provider: provider,
		Config:   conf,
		Ctx:      ctx,
	}, nil
}

func NewClient(accessTokenString string) *http.Client {
	token := oauth2.Token{
		AccessToken: accessTokenString,
	}

	authenticator, _ := NewAuthenticator()

	return authenticator.Config.Client(authenticator.Ctx, &token)
}

func GenerateState() (string, error) {
	state, err := generateRandomString(stateLength)
	if err != nil {
		return "", err
	}

	return state, nil
}

func GenerateNonce() (string, error) {
	nonce, err := generateRandomString(nonceLength)
	if err != nil {
		return "", err
	}

	return nonce, nil
}

func GenerateCodeVerifierAndChallenge() (string, string, error) {
	// generate the code verifier
	codeVerifier, err := generateRandomString(codeVerifierLength)
	if err != nil {
		return "", "", err
	}

	// create SHA256 code challenge from code verifier
	h := sha256.New()
	_, err = h.Write([]byte(codeVerifier))
	if err != nil {
		return "", "", err
	}

	codeChallenge := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	return codeVerifier, codeChallenge, nil
}

func GenerateClientAssertionToken() (string, error) {

	jti, err := generateRandomString(24)
	if err != nil {
		return "", err
	}

	claims := jwt.Claims{
		Issuer:    ClientId,
		Subject:   ClientId,
		NotBefore: jwt.NewNumericDate(time.Now()),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		Expiry:    jwt.NewNumericDate(time.Now().Add(time.Minute)),
		ID:        jti,
		Audience:  jwt.Audience{HelseidMetadata.Token_endpoint},
	}

	raw, err := generateSignedJwt(claims)
	if err != nil {
		return "", err
	}

	return raw, nil
}

func GenerateRequestObject(state, nonce, codeChallenge string) (string, error) {

	jti, err := generateRandomString(24)
	if err != nil {
		return "", err
	}

	claims := struct {
		Id                    string           `json:"jti"`
		NotBefore             *jwt.NumericDate `json:"nbf"`
		Expiry                *jwt.NumericDate `json:"exp"`
		Iss                   string           `json:"iss"`
		Client_id             string           `json:"client_id"`
		Aud                   string           `json:"aud"`
		Response_type         string           `json:"response_type"`
		Redirect_uri          string           `json:"redirect_uri"`
		Scope                 string           `json:"scope"`
		State                 string           `json:"state"`
		Nonce                 string           `json:"nonce"`
		Code_challenge        string           `json:"code_challenge"`
		Code_challenge_method string           `json:"code_challenge_method"`
	}{
		Id:                    jti,
		NotBefore:             jwt.NewNumericDate(time.Now()),
		Expiry:                jwt.NewNumericDate(time.Now().Add(time.Minute)),
		Iss:                   ClientId,
		Client_id:             ClientId,
		Aud:                   HelseidMetadata.Issuer,
		Response_type:         "code",
		Redirect_uri:          redirectLoginUrl,
		Scope:                 strings.Join(scopes, " "),
		State:                 state,
		Nonce:                 nonce,
		Code_challenge:        codeChallenge,
		Code_challenge_method: "S256",
	}

	raw, err := generateSignedJwt(claims)
	if err != nil {
		return "", err
	}

	return raw, nil
}

func generateSignedJwt(claims interface{}) (string, error) {
	if jwtSigner == nil {
		var err error
		jwtSigner, err = getJwtSigner()
		if err != nil {
			return "", err
		}
	}

	jwtString, err := jwt.Signed(jwtSigner).Claims(claims).CompactSerialize()
	if err != nil {
		return "", err
	}

	return jwtString, nil
}

func getJwtSigner() (jose.Signer, error) {
	// DO NOT save private keys in source code!
	keyJson := `{
		"p": "7msmV6Jw7Bge_6WThzw9b5lT-_Y-b2WQutNTPSS444Bt6VekUmIB8QZtXDF3Bq2ZXdGJ-IQ7Rj0_PSpC3F1k-EQ4C5_CEtAMIxr1tRzyoZ_4UMoUcmcFkXSj4ca6-0Q5xFZcAmnsFossm3sONK_rChZaGVVgFa5km6_olnK_hkF0llwrbBqvecwpVHRgpn5jCypjkvKZpNKV6cpMt2w0hLUyYyySXiOODJcvxYSQ0YbA1PIqyiOiN-5bjd01lZ3hYvCwEmMy7jCSfezAno-kxsTKIaBINE8LJWxBTTyLENLQ98EM5OAJsojS_pOXzVhesyyqvQF-7HiVvRtj8mq9XQ",
		"kty": "RSA",
		"q": "wmbqPApVGowvhhr1viWVrJ7J3Ennhpq_a_13zPwSzdZtzIrSN8VvGTODnTfkWp4wAxWE4QsN9serO4OuXolKJL0RXMV7nF4hHaf3qQQHQ3iOHwwSvk23viapqGdMW_fuAuMRoyZYXujHrv1UwPh1Qsp3IWU02L0h2qHc37rKmJyCsrj7jfsnW8hijVuyw5GoCCxrUHu9Jd0WsP0SJ4qO_CAg3LcYQJLYhtcs0TcyShzLaF0Dv7rrqVbQgG8bHIPAoPxuPKe5Gg6gNRZJqWz4cCFUwdenWJnG_jum0rgYN4G-mYio1fjanWE0QkrIpQN3khaDhI6PjAR0tahLUyG6BQ",
		"d": "PXFFBUyxYcwl5QAp3ZRSXE4pA78upT7zoiUWJmWGUG6DVzwoB4qhbIM1CrrZ6fB-Vqsa9BxeIssVhRmZoUYRwXg166Zx17JYkxRLjorwt5rsjlrRHKhKEpKF8BNQH6FpVyoapRM8YpGGdZw2y6MiNn0Fw38O9IrqK2NahwO0f90mI26r_UkB9tigXQ_YKEk0eUEpA5GcH_8r8SmX87nFW_SToklycR9Q53SLCWlcS2qA5kB_6fABhaFBYWwdAWsg2vAVu9R4vVztCPr8rbC_yVFC2GIMA7mnXnR60WKqm2zt-UQm3ppd3iuhnMOsZS4pmmsq4Er2m8TpER5hNskVkn1ddCE2qEuSKm4X15bPLWoLLeFQJopdgRFODc5GMfIHRR1gK5Yw0yvrDFg7OCxoP5XBxnKyW0ZMeTslZv9Ilg-vdAPeGIzEZI43r3TRhL9R2T5Kgo3kQ5E86Nhi3rs8BygUMggw5PbT7jrusqvSZAgNySZPm37bMXxizf3dA3lKNY69csQHivakFcq9xrcVcDzs3WRHU9oZBnr_u2FgDwVO3gHvm-UPPvmXGXe8KjuSi3cUiglkKtGk7Lbhq_6bSd1iB2SL85L5NigMnWsFGjDX9P_4Dv-jagBo8hk3IzYwXNQKTsYPKzjCyzT-ia_RuxCv80w5OdpWl2vZjVQCL3E",
		"e": "AQAB",
		"use": "sig",
		"kid": "4kNtEpAtteCp6t6rUIe8sJ4RegM=",
		"qi": "w1AN84ke2LdDGRdm3jIpdyg568QEBThKueG9koxBWolLm_VfZvfuu9uhXwW-kZffPNF4JQhhuQEvvmY-4cb0xdk5ojgcqHxWheA2d5aOdZYxdjvTq_f5holUO9xHjep4NjM5qrK0ZvlHQqjimex-bqQw-TPY51Qq4fyfFVZzmJ00HG8wW2372qOz08AgiKvTdUyIdR3afuqiK83qPoOqhd1CkhT4rKwaUg3bejigCKubjR2f8T4Pm6Hb5M2XbMLh2zWu_NrzS2yREpoosGc-otAj3TbwhSxeKdd63M8WnBkNP6xcFk_rF0tzX60AJyv-1V7K2a6XtWaPw24XtnuNQw",
		"dp": "v2uUC0RGuafcK5E605dQFCvcvC1Gj5XSD83fxPWY5D-W_4P4UJSTznpEj4K_d8Mloae8yKUSGiDOh0NJDziE-rd68ApCfWxAcmcQ42rse0u-yM6WgAuq8s_dTEaMlXR_lN1pXh7BCJCRLfwsuayMXzr29-QOExpDeKRRb4mNsDMZcidqTY9XV8jNXhtaBhLvXmWYMMFLDoRtDJn54kKkH_CDFhERKzgMspsoJcN7ql4wsEgGhuj5M0LSiyISBaAO96sbEohGueqRkzzkoeneeCBD0Z-omSblYhR6kZKMbON2F5UNzyz5XDhyfybs-Fd9IQo5wypSR3XBc2VsZ5O_mQ",
		"alg": "PS256",
		"dq": "NK_z1-Xs_s7zqmLwK2LAWBKJHx0glMioDLqbl4DSD9uH0qHlK5xk6e2eRCP7zduFo7BXXS7D0Bh5fh3ISnLnF2HurLgRMmYIj6MQakxfM5ge3KdHBTDHFdAgtzWX6m0dosar5w3jcYWhaPnb2Jj-HuYEt5ZYZk2MOVcZJ8HWWtpASfP8qZRiLGv42dr6biqx4dU4GI4Qy4xKNBnCq9jPu-FxRqCRAB9Mc-8phGJzTMbVEinzdClS6YhP5h82t9m1gWwo7GOAtWE1Zm3t9O9Fvg4qjIbIIik7V3gPVJj0Z0bQw4fYSnWxumm34iemjaKM65kSeACzQv2KLBm6oINJiQ",
		"n": "tQ0L5YvM1Lo7kT-yQbPqmR2brOXpJUEN_2MA1ZS1m80TcB2kWgp8Ry_R72ak_1NZXhz0m3kUVDkj_qeZFc76Y6HuV3WSVOzK35vMgz7w8HfwXFnpgLxLID9ELqduRIzCQQbSyipCb19UEpXYbQwqJXIUyySM4ZOsanbsVUs2y6K-aN4wCxt9SaNVTI6mO52qOxEG22Sbl2Lz_6Y7kcBcVQ9oU9pwWMmXW4MG8K80vMz6hK77KMHH3yibveb1ZMYkGNO0ZkhcMgURsLHIpLSXFamypZjZePUojUxipDj_sLY_K67Uw7wkDm2ZK_j4FEmbD8Q1IA3kSqxRhB68e44BottZsi1hcdS3Lv-x8AH5q7aOSBfVbGAOscSfcymS_dtpbQvwTzmHgq6nMylbu8NGvrtJDw_9UvADN-5hGfMnHGsBKw8Tt-7vZFYvUNJ_VRbE_XRnPQHA5k4JBRAfH80hx0EZYo4mmtoKPpx1BWAj1WwmRcuJa03TOakp5IBCzYosdtpvNuauuuamir2Vwi9IDlNcRIZpy0HxWNVGxUpk9MKLTmbHMxrgHUPchvTKinxkQ8cq-7s9QGzXQMuN8gP5AczQVxKSV33DqOa5k1F9HgOHvwHSXyCmCLsA_ZflOA58fXpfXr1MWsle6jAAz9MA-Tto6UP5cgqAWl6Ee9moRNE"
	}`

	jwk := jose.JSONWebKey{}
	err := jwk.UnmarshalJSON([]byte(keyJson))
	if err != nil {
		return nil, err
	}

	key := jose.SigningKey{
		Algorithm: jose.PS256,
		Key:       jwk,
	}

	signer, err := jose.NewSigner(key, nil)
	if err != nil {
		return nil, err
	}

	return signer, nil
}

func generateRandomString(length int) (string, error) {
	// base64 uses 6 bit for each character, 1 byte is 8 bits
	// therefore when creating a array of bytes we only need ceil((3/4) * n) bytes to generate a n character string
	byteLength := int(math.Ceil(float64(.75) * float64(length)))

	b := make([]byte, byteLength)

	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	randomString := base64.RawURLEncoding.EncodeToString(b)

	return randomString[:length], nil
}
