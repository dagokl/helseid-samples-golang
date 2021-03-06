package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log"
	"math"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/oauth2/clientcredentials"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

const ClientId = "golang-m2m-app"

const helseIdMetadataUrl = "https://helseid-sts.utvikling.nhn.no/.well-known/openid-configuration"

var Scopes = []string{"norsk-helsenett:golang-sample-api/foo"}

// add fields to this struct to fetch the corresponding value from the well-known endpoint
type authorizationServerMetadata struct {
	Issuer                 string
	Authorization_endpoint string
	Token_endpoint         string
	End_session_endpoint   string
}

var helseIdMetadata authorizationServerMetadata

// Fetches all the data required from wellKnownUrl.
// What values to fetch is defines in the wellKnown struct.
func refreshAuthorizationServerMetadata() {
	resp, err := http.Get(helseIdMetadataUrl)
	if err != nil {
		log.Fatalf("Failed to get the well-known from %v\n    Error: %s\n", helseIdMetadataUrl, err.Error())
	}

	err = json.NewDecoder(resp.Body).Decode(&helseIdMetadata)
	if err != nil {
		log.Fatalf("Failed to parse respone from well-known\n    Error: %s\n", err.Error())
	}
}

func NewClient(ctx context.Context) *http.Client {
	if helseIdMetadata == (authorizationServerMetadata{}) {
		refreshAuthorizationServerMetadata()
	}

	// create a new client assertion token to authenticate the client
	clientAssertion := generateClientAssertionToken()
	tokenRequestParams := url.Values{}
	tokenRequestParams.Set("client_assertion", clientAssertion)
	tokenRequestParams.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")

	config := clientcredentials.Config{
		ClientID:       ClientId,
		EndpointParams: tokenRequestParams,
		TokenURL:       helseIdMetadata.Token_endpoint,
		Scopes:         Scopes,
	}

	return config.Client(ctx)
}

func generateClientAssertionToken() string {
	// DO NOT store private keys in source code!
	keyJson := `{
		"p": "wNZWcc3ZWOA5mCOOaWK9AbG7nMNGj6RZ2K18JRkyXueLE2BsPbKRTmlM-G9T7TZmufmg7T_QAUpnaS8TUC5_IHip9e9X_Z7-VA_TJnc24AZSP99W-hdks8r8tT3lCGq9rSeziXt8bMUvrdVFoXfNyr0dWFn_Qqy4XQatln7_1Dhv3_FDg80IGGB0jb8SS3QUd1N7E2KHbaz3e5rL13FZC6NCuTxNRvB0TPd1jBnuAPfqL_2NW8OFCcuZWSlYzF_PMDxt_8ckH12Uf_VttNjmO4cVaaCijOG-EjeMBAKIYQtrAH0VBYsvlVwbefEAaVgCHbvdWCjL869kdGlxe8P0UQ",
		"kty": "RSA",
		"q": "uJolnAAU5bmkhxvDtLjY5vdE1cFKkvRPPokrESO-0CcF7JGW-1VsShh3PIv5WMT_wA2bTWRCLSMWphUInL5ygSEMNB8ZQU1jc5urX0jjaaONcsm3as3ExIVaORrKXRcSsUeHF6BWUl1dkPIqruOO27W0kXIUoqxpyApyIiBtyCvy7gj91OFpY3ffILrOpPeTRt9Oz5b6G3p1ZxWOEjo76vLU7MABlOi6a8tjOsb3QiNQNujHJ8Sm9Db8bHGyTHxfpk5Iw2V-El6xfAZ_pxGUonMQLp-eWRF1rSuR1vI9eSi0wNb4rxMSqHHYZ7RoYSHPcOjcf2mQC5MYNBHuCwiZ7Q",
		"d": "fSWlfYtfkKkw_K-28SyFUC2WAHAxCWPkQLwgefG-j226LNcb-zB8Lh_3uOt4i4zS-RMEF5y8UShzky3rEAa3baEYgVxcl9OEA35PP5rXU8QihCbVus8WNJmTVpojCluBtW2T5zmxf76yE99Eg9z0ltXOHOdqxFEA7weI_JFxGnK3uq7PPo6LW7VUSkEQTV8vpFEmjUe1HlAb5I_k_D8vHXgwuAXZYcWK128CmLiZnK2mHk4RfQN61xft10o7rEZVQRvCj7l3Q0XdUSvKGQyGGS2Vr-lWy-kbYv8pQUw66S9pskCiZFGlac4i7kZD2SmH53gHkkW-drly4EPZuIMowVrxP4VEs5XyWLNtyYgWxV7TgvurhPEtWssYTsBJYRN8ffoXKAQxS5xiTDWq2S4nL-nAP22eGF078K_23_laFbk0KAEx_6ZrP3zvnllr6tsSZj4TntguX7cfyUL4GwV8fDmBWxLdwiSq4yfWrMmFH_HpJteOzoooYFJTLun9QxEA4341a1875Ve_7OpOtMczL23NzK1kQDXuYASLkq6zRMVrMu7rMgETqd7L8N2lWjRsWQeGiosXztdlIlrS99-He_SmxOjR8zjQkcfAmQvUIZ0U2mFzPpWIQ8wX0FH94m2fEQRmvN1XYxyqk2NBMORlfU4UEVySUK2UWsfPtDybYoE",
		"e": "AQAB",
		"use": "sig",
		"kid": "XjDfM0IZgCCGtpAmKfNmyVQskjg=",
		"qi": "pcuG-K9MI5hERnnZehPoAXQ7JAy65YxvV7324tZ_qMsD7o9qzzR4FfAmTL3pSJzfzZEs_ZQeyW_LWX4W6M9ww0l97PWB8y439aMT-uXUuP0OfLXA8O7stLkDvChetTd-ujU9TCYJYVOOWzFmeDIyzdCR1mDuLNS0EJ3GZNQDZ36vwB6cbX_Avx5S3Vkfz6gDw_a5HSS2slxz_mZ5fFuUf6_X3yixepkq9adqHcIHuc4nxELMspLShQZelXNRSgMYi1UyZBRHPUfyvM5t4r43q6WWLbdVm1acipjUlm9UDmlhxsBhJyws6nEkgLVDpBEr0RS3y47pIhkFIjrYkDcibw",
		"dp": "cDNGEOlo8SFl4XOuxPrCZl33f3rPb3x9Gmm2tg83E6k9boTH9g4UJb93HYYJGxhwJP1t-R0L9fRIvxa48gpbxZTvrz0XwWXlLRwYC2WJ9Ec5TBizDsjVuxb8eqgMvxz8R-e1uuSyvMbuuwJAhXajsrbegC29LBo7G0Vrcwlp6Rz9WxuR4PpHH4ffySnHh0d_MP7NubW2fsYJKU4kFLLK0M6pYAYKIKB_ytig-GeN59pX1Jx-x0m3-r8P9qTsGd4VO0et6QkBp45XfSxcLMGXFEPA3bitW7NtWEQhn6Opnm16UMp2lMcrZIg3JHhpeOHQOWS5oTX7lUoT9Pf1I8IcQQ",
		"alg": "PS256",
		"dq": "O4M2bLx6ADWBHS2OQkz1YECHKIJQEGBCy95czAHCGkj6V_H3wr8fUiPhDNvzXvLjoH7Ceoi_7N1LB-_v_thHAeotjQAZnDveu_6LmQRejEf16fOt9fiwXsq-83n3k1tE43Iz0yIVsif3aisoJ4mlHJ_PvrQQgwEieSMk-GuL-ORyRNsROfgRicezX1HaHMTT7h0_wxzhNMqd3sXML4QmnO_8RPcBi4gb0XSYYPKT8_Z-fbU9v0xepoyzhCKDYLUYAP1r59JoenOctGdD8BBy4oxFw0IiQoSmc1WAhtNBjjXZT_H96jMz6KoLIiO_ItFLlxL7Qvg9P_4D54WAQH5dYQ",
		"n": "iw4rZkmU6oTNnf-4ecCA4Bx_zgbLbaqOHypA-YZ0y0isIV-1FDOqDk5pTLl1gVaigmQ2za6cOXyCXSZD5A5fazdvW14Cx1MiMEqqSYir8IdgGrUaZ6Zro2Tt4mNdjZm-HkHtJjFlVcYkl1xslzkB71OFMswCp7Vel8GsWqLbB157BxpjhT8bkhs9YPod8Pr2AacbCIaGdEGQyXEAlQwApSv1nnDn-qXoFJk0TK5aAZOgQKvgEZdUGawCq5TTGycqNh6N6I_9WND2WgXUh_eX7UQPTT6bj-F51TczfJlsDcKbGFeFT_UR592uF2zsxRunArvuXvi8zi57owH6p4FEv_FvJB8dUY23Q1ZI2PqmFRqn2K2KHdMrhN5RHGuL2JzdY23Yy739PAZ7MGkhdPK4G8RGNaYJD6t0tt-z_A0fSZSEqpTfE2-rPgII0zlGfQ0oDWCaGEfNk4lGCZBifEq-G7U4sPSsAQHpJWS9GBoyucNQ-j8ZnQcaNa3hQXWKLIZaE1adSLgWPWp40SS6_yWztQLgRdVm9UirE0eOSze54p98IVPpMoSLxdylXa8YNTE3z58EnfnrbzPobeSZ5olZcSZc_cAsscvyFktetRWgHFcpGRQfKcSM-e-vNnJWmLYFRwzOIm9oo_xBfet5n_05cR0bYzQht2mGCoI-9M71l_0"
	}`

	jwk := jose.JSONWebKey{}
	jwk.UnmarshalJSON([]byte(keyJson))
	key := jose.SigningKey{
		Algorithm: jose.PS256,
		Key:       jwk,
	}
	signer, _ := jose.NewSigner(key, nil)

	jti := generateRandomString(24)

	claims := jwt.Claims{
		Issuer:    ClientId,
		Subject:   ClientId,
		NotBefore: jwt.NewNumericDate(time.Now()),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		Expiry:    jwt.NewNumericDate(time.Now().Add(time.Minute)),
		ID:        jti,
		Audience:  jwt.Audience{helseIdMetadata.Token_endpoint},
	}

	raw, _ := jwt.Signed(signer).Claims(claims).CompactSerialize()

	return raw
}

func generateRandomString(length int) string {
	// base64 uses 6 bit for each character, 1 byte is 8 bits
	// therefore when creating a array of bytes we only need ceil((3/4) * n) bytes to generate a n character string
	byteLength := int(math.Ceil(float64(.75) * float64(length)))

	b := make([]byte, byteLength)
	rand.Read(b)
	randomString := base64.RawURLEncoding.EncodeToString(b)

	return randomString[:length]
}
