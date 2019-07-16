package signer

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io"
	"math/rand"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const nonceLength = 8

type impure interface {
	getNonce() (string, error)
	getTimestamp() string
}

type signer struct {
	consumerKey string
	signingKey  string
	impure
}

func NewSigner(consumerKey, signingKey string) *signer {
	return &signer{
		consumerKey: consumerKey,
		signingKey:  signingKey,
	}
}

// GetAuthorizationHeader is a main function which returns OAuth1.0a header
func (s *signer) GetAuthorizationHeader(uri, method, payload string) (string, error) {
	var err error
	var queryParams map[string][]string
	var oauthParams map[string]string
	var baseURI string
	var signature string

	queryParams, err = s.extractQueryParams(uri)

	if err != nil {
		return "", err
	}

	oauthParams, err = s.getOAuthParams(payload)

	if err != nil {
		return "", err
	}

	paramString := s.toOAuthParamString(queryParams, oauthParams)

	baseURI, err = s.getBaseURIString(uri)

	if err != nil {
		return "", err
	}

	sbs := s.getSignatureBaseString(method, baseURI, paramString)

	signature, err = s.signSignatureBaseString(sbs)

	if err != nil {
		return "", err
	}

	encodedSignature := url.QueryEscape(signature)

	oauthParams["oauth_signature"] = encodedSignature

	authorizationString := s.getAuthorizationString(oauthParams)

	return authorizationString, nil
}

func (s *signer) extractQueryParams(uri string) (map[string][]string, error) {
	queryMap := map[string][]string{}

	parsedURL, err := url.Parse(uri)

	if err != nil {
		return queryMap, err
	}

	for _, param := range strings.Split(parsedURL.RawQuery, "&") {
		keyValuePair := strings.SplitN(param, "=", 2)

		key := keyValuePair[0]
		value := keyValuePair[1]

		if _, ok := queryMap[key]; ok {
			if !contains(queryMap[key], value) {
				queryMap[key] = append(queryMap[key], value)
				sort.Strings(queryMap[key])
			}
		} else {
			queryMap[key] = []string{value}
		}
	}

	return queryMap, nil
}

func (s *signer) getOAuthParams(payload string) (map[string]string, error) {
	var err error
	OAuthParams := map[string]string{}

	OAuthParams["oauth_body_hash"] = s.getBodyHash(payload)
	OAuthParams["oauth_consumer_key"] = s.consumerKey

	OAuthParams["oauth_nonce"], err = s.getNonce()

	if err != nil {
		return map[string]string{}, err
	}

	OAuthParams["oauth_signature_method"] = "RSA-SHA256"
	OAuthParams["oauth_timestamp"] = s.getTimestamp()
	OAuthParams["oauth_version"] = "1.0"

	return OAuthParams, nil
}

func (s *signer) getTimestamp() string {
	nowUnix := time.Now().Unix()

	timestamp := strconv.Itoa(int(nowUnix))

	return timestamp
}

// getNonce returns securely generated random string.
func (s *signer) getNonce() (string, error) {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	buf, err := generateRandomBytes(nonceLength)

	if err != nil {
		return "", err
	}

	for i, b := range buf {
		buf[i] = letters[b%byte(len(letters))]
	}

	return string(buf), nil
}

func (s *signer) getBodyHash(payload string) string {
	hash := sha256.Sum256([]byte(payload))

	return base64.StdEncoding.EncodeToString(hash[:])
}

func (s *signer) toOAuthParamString(queryParams map[string][]string, oauthParams map[string]string) string {
	var paramsBuilder strings.Builder
	params := ""
	consolidatedParams := queryParams

	for k, v := range oauthParams {
		if _, ok := consolidatedParams[k]; ok {
			consolidatedParams[k] = append(consolidatedParams[k], v)
		} else {
			consolidatedParams[k] = []string{v}
		}
	}

	keys := getSortedKeys(consolidatedParams)

	for _, k := range keys {
		sort.Strings(consolidatedParams[k])

		for _, vV := range consolidatedParams[k] {
			str := k + "=" + vV + "&"
			paramsBuilder.WriteString(str)
		}
	}

	params = strings.TrimSuffix(paramsBuilder.String(), "&")

	return params
}

func (s *signer) getBaseURIString(uri string) (string, error) {
	URL, err := url.Parse(uri)

	if err != nil {
		return "", err
	}

	base := URL.Scheme + "://" + strings.ToLower(URL.Host) + URL.Path
	return base, nil
}

func (s *signer) getSignatureBaseString(method, baseURI, params string) string {
	sbs := url.QueryEscape(method) + "&" + url.QueryEscape(baseURI) + "&" + url.QueryEscape(params)

	return sbs
}

func (s *signer) signSignatureBaseString(signatureBaseString string) (string, error) {
	var Reader io.Reader
	var err error
	var privateKey *rsa.PrivateKey
	var signature []byte

	block, _ := pem.Decode([]byte(s.signingKey))

	privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)

	if err != nil {
		return "", err
	}

	hashed := sha256.Sum256([]byte(signatureBaseString))

	signature, err = rsa.SignPKCS1v15(Reader, privateKey, crypto.SHA256, hashed[:])

	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(signature), nil
}

func (s *signer) getAuthorizationString(oauthParams map[string]string) string {
	var authorizationBuilder strings.Builder

	authorizationBuilder.WriteString("OAuth ")

	keys := getSortedKeys(oauthParams)

	for _, k := range keys {
		authorizationBuilder.WriteString(k + `="` + oauthParams[k] + `",`)
	}

	authorizationString := strings.TrimSuffix(authorizationBuilder.String(), ",")

	return authorizationString
}

func getSortedKeys(m interface{}) []string {
	var keys []string
	var i int

	switch t := m.(type) {
	case map[string]string:
		keys = make([]string, len(t))

		for k := range t {
			keys[i] = k
			i++
		}
	case map[string][]string:
		keys = make([]string, len(t))

		for k := range t {
			keys[i] = k
			i++
		}
	}

	sort.Strings(keys)
	return keys
}

// generateRandomBytes returns array filled with securely generated random bytes of given length
func generateRandomBytes(n int) ([]byte, error) {
	buf := make([]byte, n)

	_, err := rand.Read(buf)

	if err != nil {
		return nil, err
	}

	return buf, nil
}

func contains(slice []string, el string) bool {
	for _, v := range slice {
		if v == el {
			return true
		}
	}

	return false
}
