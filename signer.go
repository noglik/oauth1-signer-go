package signer

import (
	"net/url"
)

func GetAuthorizationHeader(uri, method, payload, consumerKey, signingKey string) (string, error) {
	return "", nil
}

func extractQueryParams(uri string) (map[string][]string, error) {
	parsedURL, err := url.Parse(uri)

	if err != nil {
		return map[string][]string{}, err
	}

	return parsedURL.Query(), nil
}
