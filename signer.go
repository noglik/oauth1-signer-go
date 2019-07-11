package signer

import (
	"net/url"
	"sort"
	"strings"
)

// GetAuthorizationHeader is a main function which returns OAuth1.0a header
func GetAuthorizationHeader(uri, method, payload, consumerKey, signingKey string) (string, error) {
	return "", nil
}

func extractQueryParams(uri string) (map[string][]string, error) {
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

func contains(slice []string, el string) bool {
	for _, v := range slice {
		if v == el {
			return true
		}
	}

	return false
}
