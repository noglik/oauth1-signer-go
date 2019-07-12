package signer

import (
	"crypto/rand"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const nonceLength = 8

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

func getOAuthParams(consumerKey, payload string) (map[string]string, error) {
	OAuthParams := map[string]string{}

	return OAuthParams, nil
}

func getTimestamp() string {
	nowUnix := time.Now().Unix()

	timestamp := strconv.Itoa(int(nowUnix))

	return timestamp
}

// getNonce returns securely generated random string.
func getNonce() (string, error) {
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
