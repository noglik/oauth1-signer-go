package signer

import (
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

const (
	consumerKey = "aaa!aaa"
	signingKey  = "-----BEGIN RSA PRIVATE KEY-----\nMIICWwIBAAKBgQDRhGF7X4A0ZVlEg594WmODVVUIiiPQs04aLmvfg8SborHss5gQ\nXu0aIdUT6nb5rTh5hD2yfpF2WIW6M8z0WxRhwicgXwi80H1aLPf6lEPPLvN29EhQ\nNjBpkFkAJUbS8uuhJEeKw0cE49g80eBBF4BCqSL6PFQbP9/rByxdxEoAIQIDAQAB\nAoGAA9/q3Zk6ib2GFRpKDLO/O2KMnAfR+b4XJ6zMGeoZ7Lbpi3MW0Nawk9ckVaX0\nZVGqxbSIX5Cvp/yjHHpww+QbUFrw/gCjLiiYjM9E8C3uAF5AKJ0r4GBPl4u8K4bp\nbXeSxSB60/wPQFiQAJVcA5xhZVzqNuF3EjuKdHsw+dk+dPECQQDubX/lVGFgD/xY\nuchz56Yc7VHX+58BUkNSewSzwJRbcueqknXRWwj97SXqpnYfKqZq78dnEF10SWsr\n/NMKi+7XAkEA4PVqDv/OZAbWr4syXZNv/Mpl4r5suzYMMUD9U8B2JIRnrhmGZPzL\nx23N9J4hEJ+Xh8tSKVc80jOkrvGlSv+BxwJAaTOtjA3YTV+gU7Hdza53sCnSw/8F\nYLrgc6NOJtYhX9xqdevbyn1lkU0zPr8mPYg/F84m6MXixm2iuSz8HZoyzwJARi2p\naYZ5/5B2lwroqnKdZBJMGKFpUDn7Mb5hiSgocxnvMkv6NjT66Xsi3iYakJII9q8C\nMa1qZvT/cigmdbAh7wJAQNXyoizuGEltiSaBXx4H29EdXNYWDJ9SS5f070BRbAIl\ndqRh3rcNvpY6BKJqFapda1DjdcncZECMizT/GMrc1w==\n-----END RSA PRIVATE KEY-----\n"
)

func TestGetAuthorizationHeader(t *testing.T) {
	uri := "HTTPS://SANDBOX.api.mastercard.com/merchantid/v1/merchantid?MerchantId=GOOGLE%20LTD%20ADWORDS%20%28CC%40GOOGLE.COM%29&Type=ExactMatch&Format=JSON"
	method := "GET"

	testCases := []struct {
		name     string
		body     string
		contains []string
	}{
		{
			name: "Empty body",
			body: "",
			contains: []string{
				"OAuth ",
				`oauth_body_hash="47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="`,
				`oauth_consumer_key="` + consumerKey + `"`,
				`oauth_signature_method="RSA-SHA256"`,
				`oauth_version="1.0"`,
				`oauth_signature`,
				`oauth_nonce`,
				`oauth_timestamp`,
			},
		},
		{
			name: "Empty json object",
			body: "{}",
			contains: []string{
				"OAuth ",
				`oauth_body_hash="RBNvo1WzZ4oRRq0W9+hknpT7T8If536DEMBg9hyq/4o="`,
				`oauth_consumer_key="` + consumerKey + `"`,
				`oauth_signature_method="RSA-SHA256"`,
				`oauth_version="1.0"`,
				`oauth_signature`,
				`oauth_nonce`,
				`oauth_timestamp`,
			},
		},
	}

	for _, tC := range testCases {
		tC := tC
		t.Run(tC.name, func(t *testing.T) {
			t.Parallel()

			got, err := GetAuthorizationHeader(uri, method, tC.body, consumerKey, signingKey)

			if err != nil {
				t.Error(err)
			}

			for _, v := range tC.contains {
				if !strings.Contains(got, v) {
					t.Errorf("\ngot '%v'\nshould contain '%v'", got, v)
				}
			}
		})
	}
}

var result string

func BenchmarkGetAuthorizationHeader(b *testing.B) {
	uri := "HTTPS://SANDBOX.api.mastercard.com/merchantid/v1/merchantid?MerchantId=GOOGLE%20LTD%20ADWORDS%20%28CC%40GOOGLE.COM%29&Type=ExactMatch&Format=JSON"
	method := "GET"

	var r string

	for i := 0; i < b.N; i++ {
		r, _ = GetAuthorizationHeader(uri, method, "", consumerKey, signingKey)
	}

	result = r
}

func TestExtractQueryParams(t *testing.T) {
	testCases := []struct {
		name string
		uri  string
		want map[string][]string
	}{
		{
			name: "Simple uri",
			uri:  "https://example.com/?test=true",
			want: map[string][]string{"test": []string{"true"}},
		},
		{
			name: "Complex uri",
			uri:  "https://sandbox.api.mastercard.com/merchantid/v1/merchantid?MerchantId=GOOGLE%20LTD%20ADWORDS%20%28CC%40GOOGLE.COM%29&Format=XML&Type=ExactMatch&Format=JSON&EmptyVal=",
			want: map[string][]string{
				"EmptyVal":   []string{""},
				"Format":     []string{"JSON", "XML"},
				"MerchantId": []string{"GOOGLE%20LTD%20ADWORDS%20%28CC%40GOOGLE.COM%29"},
				"Type":       []string{"ExactMatch"},
			},
		},
		{
			name: "Support RFC",
			uri:  "https://example.com/request?b5=%3D%253D&a3=a&c%40=&a2=r%20b",
			want: map[string][]string{
				"b5":   []string{"%3D%253D"},
				"a3":   []string{"a"},
				"c%40": []string{""},
				"a2":   []string{"r%20b"},
			},
		},
		{
			name: "Non-encoded params",
			uri:  "https://example.com/request?colon=:&plus=+&comma=,",
			want: map[string][]string{
				"colon": []string{":"},
				"plus":  []string{"+"},
				"comma": []string{","},
			},
		},
		{
			name: "Encoded params",
			uri:  "https://example.com/request?colon=%3A&plus=%2B&comma=%2C",
			want: map[string][]string{
				"colon": []string{"%3A"},
				"plus":  []string{"%2B"},
				"comma": []string{"%2C"},
			},
		},
	}

	for _, tC := range testCases {
		tC := tC
		t.Run(tC.name, func(t *testing.T) {
			t.Parallel()
			got, err := extractQueryParams(tC.uri)

			if err != nil {
				t.Error(err)
			}

			if !reflect.DeepEqual(got, tC.want) {
				t.Errorf("\ngot '%v'\nwant '%v'", got, tC.want)
			}
		})
	}
}

func TestGetOAuthParams(t *testing.T) {
	keys := []string{
		"oauth_body_hash",
		"oauth_consumer_key",
		"oauth_nonce",
		"oauth_signature_method",
		"oauth_timestamp",
		"oauth_version",
	}

	testCases := []struct {
		name    string
		payload string
		keys    []string
		want    map[string]string
	}{
		{
			name:    "Without payload",
			payload: "",
			keys:    keys,
			want: map[string]string{
				"oauth_body_hash":        "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
				"oauth_consumer_key":     consumerKey,
				"oauth_signature_method": "RSA-SHA256",
				"oauth_version":          "1.0",
			},
		},
		{
			name:    "Without payload",
			payload: `{ my: "payload" }`,
			keys:    keys,
			want: map[string]string{
				"oauth_body_hash":        "Qm/nLCqwlog0uoCDvypgninzNQ25YHgTmUDl/zOgT1s=",
				"oauth_consumer_key":     consumerKey,
				"oauth_signature_method": "RSA-SHA256",
				"oauth_version":          "1.0",
			},
		},
	}

	for _, tC := range testCases {
		tC := tC

		t.Run(tC.name, func(t *testing.T) {
			t.Parallel()

			got, err := getOAuthParams(consumerKey, tC.payload)

			if err != nil {
				t.Error(err)
			}

			for _, k := range tC.keys {
				if _, ok := got[k]; !ok {
					t.Errorf("\ngot '%v'\nwant with key '%v'", got, k)
				} else if _, ok := tC.want[k]; ok {
					assertResponseEquality(t, got[k], tC.want[k])
				}
			}
		})
	}
}

func TestGetTimestamp(t *testing.T) {
	got := getTimestamp()

	gotNumber, err := strconv.Atoi(got)

	if err != nil {
		t.Error(err)
	}

	if gotNumber <= 0 {
		t.Errorf("got '%v', want >0", gotNumber)
	}
}

func TestGetNonce(t *testing.T) {
	regexpString := "^[a-zA-Z0-9]+$"
	r, err := regexp.Compile(regexpString)

	if err != nil {
		t.Error(err)
	}

	got, err := getNonce()

	if err != nil {
		t.Error(err)
	}

	length := len(got)

	if length != nonceLength {
		t.Errorf("got '%v' with length %v, but want length =%v", got, length, nonceLength)
	}

	if !r.MatchString(got) {
		t.Errorf("got '%v', which didn't match regexp '%v'", got, regexpString)
	}
}

func TestGetBodyHash(t *testing.T) {
	testCases := []struct {
		name    string
		payload string
		want    string
	}{
		{
			name:    "Empty string",
			payload: "",
			want:    "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
		},
		{
			name:    "String",
			payload: `{ my: "payload" }`,
			want:    "Qm/nLCqwlog0uoCDvypgninzNQ25YHgTmUDl/zOgT1s=",
		},
	}

	for _, tC := range testCases {
		tC := tC

		t.Run(tC.name, func(t *testing.T) {
			t.Parallel()

			got := getBodyHash(tC.payload)

			assertResponseEquality(t, got, tC.want)
		})
	}
}

func TestToOAuthParamString(t *testing.T) {
	testCases := []struct {
		name        string
		queryParams map[string][]string
		oauthParams map[string]string
		want        string
	}{
		{
			name: "RFC example",
			queryParams: map[string][]string{
				"b5":   []string{"%3D%253D"},
				"a3":   []string{"a", "2%20q"},
				"c%40": []string{""},
				"a2":   []string{"r%20b"},
				"c2":   []string{""},
			},
			oauthParams: map[string]string{
				"oauth_consumer_key":     "9djdj82h48djs9d2",
				"oauth_token":            "kkk9d7dh3k39sjv7",
				"oauth_signature_method": "HMAC-SHA1",
				"oauth_timestamp":        "137131201",
				"oauth_nonce":            "7d8f3e4a",
			},
			want: "a2=r%20b&a3=2%20q&a3=a&b5=%3D%253D&c%40=&c2=&oauth_consumer_key=9djdj82h48djs9d2&oauth_nonce=7d8f3e4a&oauth_signature_method=HMAC-SHA1&oauth_timestamp=137131201&oauth_token=kkk9d7dh3k39sjv7",
		},
		{
			name: "Ascended",
			queryParams: map[string][]string{
				"b": []string{"b"},
				"A": []string{"a", "A"},
				"B": []string{"B"},
				"a": []string{"A", "a"},
				"0": []string{"0"},
			},
			oauthParams: map[string]string{},
			want:        "0=0&A=A&A=a&B=B&a=A&a=a&b=b",
		},
	}

	for _, tC := range testCases {
		tC := tC

		t.Run(tC.name, func(t *testing.T) {
			t.Parallel()

			got := toOAuthParamString(tC.queryParams, tC.oauthParams)

			assertResponseEquality(t, got, tC.want)
		})
	}
}

func BenchmarkToOAuthParamString(b *testing.B) {
	oauthParams := map[string]string{
		"oauth_consumer_key":     "9djdj82h48djs9d2",
		"oauth_token":            "kkk9d7dh3k39sjv7",
		"oauth_signature_method": "HMAC-SHA1",
		"oauth_timestamp":        "137131201",
		"oauth_nonce":            "7d8f3e4a",
	}
	queryParams := map[string][]string{
		"b5":   []string{"%3D%253D"},
		"a3":   []string{"a", "2%20q"},
		"c%40": []string{""},
		"a2":   []string{"r%20b"},
		"c2":   []string{""},
	}

	for i := 0; i < b.N; i++ {
		toOAuthParamString(queryParams, oauthParams)
	}
}

func TestGetBaseURIString(t *testing.T) {
	testCases := []struct {
		name string
		uri  string
		want string
	}{
		{
			name: "Simple uri",
			uri:  "http://example.com/test/?test=1",
			want: "http://example.com/test/",
		},
		{
			name: "Complicated uri",
			uri:  "HTTPS://SANDBOX.api.mastercard.com/merchantid/v1/merchantid?MerchantId=GOOGLE%20LTD%20ADWORDS%20%28CC%40GOOGLE.COM%29&Format=XML&Type=ExactMatch&Format=JSON",
			want: "https://sandbox.api.mastercard.com/merchantid/v1/merchantid",
		},
		{
			name: "With base auth",
			uri:  "https://dev:secrete@192.168.100.2:8080/user?test=1",
			want: "https://192.168.100.2:8080/user",
		},
	}

	for _, tC := range testCases {
		tC := tC

		t.Run(tC.name, func(t *testing.T) {
			t.Parallel()

			got, err := getBaseURIString(tC.uri)

			if err != nil {
				t.Error(err)
			}

			assertResponseEquality(t, got, tC.want)
		})
	}
}

func TestGetSignatureBaseString(t *testing.T) {
	testCases := []struct {
		name    string
		method  string
		baseURI string
		params  string
		want    string
	}{
		{
			name:    "Simple",
			method:  "GET",
			baseURI: "https://sandbox.api.mastercard.com/merchantid/v1/merchantid",
			params:  "Format=JSON&Format=XML&MerchantId=GOOGLE%20LTD%20ADWORDS%20CC%40GOOGLE.COM&Type=ExactMatch&oauth_consumer_key=aaa!aaa&oauth_nonce=uTeLPs6K&oauth_signature_method=RSA-SHA256&oauth_timestamp=1524771555&oauth_version=1.0",
			want:    "GET&https%3A%2F%2Fsandbox.api.mastercard.com%2Fmerchantid%2Fv1%2Fmerchantid&Format%3DJSON%26Format%3DXML%26MerchantId%3DGOOGLE%2520LTD%2520ADWORDS%2520CC%2540GOOGLE.COM%26Type%3DExactMatch%26oauth_consumer_key%3Daaa%21aaa%26oauth_nonce%3DuTeLPs6K%26oauth_signature_method%3DRSA-SHA256%26oauth_timestamp%3D1524771555%26oauth_version%3D1.0",
		},
	}

	for _, tC := range testCases {
		tC := tC

		t.Run(tC.name, func(t *testing.T) {
			t.Parallel()

			got := getSignatureBaseString(tC.method, tC.baseURI, tC.params)

			assertResponseEquality(t, got, tC.want)
		})
	}
}

func TestSignSignatureBaseString(t *testing.T) {
	testCases := []struct {
		name                string
		signatureBaseString string
		want                string
	}{
		{
			name:                "Simple",
			signatureBaseString: "GET&https%3A%2F%2Fsandbox.api.mastercard.com%2Fmerchantid%2Fv1%2Fmerchantid&Format%3DJSON%26Format%3DXML%26MerchantId%3DGOOGLE%2520LTD%2520ADWORDS%2520CC%2540GOOGLE.COM%26Type%3DExactMatch%26oauth_consumer_key%3Daaa%21aaa%26oauth_nonce%3DuTeLPs6K%26oauth_signature_method%3DRSA-SHA256%26oauth_timestamp%3D1524771555%26oauth_version%3D1.0",
			want:                "Q/AnafnIfOC67BsVkQl9dQlRJeOzfSFUi6YugxLhAXasNyyAmZiXPkU5r8zZnuCg2NE8sqG9Jj0zMTY/vFbxhSQOaZs0ogpcJUE0CvWuMVzmgY/Dxv5XfjdZMfXVItkFkoaAs2GRryNd4fb26UekyX3JTHZpY+HJdUFjwrDM3q0=",
		},
	}

	for _, tC := range testCases {
		tC := tC

		t.Run(tC.name, func(t *testing.T) {
			t.Parallel()

			got, err := signSignatureBaseString(tC.signatureBaseString, signingKey)

			if err != nil {
				t.Error(err)
			}

			assertResponseEquality(t, got, tC.want)
		})
	}
}

func TestGetAuthorizationString(t *testing.T) {
	testCases := []struct {
		name        string
		oauthParams map[string]string
		want        string
	}{
		{
			name: "Simple",
			oauthParams: map[string]string{
				"oauth_body_hash":        "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
				"oauth_consumer_key":     "aaa!aaa",
				"oauth_nonce":            "oauth_nonce",
				"oauth_signature":        "Q%2FAnafnIfOC67BsVkQl9dQlRJeOzfSFUi6YugxLhAXasNyyAmZiXPkU5r8zZnuCg2NE8sqG9Jj0zMTY%2FvFbxhSQOaZs0ogpcJUE0CvWuMVzmgY%2FDxv5XfjdZMfXVItkFkoaAs2GRryNd4fb26UekyX3JTHZpY%2BHJdUFjwrDM3q0%3D",
				"oauth_signature_method": "RSA-SHA256",
				"oauth_timestamp":        "oauth_timestamp",
				"oauth_version":          "1.0",
			},
			want: `OAuth oauth_body_hash="47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",oauth_consumer_key="aaa!aaa",oauth_nonce="oauth_nonce",oauth_signature="Q%2FAnafnIfOC67BsVkQl9dQlRJeOzfSFUi6YugxLhAXasNyyAmZiXPkU5r8zZnuCg2NE8sqG9Jj0zMTY%2FvFbxhSQOaZs0ogpcJUE0CvWuMVzmgY%2FDxv5XfjdZMfXVItkFkoaAs2GRryNd4fb26UekyX3JTHZpY%2BHJdUFjwrDM3q0%3D",oauth_signature_method="RSA-SHA256",oauth_timestamp="oauth_timestamp",oauth_version="1.0"`,
		},
	}

	for _, tC := range testCases {
		tC := tC

		t.Run(tC.name, func(t *testing.T) {
			t.Parallel()

			got := getAuthorizationString(tC.oauthParams)

			assertResponseEquality(t, got, tC.want)
		})
	}
}

func TestContains(t *testing.T) {
	array := []string{"Brad", "John", "Anna"}

	testCases := []struct {
		name    string
		array   []string
		element string
		want    bool
	}{
		{
			name:    "Exist",
			array:   array,
			element: "John",
			want:    true,
		},
		{
			name:    "Doesn't exist",
			array:   array,
			element: "Joshua",
			want:    false,
		},
	}

	for _, tC := range testCases {
		tC := tC

		t.Run(tC.name, func(t *testing.T) {
			t.Parallel()

			got := contains(tC.array, tC.element)

			assertResponseEquality(t, got, tC.want)
		})
	}
}

func BenchmarkContains(b *testing.B) {
	s := []string{"Brad", "John", "Anna"}
	for i := 0; i < b.N; i++ {
		contains(s, "John")
	}
}

func TestGenerateRandomBytes(t *testing.T) {
	testCases := []struct {
		name   string
		length int
	}{
		{
			name:   "Length 6",
			length: 6,
		},
		{
			name:   "Length 8",
			length: 8,
		},
	}

	for _, tC := range testCases {
		tC := tC

		t.Run(tC.name, func(t *testing.T) {
			t.Parallel()

			got, err := generateRandomBytes(tC.length)

			if err != nil {
				t.Error(err)
			}

			if len(got) != tC.length {
				t.Errorf("got length %v, want %v", len(got), tC.length)
			}
		})
	}
}

func TestGetSortedKeys(t *testing.T) {
	testCases := []struct {
		name string
		m    interface{}
		want []string
	}{
		{
			name: "Map of strings",
			m: map[string]string{
				"oauth_nonce":     "",
				"oauth_body_hash": "",
				"oauth_timestamp": "",
				"oauth_signature": "",
			},
			want: []string{
				"oauth_body_hash",
				"oauth_nonce",
				"oauth_signature",
				"oauth_timestamp",
			},
		},
		{
			name: "Map of arrays",
			m: map[string][]string{
				"oauth_nonce":     []string{},
				"oauth_body_hash": []string{},
				"oauth_timestamp": []string{},
				"oauth_signature": []string{},
			},
			want: []string{
				"oauth_body_hash",
				"oauth_nonce",
				"oauth_signature",
				"oauth_timestamp",
			},
		},
	}

	for _, tC := range testCases {
		tC := tC

		t.Run(tC.name, func(t *testing.T) {
			t.Parallel()

			got := getSortedKeys(tC.m)

			if !reflect.DeepEqual(got, tC.want) {
				t.Errorf("\ngot '%v'\nwant '%v'", got, tC.want)
			}
		})
	}
}

func assertResponseEquality(t *testing.T, got, want interface{}) {
	t.Helper()

	if got != want {
		t.Errorf("\ngot '%v'\nwant '%v'", got, want)
	}
}
