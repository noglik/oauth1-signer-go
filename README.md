# Oauth1-signer-go

This package is partially tested with sanbox service. DO NOT USE IN PRODUCTION.

## Overview

Zero dependency library for generating a Mastercard API compliant OAuth signature.

## Compatibility

Go 1.12.9

## Usage

### Prerequisites

Before using this library, you will need to set up a project in [Mastercard Developer Portal]().
As part of this setup, you'll receive credentials for your app.
- A consumer key (displayed on Mastercard Developer Portal)
- A private request signging key (matching the public certificate displayed on the Mastercard Developer Portal)

### Adding the library to your project

```bash
go get -u github.com/noglik/oauth1-signer-go
```

### Loading the Signing Key

```go
// to be done
```

### Creating the OAuth authorization header

Add `signer "github.com/noglik/oauth1-signer-go"` to `import`.

```go
consumerKey := "<your consumer key>"
uri := "https://sandbox.api.mastercard.com/service"
method := http.MethodPost
payload := "Hello world!"

authHeader := signer.GetAuthorizationHeader(uri, method, payload, consumerKey, signingKey)
```
