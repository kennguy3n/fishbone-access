package wasabi

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

// signRequestSigV4 mutates the request in place, adding the necessary
// Authorization, X-Amz-Date, and X-Amz-Content-Sha256 headers per the
// AWS Signature Version 4 spec. Wasabi's IAM is API-compatible with AWS
// IAM and accepts SigV4 signatures with service="iam" and region="us-east-1".
func signRequestSigV4(req *http.Request, accessKeyID, secretAccessKey, region, service string, now time.Time) error {
	if region == "" {
		region = "us-east-1"
	}
	if service == "" {
		service = "iam"
	}

	amzDate := now.UTC().Format("20060102T150405Z")
	dateStamp := now.UTC().Format("20060102")

	bodyHash, err := hashBody(req)
	if err != nil {
		return err
	}

	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", bodyHash)

	canonicalQuery := canonicalQueryString(req.URL.RawQuery)
	canonicalHeaders, signedHeaders := canonicalHeaders(req)
	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalURI(req.URL.Path),
		canonicalQuery,
		canonicalHeaders,
		signedHeaders,
		bodyHash,
	}, "\n")

	credentialScope := dateStamp + "/" + region + "/" + service + "/aws4_request"
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		credentialScope,
		hashString(canonicalRequest),
	}, "\n")

	kDate := hmacSHA256([]byte("AWS4"+secretAccessKey), dateStamp)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, service)
	kSigning := hmacSHA256(kService, "aws4_request")
	signature := hex.EncodeToString(hmacSHA256(kSigning, stringToSign))

	authValue := "AWS4-HMAC-SHA256 Credential=" + accessKeyID + "/" + credentialScope +
		", SignedHeaders=" + signedHeaders +
		", Signature=" + signature
	req.Header.Set("Authorization", authValue)
	return nil
}

func hashBody(req *http.Request) (string, error) {
	if req.Body == nil {
		return hashString(""), nil
	}
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return "", err
	}
	req.Body = io.NopCloser(strings.NewReader(string(body)))
	if req.GetBody == nil {
		req.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader(string(body))), nil
		}
	}
	return hashString(string(body)), nil
}

func canonicalURI(path string) string {
	if path == "" {
		return "/"
	}
	return path
}

func canonicalQueryString(rawQuery string) string {
	if rawQuery == "" {
		return ""
	}
	pairs := strings.Split(rawQuery, "&")
	sort.Strings(pairs)
	return strings.Join(pairs, "&")
}

func canonicalHeaders(req *http.Request) (string, string) {
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	headers := map[string]string{"host": host}
	if v := req.Header.Get("X-Amz-Date"); v != "" {
		headers["x-amz-date"] = v
	}
	if v := req.Header.Get("X-Amz-Content-Sha256"); v != "" {
		headers["x-amz-content-sha256"] = v
	}
	if v := req.Header.Get("Content-Type"); v != "" {
		headers["content-type"] = v
	}
	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var canonical strings.Builder
	for _, k := range keys {
		canonical.WriteString(k)
		canonical.WriteString(":")
		canonical.WriteString(strings.TrimSpace(headers[k]))
		canonical.WriteString("\n")
	}
	return canonical.String(), strings.Join(keys, ";")
}

func hashString(s string) string {
	h := sha256.New()
	_, _ = h.Write([]byte(s))
	return hex.EncodeToString(h.Sum(nil))
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write([]byte(data))
	return h.Sum(nil)
}
