// Package api provides HTTP transport for the FourCore ATTACK SDK.
package api

import (
	"cmp"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// Do sends an API request without buffering either body. URI is an API path,
// not an external URL. The caller must close the returned response body.
// HTTP error statuses are returned as responses; DecodeResponse decodes them.
func (g *HTTPAPI) Do(ctx context.Context, method, uri string, body io.Reader, options ...ReqOptions) (*http.Response, error) {
	var opts ReqOptions
	if len(options) > 0 {
		opts = options[0]
	}
	return g.doBase(ctx, g.baseURL, method, uri, body, opts)
}

func (g *HTTPAPI) doBase(ctx context.Context, base *url.URL, method, uri string, body io.Reader, opts ReqOptions) (*http.Response, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	g.rateMu.RLock()
	limiter := g.rateLimiter
	g.rateMu.RUnlock()
	if err := limiter.WaitMaxDuration(ctx, 5*time.Second); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("%w: %v", ErrRateLimited, err)
	}

	req, err := http.NewRequestWithContext(ctx, method, g.ResolveBase(base, uri), body)
	if err != nil {
		return nil, fmt.Errorf("create API request: %w", err)
	}
	for key, values := range opts.Headers {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
	req.Header.Set("Authorization", "Bearer "+g.APIKey)
	if opts.ContentLength != 0 {
		req.ContentLength = opts.ContentLength
	}
	query := req.URL.Query()
	for key, values := range opts.Params {
		for _, value := range values {
			query.Add(key, value)
		}
	}
	req.URL.RawQuery = query.Encode()

	client := g.client
	if opts.NoRedirect {
		copyClient := *client
		copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		client = &copyClient
	}
	response, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("send API request: %w", err)
	}
	if response.StatusCode == http.StatusTooManyRequests {
		info := parseRateLimitHeaders(response.Header)
		if info.Limit > 0 && info.Limit != limiter.limit {
			g.setRateLimit(info.Limit)
		}
	}
	return response, nil
}

// GetStream fetches an HTTP(S) download URL without API credentials or cookies.
// It uses the configured transport and timeout, but an isolated redirect policy.
// The caller must close the returned response body, including on HTTP errors.
func (g *HTTPAPI) GetStream(ctx context.Context, rawURL string) (*http.Response, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse download URL: %w", err)
	}
	if err := validateDownloadURL(u); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("create download request: %w", err)
	}
	client := *g.client
	client.Jar = nil
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errors.New("too many download redirects")
		}
		if err := validateDownloadURL(req.URL); err != nil {
			return err
		}
		req.Header.Del("Authorization")
		req.Header.Del("Cookie")
		req.Header.Del("Proxy-Authorization")
		return nil
	}
	response, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download file: %w", err)
	}
	return response, nil
}

func validateDownloadURL(u *url.URL) error {
	if (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil {
		return errors.New("download URL must be an absolute HTTP(S) URL without user credentials")
	}
	return nil
}

// DecodeResponse decodes a successful JSON response or returns an *APIError.
// It always closes the response body. A nil destination discards success bodies.
func DecodeResponse(response *http.Response, dest any) error {
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return fmt.Errorf("read API response: %w", err)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return responseError(response.StatusCode, body, response.Header)
	}
	if dest == nil || response.StatusCode == http.StatusNoContent {
		return nil
	}
	if err := json.Unmarshal(body, dest); err != nil {
		return fmt.Errorf("decode API response: %w", err)
	}
	return nil
}

func responseError(status int, body []byte, headers ...http.Header) *APIError {
	var result APIError
	// Empty, null, and non-JSON error bodies still retain their HTTP status.
	if len(body) > 0 {
		if err := json.Unmarshal(body, &result); err != nil {
			result = APIError{}
		}
	}
	result.Status = status
	result.Code = status
	result.Title = cmp.Or(result.Title, result.Message, http.StatusText(status))
	if len(headers) > 0 {
		value := cmp.Or(headers[0].Get("Retry-After"), headers[0].Get("x-ratelimit-retry-after"))
		if seconds, err := strconv.ParseInt(value, 10, 64); err == nil {
			result.RetryAfter = max(seconds, 0)
		} else if delay, err := time.ParseDuration(value); err == nil && delay > 0 {
			result.RetryAfter = int64(delay / time.Second)
			if delay%time.Second != 0 {
				result.RetryAfter++
			}
		}
	}
	return &result
}

// Error describes a structured API refusal, including its HTTP status.
func (a *APIError) Error() string {
	message := cmp.Or(a.Title, a.Message, http.StatusText(a.Status))
	if a.RetryAfter > 0 {
		message += fmt.Sprintf(": retry after %d seconds", a.RetryAfter)
	}
	if a.Detail != "" {
		return fmt.Sprintf("%s (%d): %s", message, a.Status, a.Detail)
	}
	return fmt.Sprintf("%s (%d)", message, a.Status)
}

// Is preserves the SDK's sentinel error checks for authentication, missing
// resources, and rate limiting while also exposing structured API errors.
func (a *APIError) Is(target error) bool {
	switch a.Status {
	case http.StatusUnauthorized, http.StatusForbidden:
		return target == ErrApiKeyInvalid
	case http.StatusNotFound:
		return target == ErrNotFound
	case http.StatusTooManyRequests:
		return target == ErrRateLimited
	default:
		return false
	}
}
