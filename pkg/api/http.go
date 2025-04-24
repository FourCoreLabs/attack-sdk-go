package api

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"encoding/json"
)

// RateLimiter implements a local rate limiting mechanism
type RateLimiter struct {
	mu            sync.Mutex
	requests      []time.Time
	limit         int           // Default rate limit per minute
	windowMinutes time.Duration // Window duration in minutes
}

// NewRateLimiter creates a new rate limiter with default values
func NewRateLimiter(limit int) *RateLimiter {
	return &RateLimiter{
		requests:      make([]time.Time, 0, limit),
		limit:         limit,
		windowMinutes: 1, // Default window of 1 minute
	}
}

// IsAllowed checks if a request is allowed based on rate limits
func (r *RateLimiter) IsAllowed() (bool, time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	windowStart := now.Add(-time.Minute * r.windowMinutes)

	// Cleanup old requests
	validRequests := make([]time.Time, 0, len(r.requests))
	for _, t := range r.requests {
		if t.After(windowStart) {
			validRequests = append(validRequests, t)
		}
	}
	r.requests = validRequests

	// Check if we're at the limit
	if len(r.requests) >= r.limit {
		// Calculate time until oldest request expires
		waitTime := r.requests[0].Add(time.Minute * r.windowMinutes).Sub(now)
		return false, waitTime
	}

	// Add current request
	r.requests = append(r.requests, now)
	return true, 0
}

// RemainingRequests returns the number of remaining requests in the current window
func (r *RateLimiter) RemainingRequests() int {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	windowStart := now.Add(-time.Minute * r.windowMinutes)

	// Count valid requests
	validCount := 0
	for _, t := range r.requests {
		if t.After(windowStart) {
			validCount++
		}
	}

	return r.limit - validCount
}

// HTTPAPI represents an HTTP API client
type HTTPAPI struct {
	BaseURL     string
	baseURL     *url.URL
	client      *http.Client
	APIKey      string
	rateLimiter *RateLimiter
}

// NewHTTPAPI creates a new API client with default rate limit of 100 reqs/min
func NewHTTPAPI(baseURL, apiKey string) (*HTTPAPI, error) {
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}

	return &HTTPAPI{
		BaseURL:     baseURL,
		baseURL:     parsedURL,
		client:      &http.Client{Timeout: 60 * time.Second},
		APIKey:      apiKey,
		rateLimiter: NewRateLimiter(100), // Default rate limit: 100 requests per minute
	}, nil
}

var (
	ErrApiKeyInvalid = errors.New("invalid api key")
	ErrNotFound      = errors.New("resource not found")
	ErrRateLimited   = errors.New("rate limit exceeded")
)

type ErrorItem struct {
	Name   string         `json:"name" description:"For example, name of the parameter that caused the error"`
	Reason string         `json:"reason" description:"Human readable error message"`
	More   map[string]any `json:"more,omitempty" description:"Additional information about the error"`
}

type APIError struct {
	Code   int         `json:"code"`
	Detail string      `json:"detail"`
	Title  string      `json:"title"`
	Status int         `json:"status,omitempty"`
	Errors []ErrorItem `json:"errors,omitempty" xml:"errors,omitempty"`
}

func (a *APIError) GetFirstError() ErrorItem {
	if len(a.Errors) > 0 {
		return a.Errors[0]
	}

	return ErrorItem{
		Name: "Unknown",
	}
}

func (g *HTTPAPI) ResolveBase(base *url.URL, uri string) string {
	rel := &url.URL{Path: uri}
	u := base.ResolveReference(rel)

	return u.String()
}

type ReqOptions struct {
	Params  map[string]string
	Headers map[string]string
}

func (g *HTTPAPI) Req(method string, uri string, postBody []byte, isJSON bool, options ...ReqOptions) ([]byte, int, string, error) {
	return g.reqBase(g.baseURL, method, uri, postBody, isJSON, options...)
}

// RateInfo contains information about API rate limits
type RateInfo struct {
	Limit      int    // x-ratelimit-limit
	Remaining  int    // x-ratelimit-remaining
	Used       int    // x-ratelimit-used
	Reset      int64  // x-ratelimit-reset
	RetryAfter int64  // x-ratelimit-retry-after
	Resource   string // x-ratelimit-resource
}

func parseRateLimitHeaders(headers http.Header) RateInfo {
	info := RateInfo{}

	if v := headers.Get("x-ratelimit-limit"); v != "" {
		info.Limit, _ = strconv.Atoi(v)
	}
	if v := headers.Get("x-ratelimit-remaining"); v != "" {
		info.Remaining, _ = strconv.Atoi(v)
	}
	if v := headers.Get("x-ratelimit-used"); v != "" {
		info.Used, _ = strconv.Atoi(v)
	}
	if v := headers.Get("x-ratelimit-reset"); v != "" {
		info.Reset, _ = strconv.ParseInt(v, 10, 64)
	}
	if v := headers.Get("x-ratelimit-retry-after"); v != "" {
		info.RetryAfter, _ = strconv.ParseInt(v, 10, 64)
	}
	if v := headers.Get("x-ratelimit-resource"); v != "" {
		info.Resource = v
	}

	return info
}

func (g *HTTPAPI) reqBase(base *url.URL, method string, uri string, postBody []byte, isJSON bool, options ...ReqOptions) ([]byte, int, string, error) {
	// Check local rate limiter before making request
	allowed, waitTime := g.rateLimiter.IsAllowed()
	if !allowed {
		// Wait for the retry period or return error
		select {
		case <-context.Background().Done():
			return nil, 0, "", context.Background().Err()
		case <-time.After(waitTime):
			// Continue after waiting
		}
	}

	buf := bytes.NewBuffer(postBody)
	req, err := http.NewRequest(method, g.ResolveBase(base, uri), buf)
	if err != nil {
		return nil, 0, "", err
	}

	if isJSON {
		req.Header.Set("Accept", "application/json")
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", g.APIKey))

	if len(options) > 0 {
		optionsVal := options[0]
		for k, v := range optionsVal.Headers {
			req.Header[k] = []string{v}
		}
		if params := optionsVal.Params; len(params) > 0 {
			q := req.URL.Query()
			for k, v := range params {
				q.Add(k, v)
			}
			req.URL.RawQuery = q.Encode()
		}
	}

	response, err := g.client.Do(req)
	if err != nil {
		return nil, 0, "", err
	}
	defer response.Body.Close()

	// Parse rate limit headers from response and update limiter if needed
	rateInfo := parseRateLimitHeaders(response.Header)

	// If we received a rate limit response, update our local limiter if needed
	if response.StatusCode == http.StatusTooManyRequests && rateInfo.RetryAfter > 0 {
		// Create a new rate limiter with adjusted limits if needed
		if rateInfo.Limit > 0 && rateInfo.Limit != g.rateLimiter.limit {
			g.rateLimiter = NewRateLimiter(rateInfo.Limit)
		}

		return nil, response.StatusCode, response.Header.Get("Content-Type"), ErrRateLimited
	}

	body, err := io.ReadAll(response.Body)
	return body, response.StatusCode, response.Header.Get("Content-Type"), err
}

func (g *HTTPAPI) ReqBuf(method string, uri string, buf []byte, dest interface{}, options ...ReqOptions) (interface{}, error) {
	body, statusCode, _, err := g.Req(method, uri, buf, true, options...)
	if err != nil {
		return nil, err
	}

	switch statusCode {
	case http.StatusOK, http.StatusCreated:
		if err := json.Unmarshal(body, dest); err != nil {
			return nil, err
		}

		return dest, nil
	case http.StatusBadRequest:
		var message APIError
		if err := json.Unmarshal(body, &message); err != nil {
			return nil, err
		}

		apiErr := message.GetFirstError()

		return nil, fmt.Errorf("%v: %v", apiErr.Name, apiErr.Reason)
	case http.StatusNotFound:
		var message APIError
		if err := json.Unmarshal(body, &message); err != nil {
			return nil, ErrNotFound
		}
		apiErr := message.GetFirstError()

		return nil, fmt.Errorf("%v: %v", apiErr.Name, apiErr.Reason)
	case http.StatusUnauthorized:
		var message APIError
		if err := json.Unmarshal(body, &message); err != nil {
			return nil, ErrApiKeyInvalid
		}
		apiErr := message.GetFirstError()

		return nil, fmt.Errorf("%v: %v", apiErr.Name, apiErr.Reason)
	case http.StatusTooManyRequests:
		var message APIError
		if err := json.Unmarshal(body, &message); err != nil {
			return nil, ErrRateLimited
		}
		apiErr := message.GetFirstError()

		return nil, fmt.Errorf("%v: %v", apiErr.Name, apiErr.Reason)
	default:
		var message APIError
		if err := json.Unmarshal(body, &message); err != nil {
			return nil, fmt.Errorf("%s: %v", ErrNotFound.Error(), errors.New("invalid response content"))
		}

		apiErr := message.GetFirstError()

		return nil, fmt.Errorf("%v: %v", apiErr.Name, apiErr.Reason)
	}
}

func (g *HTTPAPI) ReqJSON(method string, uri string, post interface{}, dest interface{}, options ...ReqOptions) (interface{}, error) {
	var err error
	var buf []byte

	if post != nil {
		buf, err = json.Marshal(post)
		if err != nil {
			return nil, err
		}
	}

	msg, err := g.ReqBuf(method, uri, buf, dest, options...)
	if err != nil {
		return msg, err
	}

	return dest, nil
}

func (g *HTTPAPI) GetJSON(uri string, dest interface{}, options ...ReqOptions) (interface{}, error) {
	return g.ReqJSON("GET", uri, nil, dest, options...)
}

func (g *HTTPAPI) PostJSON(uri string, post interface{}, dest interface{}, options ...ReqOptions) (interface{}, error) {
	return g.ReqJSON("POST", uri, post, dest, options...)
}

func (g *HTTPAPI) PutJSON(uri string, post interface{}, dest interface{}, options ...ReqOptions) (interface{}, error) {
	return g.ReqJSON("PUT", uri, post, dest, options...)
}

func (g *HTTPAPI) DeleteJSON(uri string, post interface{}, dest interface{}, options ...ReqOptions) (interface{}, error) {
	return g.ReqJSON("DELETE", uri, post, dest, options...)
}
