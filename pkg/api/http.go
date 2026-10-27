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

	"golang.org/x/time/rate"
)

// RateLimiter wraps the golang.org/x/time/rate Limiter
type RateLimiter struct {
	limiter *rate.Limiter // Token bucket rate limiter
	limit   int           // Store original limit value
}

// NewRateLimiter creates a new rate limiter with default values
func NewRateLimiter(requestsPerMinute int) *RateLimiter {
	// Convert requests per minute to requests per second
	rps := float64(requestsPerMinute) / 60.0
	// Create a token bucket with capacity equal to the limit and refill rate of rps
	limiter := rate.NewLimiter(rate.Limit(rps), requestsPerMinute)

	return &RateLimiter{
		limiter: limiter,
		limit:   requestsPerMinute,
	}
}

// IsAllowed checks if a request is allowed based on rate limits without blocking
// Returns true if allowed, false if rate limited, and duration to wait if limited
func (r *RateLimiter) IsAllowed() (bool, time.Duration) {
	// Use Reserve to get information about when a token would be available
	reservation := r.limiter.Reserve()
	if !reservation.OK() {
		// This generally shouldn't happen with the standard token bucket,
		// but we'll handle it anyway
		reservation.Cancel()
		return false, 0
	}

	// Check if we need to wait
	delay := reservation.Delay()
	if delay == 0 {
		// No need to wait, token available immediately
		return true, 0
	}

	// We'd need to wait - cancel the reservation since we're not actually consuming yet
	// and return the wait time
	reservation.Cancel()
	return false, delay
}

// Allow checks if a request is allowed based on rate limits and consumes a token if available
func (r *RateLimiter) Allow() bool {
	return r.limiter.Allow()
}

// Wait blocks until a request can be allowed or the context is done
func (r *RateLimiter) Wait(ctx context.Context) error {
	return r.limiter.Wait(ctx)
}

// WaitMaxDuration tries to wait for a token but only up to the specified max duration
func (r *RateLimiter) WaitMaxDuration(ctx context.Context, maxWait time.Duration) error {
	// Create a new context with timeout
	ctx, cancel := context.WithTimeout(ctx, maxWait)
	defer cancel()

	return r.limiter.Wait(ctx)
}

// RemainingTokens returns an estimate of the number of remaining requests
func (r *RateLimiter) RemainingTokens() float64 {
	return r.limiter.Tokens()
}

// HTTPAPI represents an HTTP API client
type HTTPAPI struct {
	BaseURL     string
	baseURL     *url.URL
	client      *http.Client
	APIKey      string
	rateLimiter *RateLimiter
	rateMu      sync.RWMutex
}

// NewHTTPAPI creates a new API client with default rate limit of 100 reqs/min
func NewHTTPAPI(baseURL, apiKey string, client ...*http.Client) (*HTTPAPI, error) {
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}

	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxConnsPerHost:     10,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	}

	httpClient := &http.Client{Timeout: 60 * time.Second, Transport: transport}
	if len(client) > 0 {
		httpClient = client[0]
	}

	return &HTTPAPI{
		BaseURL:     baseURL,
		baseURL:     parsedURL,
		client:      httpClient,
		APIKey:      apiKey,
		rateLimiter: NewRateLimiter(100), // Default rate limit: 100 requests per minute
	}, nil
}

// setRateLimit updates the rate limiter with a new limit
func (g *HTTPAPI) setRateLimit(requestsPerMinute int) {
	g.rateMu.Lock()
	defer g.rateMu.Unlock()
	g.rateLimiter = NewRateLimiter(requestsPerMinute)
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

// APIError describes an HTTP error in either the standard v2 or legacy envelope.
// Use errors.As to inspect it and errors.Is to match SDK sentinel errors.
type APIError struct {
	Code    int         `json:"code"`
	Detail  string      `json:"detail"`
	Title   string      `json:"title"`
	Status  int         `json:"status,omitempty"`
	Errors  []ErrorItem `json:"errors,omitempty" xml:"errors,omitempty"`
	Message string      `json:"error,omitempty"`
	// RetryAfter is the server-requested retry delay in seconds, when available.
	RetryAfter int64 `json:"-"`
}

type ForbiddenError struct {
	Code  int    `json:"code"`
	Error string `json:"error"`
}

func (a *APIError) GetError() ErrorItem {
	return ErrorItem{
		Name:   a.Title,
		Reason: fmt.Sprintf("%v", a.Status),
	}
}

func (g *HTTPAPI) ResolveBase(base *url.URL, uri string) string {
	rel := &url.URL{Path: uri}
	u := base.ResolveReference(rel)

	return u.String()
}

// ReqOptions customizes query parameters, headers, and streaming behavior.
type ReqOptions struct {
	Params  url.Values
	Headers url.Values
	// NoRedirect returns redirect responses without following them.
	NoRedirect bool
	// ContentLength overrides the inferred request length when nonzero.
	ContentLength int64
}

func (g *HTTPAPI) req(ctx context.Context, method string, uri string, postBody []byte, isJSON bool, options ...ReqOptions) ([]byte, int, string, error) {
	return g.reqBase(ctx, g.baseURL, method, uri, postBody, isJSON, options...)
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

func (g *HTTPAPI) reqBase(ctx context.Context, base *url.URL, method string, uri string, postBody []byte, isJSON bool, options ...ReqOptions) ([]byte, int, string, error) {
	var opts ReqOptions
	if len(options) > 0 {
		opts = options[0]
	}
	opts.Headers = url.Values(http.Header(opts.Headers).Clone())
	if opts.Headers == nil {
		opts.Headers = make(url.Values)
	}
	if isJSON {
		opts.Headers.Set("Accept", "application/json")
		if postBody != nil {
			opts.Headers.Set("Content-Type", "application/json")
		}
	}
	response, err := g.doBase(ctx, base, method, uri, bytes.NewReader(postBody), opts)
	if err != nil {
		return nil, 0, "", err
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err == nil && response.StatusCode == http.StatusTooManyRequests {
		return nil, response.StatusCode, response.Header.Get("Content-Type"), responseError(response.StatusCode, body, response.Header)
	}
	return body, response.StatusCode, response.Header.Get("Content-Type"), err
}

func (g *HTTPAPI) reqBuf(ctx context.Context, method string, uri string, buf []byte, dest interface{}, options ...ReqOptions) (interface{}, error) {
	body, statusCode, _, err := g.req(ctx, method, uri, buf, true, options...)
	if err != nil {
		return nil, err
	}

	switch statusCode {
	case http.StatusOK, http.StatusCreated:
		if err := json.Unmarshal(body, dest); err != nil {
			return nil, err
		}

		return dest, nil

	default:
		return nil, responseError(statusCode, body)
	}
}

func (g *HTTPAPI) ReqJSON(ctx context.Context, method string, uri string, post interface{}, dest interface{}, options ...ReqOptions) (interface{}, error) {
	var err error
	var buf []byte

	if post != nil {
		buf, err = json.Marshal(post)
		if err != nil {
			return nil, err
		}
	}

	msg, err := g.reqBuf(ctx, method, uri, buf, dest, options...)
	if err != nil {
		return msg, err
	}

	return dest, nil
}

func (g *HTTPAPI) GetJSON(ctx context.Context, uri string, dest interface{}, options ...ReqOptions) (interface{}, error) {
	return g.ReqJSON(ctx, "GET", uri, nil, dest, options...)
}

func (g *HTTPAPI) PostJSON(ctx context.Context, uri string, post interface{}, dest interface{}, options ...ReqOptions) (interface{}, error) {
	return g.ReqJSON(ctx, "POST", uri, post, dest, options...)
}

func (g *HTTPAPI) PutJSON(ctx context.Context, uri string, post interface{}, dest interface{}, options ...ReqOptions) (interface{}, error) {
	return g.ReqJSON(ctx, "PUT", uri, post, dest, options...)
}

func (g *HTTPAPI) DeleteJSON(ctx context.Context, uri string, post interface{}, dest interface{}, options ...ReqOptions) (interface{}, error) {
	return g.ReqJSON(ctx, "DELETE", uri, post, dest, options...)
}
