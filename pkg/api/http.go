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

// SetRateLimit updates the rate limiter with a new limit
func (g *HTTPAPI) SetRateLimit(requestsPerMinute int) {
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
	// We can use either IsAllowed or Wait depending on whether we want to block or return immediately
	// Let's implement both approaches with priority to IsAllowed for quick checks

	// First check if we can make the request without waiting
	allowed, waitTime := g.rateLimiter.IsAllowed()
	if !allowed {
		// If wait time is reasonable (less than 5 seconds), we can wait
		if waitTime <= 5*time.Second {
			select {
			case <-time.After(waitTime):
				// Continue after waiting the short duration
			case <-context.Background().Done():
				return nil, 0, "", context.Background().Err()
			}
		} else {
			// Wait time is too long, let's use the Wait method with a max timeout
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			// Try to wait for a token, but only up to our limit
			if err := g.rateLimiter.WaitMaxDuration(ctx, 5*time.Second); err != nil {
				// If we couldn't get a token in time, return a rate limit error
				if errors.Is(err, context.DeadlineExceeded) {
					return nil, 0, "", fmt.Errorf("%w: retry after %.1f seconds",
						ErrRateLimited, waitTime.Seconds())
				}
				return nil, 0, "", err
			}
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

	// Parse rate limit headers from response
	rateInfo := parseRateLimitHeaders(response.Header)

	// If we received a rate limit response, update our local limiter if needed
	if response.StatusCode == http.StatusTooManyRequests {
		// Update rate limiter if we get new limit information
		if rateInfo.Limit > 0 && rateInfo.Limit != g.rateLimiter.limit {
			g.SetRateLimit(rateInfo.Limit)
		}

		// If there's a retry-after header, return appropriate error
		if rateInfo.RetryAfter > 0 {
			return nil, response.StatusCode, response.Header.Get("Content-Type"),
				fmt.Errorf("%w: retry after %d seconds", ErrRateLimited, rateInfo.RetryAfter)
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
