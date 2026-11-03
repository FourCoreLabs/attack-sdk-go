package emergingthreats

import (
	"bufio"
	"cmp"
	"context"
	"fmt"
	"iter"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/fourcorelabs/attack-sdk-go/pkg/api"
)

// RunEvent is one SSE event. Type is normally retry, status-update, keep_alive or
// close. Data is the unmodified event payload, not necessarily a JSON document.
// A close event may contain an error object or the string "execution complete".
type RunEvent struct {
	ID    string
	Type  string
	Data  string
	Retry time.Duration
}

// WatchRun streams per-threat run events, stopping on close, EOF, cancellation or
// when the consumer breaks iteration. It closes the body on every exit and does
// not reconnect/retry. For long-lived streams pass
// an HTTP client without a short total timeout to api.NewHTTPAPI.
//
// Status-update events are invalidation notifications: call GetReport to refresh
// the report. Inspect a close event's Data for a server-reported stream error.
//
// Required permission: emergingthreat.read.
// Required feature: emerging_threats. Refreshing via GetReport needs executions.read.
func WatchRun(ctx context.Context, h *api.HTTPAPI, runID string) iter.Seq2[RunEvent, error] {
	return func(yield func(RunEvent, error) bool) {
		if err := validatePathSegment(runID, "run ID"); err != nil {
			yield(RunEvent{}, err)
			return
		}
		response, err := h.Do(ctx, http.MethodGet, ExecutionsV2URI+"/runs/"+runID+"/sse", nil, api.ReqOptions{
			Headers: url.Values{"Accept": {"text/event-stream"}},
		})
		if err != nil {
			yield(RunEvent{}, fmt.Errorf("watch emerging-threat run: %w", err))
			return
		}
		if response.StatusCode < 200 || response.StatusCode >= 300 {
			err := api.DecodeResponse(response, nil)
			yield(RunEvent{}, fmt.Errorf("watch emerging-threat run: %w", err))
			return
		}
		defer response.Body.Close()
		mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
		if err != nil || mediaType != "text/event-stream" {
			yield(RunEvent{}, fmt.Errorf("watch emerging-threat run: expected text/event-stream, got %q", response.Header.Get("Content-Type")))
			return
		}

		scanner := bufio.NewScanner(response.Body)
		scanner.Buffer(make([]byte, 4096), 1024*1024)
		var id, eventType string
		var retry time.Duration
		var data []string
		for scanner.Scan() {
			line := scanner.Text()
			if line == "" {
				if len(data) > 0 || eventType != "" {
					event := RunEvent{ID: id, Type: cmp.Or(eventType, "message"), Data: strings.Join(data, "\n"), Retry: retry}
					if !yield(event, nil) || event.Type == "close" {
						return
					}
				}
				eventType = ""
				data = nil
				continue
			}
			if strings.HasPrefix(line, ":") {
				continue
			}
			field, value, _ := strings.Cut(line, ":")
			value = strings.TrimPrefix(value, " ")
			switch field {
			case "id":
				if !strings.ContainsRune(value, '\x00') {
					id = value
				}
			case "event":
				eventType = value
			case "data":
				data = append(data, value)
			case "retry":
				if milliseconds, err := strconv.ParseUint(value, 10, 63); err == nil && milliseconds <= uint64((1<<63-1)/time.Millisecond) {
					retry = time.Duration(milliseconds) * time.Millisecond
				}
			}
		}
		if err := scanner.Err(); err != nil {
			if ctx.Err() != nil {
				err = ctx.Err()
			}
			yield(RunEvent{}, fmt.Errorf("read emerging-threat events: %w", err))
		}
	}
}
