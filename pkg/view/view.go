package view

import (
	"fmt"
	"io"
	"strings"

	"github.com/fourcorelabs/attack-sdk-go/pkg/view/renderers"
)

type Format string

const (
	FormatJSON  Format = "json"
	FormatTable Format = "table"
	FormatCSV   Format = "csv"
)

type Mode string

const (
	ModeSummary  Mode = "summary"
	ModeExpanded Mode = "expanded"
)

type Transformable interface {
	// Transform converts an item into its expanded representation.
	// Required permission: none for the interface; implementations may require permissions.
	Transform() (any, error)
}

type Summarizable interface {
	// Summary converts an item into its summary representation.
	// Required permission: none for the interface; implementations may require permissions.
	Summary() (any, error)
}

type View[T any] struct {
	Format                 Format
	Mode                   Mode
	Data                   []T
	vr                     *ViewRender
	isSingleElemAndCompose bool // if true render as object and remove array element
}

type ViewOpts[T any] func(*View[T]) error

// New creates a view with the given format, mode, data, and options.
//
// Required permission: none (local operation; custom options may require permissions).
func New[T any](format, mode string, data []T, opts ...ViewOpts[T]) (*View[T], error) {
	f, err := NormalizeFormat(format)
	if err != nil {
		return nil, err
	}

	m, err := NormalizeMode(mode)
	if err != nil {
		return nil, err
	}

	v := &View[T]{
		Format: f,
		Mode:   m,
		Data:   data,
	}

	for _, fn := range opts {
		if err := fn(v); err != nil {
			return v, err
		}
	}

	if v.vr == nil {
		rf, err := NewViewRender()
		if err != nil {
			return v, err
		}
		v.vr = rf
	}

	return v, nil
}

// WithViewRender configures a view to use the supplied renderer registry.
//
// Required permission: none (local operation).
func WithViewRender[T any](vr *ViewRender) ViewOpts[T] {
	return func(v *View[T]) error {
		v.vr = vr
		return nil
	}
}

// SingleElemAndCompose configures single-element composed output for a view.
//
// Required permission: none (local operation).
func SingleElemAndCompose[T any]() ViewOpts[T] {
	return func(v *View[T]) error {
		v.isSingleElemAndCompose = true
		return nil
	}
}

// Render transforms the view's data and writes it using the configured renderer.
//
// Required permission: none for built-in rendering; custom transformations and
// renderers may require permissions.
func (v *View[T]) Render(w io.Writer) error {
	if w == nil {
		return fmt.Errorf("writer cannot be nil")
	}

	renderer, err := v.vr.GetRenderer(v.Format)
	if err != nil {
		return err
	}

	items, err := Materialize(v.Data, v.Mode)
	if err != nil {
		return err
	}

	opts := make([]renderers.RendererOptFunc, 0, 1)
	if v.isSingleElemAndCompose {
		opts = append(opts, renderers.SingleElemAndComposeOption())
	}

	return renderer.Render(w, items, opts...)
}

// Materialize transforms items and optionally summarizes them for the given mode.
//
// Required permission: none for this helper; custom Transform and Summary methods
// may require permissions.
func Materialize[T any](data []T, mode Mode) ([]any, error) {
	items := make([]any, 0, len(data))
	for _, item := range data {
		processed, err := processItem(any(item), mode)
		if err != nil {
			return nil, err
		}

		items = append(items, processed)
	}

	return items, nil
}

func processItem(item any, mode Mode) (d any, err error) {
	expanded := item
	if transformer, ok := item.(Transformable); ok {
		transformed, err := transformer.Transform()
		if err != nil {
			return nil, err
		}
		expanded = transformed
	}

	if mode != ModeSummary {
		return expanded, nil
	}

	if summarizer, ok := expanded.(Summarizable); ok {
		return summarizer.Summary()
	}

	return expanded, nil
}

// NormalizeFormat normalizes and validates an output format name.
//
// Required permission: none (local operation).
func NormalizeFormat(format string) (Format, error) {
	f := Format(strings.ToLower(strings.TrimSpace(format)))
	switch f {
	case FormatJSON, FormatTable, FormatCSV:
		return f, nil
	default:
		return "", fmt.Errorf("invalid format %q", format)
	}
}

// NormalizeMode normalizes and validates a view mode name.
//
// Required permission: none (local operation).
func NormalizeMode(mode string) (Mode, error) {
	m := Mode(strings.ToLower(strings.TrimSpace(mode)))
	switch m {
	case ModeSummary, ModeExpanded:
		return m, nil
	default:
		return "", fmt.Errorf("invalid mode %q", mode)
	}
}
