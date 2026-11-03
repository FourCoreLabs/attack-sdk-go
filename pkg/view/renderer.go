package view

import (
	"fmt"
	"io"
	"sync"

	"github.com/fourcorelabs/attack-sdk-go/pkg/view/renderers"
	"github.com/fourcorelabs/attack-sdk-go/pkg/view/renderers/csv"
	"github.com/fourcorelabs/attack-sdk-go/pkg/view/renderers/json"
	"github.com/fourcorelabs/attack-sdk-go/pkg/view/renderers/table"
)

type RendererFactory func() renderers.Renderer

type ViewRender struct {
	renderers map[Format]RendererFactory
	mu        sync.RWMutex
}

type ViewRenderOpt func(*ViewRender) error

// NewViewRender creates a renderer registry, using built-in renderers by default.
//
// Required permission: none (local operation; custom options may require permissions).
func NewViewRender(opts ...ViewRenderOpt) (*ViewRender, error) {
	vr := &ViewRender{
		renderers: make(map[Format]RendererFactory),
		mu:        sync.RWMutex{},
	}

	for _, fn := range opts {
		if err := fn(vr); err != nil {
			return vr, err
		}
	}

	if len(vr.renderers) == 0 {
		for format, factory := range map[Format]func() renderers.Renderer{
			FormatJSON:  json.NewJsonRender,
			FormatTable: table.NewTableRender,
			FormatCSV:   csv.NewCsvRender,
		} {
			if err := vr.RegisterRenderer(format, factory); err != nil {
				return vr, err
			}
		}
	}

	return vr, nil
}

// RegisterRenderer registers a renderer factory for the given format.
//
// Required permission: none (local operation).
func (r *ViewRender) RegisterRenderer(format Format, factory RendererFactory) error {
	if format == "" {
		return fmt.Errorf("format cannot be empty")
	}
	if factory == nil {
		return fmt.Errorf("renderer factory cannot be nil")
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.renderers[format] = factory
	return nil
}

// Render writes items using the renderer registered for the given format.
//
// Required permission: none for built-in renderers; custom renderers may require permissions.
func (r *ViewRender) Render(format Format, w io.Writer, items []any, opts ...renderers.RendererOptFunc) error {
	renderer, err := r.GetRenderer(format)
	if err != nil {
		return err
	}

	return renderer.Render(w, items, opts...)
}

// GetRenderer creates a renderer using the factory registered for the given format.
//
// Required permission: none for built-in factories; custom factories may require permissions.
func (r *ViewRender) GetRenderer(format Format) (renderers.Renderer, error) {
	r.mu.RLock()
	factory, ok := r.renderers[format]
	r.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("unsupported format %q", format)
	}

	return factory(), nil
}

// WithJsonRender registers the built-in JSON renderer.
//
// Required permission: none (local operation).
func WithJsonRender() ViewRenderOpt {
	return func(vr *ViewRender) error {
		return vr.RegisterRenderer(FormatJSON, json.NewJsonRender)
	}
}

// WithTableRender registers the built-in table renderer.
//
// Required permission: none (local operation).
func WithTableRender() ViewRenderOpt {
	return func(vr *ViewRender) error {
		return vr.RegisterRenderer(FormatTable, table.NewTableRender)
	}
}

// WithCsvRender registers the built-in CSV renderer.
//
// Required permission: none (local operation).
func WithCsvRender() ViewRenderOpt {
	return func(vr *ViewRender) error {
		return vr.RegisterRenderer(FormatCSV, csv.NewCsvRender)
	}
}
