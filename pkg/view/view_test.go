package view

import (
	"bytes"
	"iter"
	"strings"
	"testing"
)

type sample struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Score int    `json:"score"`
}

type transformed struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type summary struct {
	ID string `json:"id"`
}

type item struct {
	v               sample
	transformCalled *bool
	summaryCalled   *bool
}

func (i item) Transform() (any, error) {
	*i.transformCalled = true
	return transformed{
		ID:   i.v.ID,
		Name: strings.ToUpper(i.v.Name),
	}, nil
}

func (i item) Summary() (any, error) {
	*i.summaryCalled = true
	return summary{ID: i.v.ID}, nil
}

func seqFromItems[T any](items []T) iter.Seq2[T, error] {
	return func(yield func(T, error) bool) {
		for _, item := range items {
			if !yield(item, nil) {
				return
			}
		}
	}
}

func TestViewSummaryCallsTransformAndSummary(t *testing.T) {
	transformCalled := false
	summaryCalled := false

	v, err := New("json", "summary", seqFromItems([]item{{
		v:               sample{ID: "1", Name: "alpha", Score: 10},
		transformCalled: &transformCalled,
		summaryCalled:   &summaryCalled,
	}}))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	b := &bytes.Buffer{}
	if err := v.Render(b); err != nil {
		t.Fatalf("Render() error = %v", err)
	}

	if !transformCalled {
		t.Fatalf("Transform() was not called")
	}
	if !summaryCalled {
		t.Fatalf("Summary() was not called")
	}

	out := b.String()
	if !strings.Contains(out, `"id": "1"`) {
		t.Fatalf("unexpected summary output: %s", out)
	}
	if strings.Contains(out, `"name"`) {
		t.Fatalf("summary output should not include expanded fields: %s", out)
	}
}

func TestViewCSVUsesJSONTagsForHeaders(t *testing.T) {
	v, err := New("csv", "expanded", seqFromItems([]sample{{
		ID: "a1", Name: "alpha", Score: 7,
	}}))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	b := &bytes.Buffer{}
	if err := v.Render(b); err != nil {
		t.Fatalf("Render() error = %v", err)
	}

	out := b.String()
	if !strings.HasPrefix(out, "id,name,score\n") {
		t.Fatalf("csv headers are not from json tags: %q", out)
	}
}
