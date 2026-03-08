package renderers

import (
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"sort"
	"strings"
	"time"
)

type Renderer interface {
	Render(w io.Writer, items []any) error
}

func BuildRecords(items []any) ([]string, []map[string]any, error) {
	headers := make([]string, 0)
	seen := make(map[string]struct{})
	records := make([]map[string]any, 0, len(items))

	for _, item := range items {
		rec, cols, err := toRecord(item)
		if err != nil {
			return nil, nil, err
		}

		for _, h := range cols {
			if _, ok := seen[h]; ok {
				continue
			}
			seen[h] = struct{}{}
			headers = append(headers, h)
		}

		records = append(records, rec)
	}

	return headers, records, nil
}

func toRecord(item any) (map[string]any, []string, error) {
	if item == nil {
		return map[string]any{"value": nil}, []string{"value"}, nil
	}

	rv := reflect.ValueOf(item)
	for rv.Kind() == reflect.Pointer {
		if rv.IsNil() {
			return map[string]any{"value": nil}, []string{"value"}, nil
		}
		rv = rv.Elem()
	}

	switch rv.Kind() {
	case reflect.Struct:
		rec, headers := structRecord(rv)
		return rec, headers, nil
	case reflect.Map:
		rec, headers := mapRecord(rv)
		return rec, headers, nil
	default:
		return map[string]any{"value": item}, []string{"value"}, nil
	}
}

func structRecord(v reflect.Value) (map[string]any, []string) {
	t := v.Type()
	record := make(map[string]any, t.NumField())
	headers := make([]string, 0, t.NumField())

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		if !field.IsExported() {
			continue
		}

		header, ok := fieldHeader(field)
		if !ok {
			continue
		}

		record[header] = v.Field(i).Interface()
		headers = append(headers, header)
	}

	return record, headers
}

func mapRecord(v reflect.Value) (map[string]any, []string) {
	record := make(map[string]any, v.Len())
	headers := make([]string, 0, v.Len())

	iter := v.MapRange()
	for iter.Next() {
		k := fmt.Sprint(iter.Key().Interface())
		record[k] = iter.Value().Interface()
		headers = append(headers, k)
	}

	sort.Strings(headers)
	return record, headers
}

func fieldHeader(field reflect.StructField) (string, bool) {
	tag := field.Tag.Get("json")
	if tag == "-" {
		return "", false
	}

	if tag == "" {
		return field.Name, true
	}

	name := strings.Split(tag, ",")[0]
	if name == "" {
		return field.Name, true
	}

	return name, true
}

func StringifyCell(value any) string {
	if value == nil {
		return ""
	}

	switch v := value.(type) {
	case time.Time:
		return v.Format(time.RFC3339)
	case *time.Time:
		if v == nil {
			return ""
		}
		return v.Format(time.RFC3339)
	}

	rv := reflect.ValueOf(value)
	for rv.Kind() == reflect.Pointer {
		if rv.IsNil() {
			return ""
		}
		rv = rv.Elem()
	}

	switch rv.Kind() {
	case reflect.Struct, reflect.Map, reflect.Array, reflect.Slice:
		b, err := json.Marshal(rv.Interface())
		if err == nil {
			return string(b)
		}
	}

	return fmt.Sprint(rv.Interface())
}
