package wrapper

import (
	"encoding/json"
	"reflect"
)

// Wrapper is a generic interface for JSON operations and runtime type inspection.
type Wrapper interface {
	json.Marshaler
	json.Unmarshaler
	Get() any
	TypeName() string
	Clone() Wrapper
}

// WithJSON adds JSON capabilities and introspection to any type.
type WithJSON[T any] struct {
	Data T
}

// NewWrapper creates a new wrapped instance.
func NewWrapper[T any](data T) *WithJSON[T] {
	return &WithJSON[T]{Data: data}
}

// MarshalJSON implements json.Marshaler
func (w *WithJSON[T]) MarshalJSON() ([]byte, error) {
	return json.Marshal(w.Data)
}

// UnmarshalJSON implements json.Unmarshaler
func (w *WithJSON[T]) UnmarshalJSON(data []byte) error {
	return json.Unmarshal(data, &w.Data)
}

// Get returns the underlying data.
func (w *WithJSON[T]) Get() any {
	return w.Data
}

// Set updates the underlying data
func (w *WithJSON[T]) Set(data T) {
	w.Data = data
}

// TypeName returns the name of the underlying data type.
func (w *WithJSON[T]) TypeName() string {
	var t T
	return reflect.TypeOf(t).String()
}

// Clone returns a new wrapper with a deep copy of the data
func (w *WithJSON[T]) Clone() Wrapper {
	var newData T
	return NewWrapper(newData)
}
