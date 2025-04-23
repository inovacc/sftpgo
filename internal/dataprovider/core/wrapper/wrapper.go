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

// // HandleWrapper extracts type and data from the Wrapper
// func HandleWrapper(w Wrapper) {
// 	data := w.Get()
// 	typ := reflect.TypeOf(data)
//
// 	fmt.Printf("Type from TypeName(): %s\n", w.TypeName())
// 	fmt.Printf("Type from reflect:   %s\n", typ.String())
// 	fmt.Printf("Value:               %+v\n", data)
// }
//
// // GetWrappedType extracts the underlying type using reflection with type safety
// func GetWrappedType[T any](w Wrapper) (T, error) {
// 	var zero T
//
// 	// Get the reflect.Value of the wrapper
// 	rv := reflect.ValueOf(w)
//
// 	// Check if it's a pointer and dereference if needed
// 	if rv.Kind() == reflect.Ptr {
// 		rv = rv.Elem()
// 	}
//
// 	// Look for the Data field in the struct
// 	if rv.Kind() != reflect.Struct {
// 		return zero, fmt.Errorf("wrapper must be a struct")
// 	}
//
// 	dataField := rv.FieldByName("Data")
// 	if !dataField.IsValid() {
// 		return zero, fmt.Errorf("no Data field found in wrapper")
// 	}
//
// 	// Try to convert the value to the requested type
// 	value := dataField.Interface()
// 	typed, ok := value.(T)
// 	if !ok {
// 		return zero, fmt.Errorf("value is not of type %T", zero)
// 	}
//
// 	return typed, nil
// }
//
// // GetWrappedValue extracts the underlying value using reflection
// func GetWrappedValue(w Wrapper) (any, reflect.Type, error) {
// 	// Get the reflect.Value of the wrapper
// 	rv := reflect.ValueOf(w)
//
// 	// Check if it's a pointer and dereference if needed
// 	if rv.Kind() == reflect.Ptr {
// 		rv = rv.Elem()
// 	}
//
// 	// Look for the Data field in the struct
// 	if rv.Kind() != reflect.Struct {
// 		return nil, nil, fmt.Errorf("wrapper must be a struct")
// 	}
//
// 	dataField := rv.FieldByName("Data")
// 	if !dataField.IsValid() {
// 		return nil, nil, fmt.Errorf("no Data field found in wrapper")
// 	}
// 	return dataField.Interface(), dataField.Type(), nil
// }
