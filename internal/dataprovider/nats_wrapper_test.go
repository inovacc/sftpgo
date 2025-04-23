package dataprovider

import (
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
)

type TestUser struct {
	Name        string   `json:"name" xml:"name"`
	Description string   `json:"description" xml:"description"`
	Categories  []string `json:"categories" xml:"categories"`
	Price       float64  `json:"price" xml:"price"`
	Features    []string `json:"features" xml:"features"`
	Color       string   `json:"color" xml:"color"`
	Material    string   `json:"material" xml:"material"`
}

func TestWrapper(t *testing.T) {
	tests := []struct {
		name    string
		input   TestUser
		wantErr bool
	}{
		{
			name: "Valid full user data",
			input: TestUser{
				Name:        "Microwave Vertex Marble",
				Description: "Full him bale me within. As far to canoe wad its it.",
				Categories:  []string{"musical instruments", "bicycles and accessories", "books"},
				Price:       46.06,
				Features:    []string{"user-friendly", "compact"},
				Color:       "navy",
				Material:    "granite",
			},
			wantErr: false,
		},
		{
			name: "Empty categories and features",
			input: TestUser{
				Name:        "Simple Product",
				Description: "Basic description",
				Categories:  []string{},
				Price:       19.99,
				Features:    []string{},
				Color:       "red",
				Material:    "plastic",
			},
			wantErr: false,
		},
		{
			name: "Zero price",
			input: TestUser{
				Name:        "Free Item",
				Description: "Free product description",
				Categories:  []string{"free"},
				Price:       0.0,
				Features:    []string{"free"},
				Color:       "white",
				Material:    "paper",
			},
			wantErr: false,
		},
		{
			name: "Special characters in strings",
			input: TestUser{
				Name:        "Product!@#$%^&*()",
				Description: "Description with šĕęćīàł characters 你好",
				Categories:  []string{"category#1", "category@2"},
				Price:       99.99,
				Features:    []string{"feature!1", "feature@2"},
				Color:       "blue-green",
				Material:    "mixed/material",
			},
			wantErr: false,
		},
		{
			name: "Maximum float value",
			input: TestUser{
				Name:        "Expensive Product",
				Description: "Very expensive item",
				Categories:  []string{"luxury"},
				Price:       1.797693134862315e+308, // Max float64
				Features:    []string{"expensive"},
				Color:       "gold",
				Material:    "diamond",
			},
			wantErr: false,
		},
		{
			name: "Negative price",
			input: TestUser{
				Name:        "Invalid Product",
				Description: "Product with negative price",
				Categories:  []string{"test"},
				Price:       -1.0,
				Features:    []string{"test"},
				Color:       "red",
				Material:    "plastic",
			},
			wantErr: false,
		},
		{
			name: "Empty required fields",
			input: TestUser{
				Name:        "",
				Description: "",
				Categories:  nil,
				Price:       0.0,
				Features:    nil,
				Color:       "",
				Material:    "",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create wrapper
			p := newWrapper(tt.input)

			// Test MarshalJSON
			data, err := p.MarshalJSON()
			if (err != nil) != tt.wantErr {
				t.Errorf("MarshalJSON() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			// Validate JSON structure
			var rawMap map[string]interface{}
			if err := json.Unmarshal(data, &rawMap); err != nil {
				t.Errorf("Generated JSON is invalid: %v", err)
				return
			}

			// Test UnmarshalJSON
			newWrapper := newWrapper(TestUser{})
			if err := newWrapper.UnmarshalJSON(data); err != nil {
				t.Errorf("UnmarshalJSON() error = %v", err)
				return
			}

			// Compare original and unmarshalled results
			result := newWrapper.Get()
			if !reflect.DeepEqual(result, tt.input) {
				t.Errorf("Data mismatch after marshal/unmarshal\ngot: %+v\nwant: %+v", result, tt.input)
			}
		})
	}
}

func TestWrapperEdgeCases(t *testing.T) {
	t.Run("Unmarshal invalid JSON", func(t *testing.T) {
		w := newWrapper(TestUser{})
		err := w.UnmarshalJSON([]byte(`{"invalid json`))
		if err == nil {
			t.Error("Expected error for invalid JSON, got nil")
		}
	})

	t.Run("Unmarshal empty JSON", func(t *testing.T) {
		w := newWrapper(TestUser{})
		err := w.UnmarshalJSON([]byte(`{}`))
		if err != nil {
			t.Errorf("Unexpected error for empty JSON: %v", err)
		}
	})

	t.Run("Unmarshal with invalid types", func(t *testing.T) {
		w := newWrapper(TestUser{})
		err := w.UnmarshalJSON([]byte(`{"price": "not a number"}`))
		if err == nil {
			t.Error("Expected error for invalid type conversion, got nil")
		}
	})

	t.Run("Unmarshal with null values", func(t *testing.T) {
		w := newWrapper(TestUser{})
		err := w.UnmarshalJSON([]byte(`{"name": null, "price": null}`))
		if err != nil {
			t.Errorf("Unexpected error for null values: %v", err)
		}
	})
}

func TestGetType(t *testing.T) {
	wUser := newWrapper(TestUser{
		Name:        "Microwave Vertex Marble",
		Description: "Full him bale me within. As far to canoe wad its it.",
		Categories:  []string{"musical instruments", "bicycles and accessories", "books"},
		Price:       46.06,
		Features:    []string{"user-friendly", "compact"},
		Color:       "navy",
		Material:    "granite",
	})

	fmt.Println(wUser.TypeName())
}

// func TestCloneFull(t *testing.T) {
// 	wUser := newWrapper(TestUser{
// 		Name:        "Microwave Vertex Marble",
// 		Description: "Full him bale me within. As far to canoe wad its it.",
// 		Categories:  []string{"musical instruments", "bicycles and accessories", "books"},
// 		Price:       46.06,
// 		Features:    []string{"user-friendly", "compact"},
// 		Color:       "navy",
// 		Material:    "granite",
// 	})
//
// 	clone := wUser.Clone()
// 	expected := clone.Get().Name
//
// 	if expected != "" {
// 		t.Error("Cloned wrapper empty")
// 	}
// }
//
// func TestCloneEmpty(t *testing.T) {
// 	wUser := newWrapper(TestUser{
// 		Name:        "Microwave Vertex Marble",
// 		Description: "Full him bale me within. As far to canoe wad its it.",
// 		Categories:  []string{"musical instruments", "bicycles and accessories", "books"},
// 		Price:       46.06,
// 		Features:    []string{"user-friendly", "compact"},
// 		Color:       "navy",
// 		Material:    "granite",
// 	})
//
// 	clone := wUser.Clone()
// 	expected := clone.Get().Name
//
// 	if expected != wUser.Get().Name {
// 		t.Error("Cloned wrapper need to be empty")
// 	}
// }
//
// func TestCloneDeepCopy(t *testing.T) {
// 	original := newWrapper(TestUser{
// 		Categories: []string{"cat1", "cat2"},
// 		Features:   []string{"feat1", "feat2"},
// 	})
//
// 	clone := original.Clone()
//
// 	// Modify original's slices
// 	originalUser := original.Get()
// 	originalUser.Categories[0] = "modified"
// 	originalUser.Features[0] = "modified"
//
// 	// Check if clone's slices were affected
// 	clonedUser := clone.Get()
// 	if clonedUser.Categories[0] == "modified" || clonedUser.Features[0] == "modified" {
// 		t.Error("Clone did not perform deep copy of slices")
// 	}
// }

func TestEmptyWrapperWithSet(t *testing.T) {
	// Create an empty wrapper
	emptyWrapper := newWrapper(TestUser{})

	// Prepare test data
	testUser := TestUser{
		Name:        "Test User",
		Description: "Test Description",
		Categories:  []string{"test1", "test2"},
		Price:       29.99,
		Features:    []string{"feature1", "feature2"},
		Color:       "blue",
		Material:    "metal",
	}

	// Set the data to an empty wrapper
	emptyWrapper.Set(testUser)

	// Verify the data was set correctly
	result := emptyWrapper.Get()
	if !reflect.DeepEqual(result, testUser) {
		t.Errorf("Set() failed to update empty wrapper\ngot: %+v\nwant: %+v", result, testUser)
	}

	// Test JSON marshaling of the updated wrapper
	data, err := emptyWrapper.MarshalJSON()
	if err != nil {
		t.Errorf("MarshalJSON() error after Set(): %v", err)
	}

	// Verify JSON structure
	var rawMap map[string]interface{}
	if err := json.Unmarshal(data, &rawMap); err != nil {
		t.Errorf("Generated JSON is invalid after Set(): %v", err)
	}

	// Create another empty wrapper and unmarshal the data
	verifyWrapper := newWrapper(TestUser{})
	if err := verifyWrapper.UnmarshalJSON(data); err != nil {
		t.Errorf("UnmarshalJSON() error after Set(): %v", err)
	}

	// Compare the results
	if !reflect.DeepEqual(verifyWrapper.Get(), testUser) {
		t.Errorf("Data mismatch after Set() and marshal/unmarshal\ngot: %+v\nwant: %+v", verifyWrapper.Get(), testUser)
	}
}
