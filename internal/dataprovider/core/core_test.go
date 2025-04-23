package core

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/brianvoe/gofakeit/v7"
	"github.com/drakkan/sftpgo/v2/internal/dataprovider/core/wrapper"
	"github.com/nats-io/nats.go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type TestProduct struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Categories  []string `json:"categories"`
	Price       float64  `json:"price"`
	Features    []string `json:"features"`
	Color       string   `json:"color"`
	Material    string   `json:"material"`
}

const (
	testBucket = "test-bucket"
	testKey    = "test-key"
)

var (
	nc  *nats.Conn
	js  nats.JetStreamContext
	cfg *NatsCoreConfig
)

func TestMain(m *testing.M) {
	// Setup
	var err error
	nc, err = nats.Connect(fmt.Sprintf("nats://192.168.15.177:4222, %s", nats.DefaultURL))
	if err != nil {
		fmt.Printf("Failed to connect to NATS: %v\n", err)
		os.Exit(1)
	}

	js, err = nc.JetStream()
	if err != nil {
		fmt.Printf("Failed to create JetStream context: %v\n", err)
		nc.Close()
		os.Exit(1)
	}

	cfg = &NatsCoreConfig{
		JS:           js,
		MaxRetries:   3,
		RetryDelay:   50 * time.Millisecond,
		StorageNames: []string{testBucket},
	}

	// Run tests
	code := m.Run()

	// Cleanup
	if err := js.DeleteKeyValue(testBucket); err != nil {
		fmt.Printf("Failed to cleanup test bucket: %v\n", err)
	}
	nc.Close()

	os.Exit(code)
}

func TestNewNatsCore(t *testing.T) {
	tests := []struct {
		name    string
		config  *NatsCoreConfig
		wantErr bool
	}{
		{
			name:    "Valid config",
			config:  cfg,
			wantErr: false,
		},
		{
			name: "Missing JS context",
			config: &NatsCoreConfig{
				MaxRetries:   3,
				RetryDelay:   50 * time.Millisecond,
				StorageNames: []string{testBucket},
			},
			wantErr: true,
		},
		{
			name: "Negative retries",
			config: &NatsCoreConfig{
				JS:           js,
				MaxRetries:   -1,
				RetryDelay:   50 * time.Millisecond,
				StorageNames: []string{testBucket},
			},
			wantErr: true,
		},
		{
			name: "Empty storage names",
			config: &NatsCoreConfig{
				JS:         js,
				MaxRetries: 3,
				RetryDelay: 50 * time.Millisecond,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			core, err := NewNatsCore(tt.config)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, core)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, core)
			}
		})
	}
}

func TestNatsCore_CRUD(t *testing.T) {
	core, err := NewNatsCore(cfg)
	require.NoError(t, err)

	product := TestProduct{
		Name:        gofakeit.ProductName(),
		Description: gofakeit.ProductDescription(),
		Categories:  []string{gofakeit.ProductCategory()},
		Price:       gofakeit.Price(1, 1000),
		Features:    []string{gofakeit.Word(), gofakeit.Word()},
		Color:       gofakeit.Color(),
		Material:    gofakeit.Word(),
	}

	t.Run("Create", func(t *testing.T) {
		revision, err := core.CreateItem(testBucket, testKey, wrapper.NewWrapper(product))
		assert.NoError(t, err)
		assert.Greater(t, revision, uint64(0))
	})

	t.Run("Create Duplicate", func(t *testing.T) {
		_, err := core.CreateItem(testBucket, testKey, wrapper.NewWrapper(product))
		assert.Error(t, err)
	})

	t.Run("Get", func(t *testing.T) {
		var retrieved TestProduct
		w := wrapper.NewWrapper(&retrieved)
		revision, err := core.GetItem(testBucket, testKey, w)
		assert.NoError(t, err)
		assert.Greater(t, revision, uint64(0))
		assert.Equal(t, product, retrieved)
	})

	t.Run("Update", func(t *testing.T) {
		product.Price = 999.99
		err := core.UpdateItem(testBucket, testKey, wrapper.NewWrapper(product))
		assert.NoError(t, err)

		var retrieved TestProduct
		w := wrapper.NewWrapper(&retrieved)
		_, err = core.GetItem(testBucket, testKey, w)
		assert.NoError(t, err)
		assert.Equal(t, product, retrieved)
	})

	t.Run("List Items", func(t *testing.T) {
		items, err := core.ListItems(testBucket)
		assert.NoError(t, err)
		assert.Contains(t, items, testKey)
	})

	t.Run("Delete", func(t *testing.T) {
		err := core.DeleteItem(testBucket, testKey)
		assert.NoError(t, err)

		var retrieved TestProduct
		w := wrapper.NewWrapper(&retrieved)
		_, err = core.GetItem(testBucket, testKey, w)
		assert.Error(t, err)
	})
}

func BenchmarkNatsCore(b *testing.B) {
	core, err := NewNatsCore(cfg)
	require.NoError(b, err)

	product := TestProduct{
		Name:        gofakeit.ProductName(),
		Description: gofakeit.ProductDescription(),
		Categories:  []string{gofakeit.ProductCategory()},
		Price:       gofakeit.Price(1, 1000),
		Features:    []string{gofakeit.Word(), gofakeit.Word()},
		Color:       gofakeit.Color(),
		Material:    gofakeit.Word(),
	}

	b.Run("CreateItem", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			key := fmt.Sprintf("bench-key-%d", i)
			_, _ = core.CreateItem(testBucket, key, wrapper.NewWrapper(product))
		}
	})

	b.Run("GetItem", func(b *testing.B) {
		key := "bench-get-key"
		_, _ = core.CreateItem(testBucket, key, wrapper.NewWrapper(product))
		var retrieved TestProduct
		w := wrapper.NewWrapper(&retrieved)

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = core.GetItem(testBucket, key, w)
		}
	})

	b.Run("UpdateItem", func(b *testing.B) {
		key := "bench-update-key"
		_, _ = core.CreateItem(testBucket, key, wrapper.NewWrapper(product))

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			product.Price = float64(i)
			_ = core.UpdateItem(testBucket, key, wrapper.NewWrapper(product))
		}
	})

	// For the ListItems benchmark, create a fixed number of items
	const fixedItemCount = 100
	setupFixedItems := func() {
		for i := 0; i < fixedItemCount; i++ {
			key := fmt.Sprintf("fixed-key-%d", i)
			product := TestProduct{
				Name:  fmt.Sprintf("Product-%d", i),
				Price: float64(i),
			}
			_, _ = core.CreateItem(testBucket, key, wrapper.NewWrapper(product))
		}
	}

	b.Run("ListItems", func(b *testing.B) {
		setupFixedItems()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = core.ListItems(testBucket)
		}
	})
}
