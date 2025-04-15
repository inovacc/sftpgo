package nats

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"log"
	"os"
	"sync"
	"testing"
	"time"
)

var testObj testStruct

type user struct {
	Username string
	Email    string
}

func (u *user) Marshal() ([]byte, error) {
	return json.Marshal(u)
}

func (u *user) Unmarshal(data []byte) error {
	return json.Unmarshal(data, u)
}

type testStruct struct {
	js  nats.JetStreamContext
	ctx context.Context
}

func TestMain(m *testing.M) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	nc, err := nats.Connect(nats.DefaultURL)
	if err != nil {
		log.Fatalf("Error connecting to nats server: %v", err)
	}

	js, err := nc.JetStream()
	if err != nil {
		log.Fatalf("Error getting JetStream context: %v", err)
	}

	testObj.ctx = ctx
	testObj.js = js

	os.Exit(m.Run())
}

func TestWatchAndSyncTyped(t *testing.T) {
	kv, err := testObj.js.CreateKeyValue(&nats.KeyValueConfig{
		Bucket:      "TEST_BUCKET9",
		Description: "test bucket for testing purpose",
		Storage:     nats.FileStorage,
		Compression: true,
	})
	if err != nil {
		t.Fatalf("Error creating key-value store: %v", err)
	}

	userFactory := func() *user {
		return &user{}
	}

	if err := SafeWriteTyped[*user](kv, "users.john", userFactory, func(u *user) (*user, error) {
		if u.Username == "" {
			u.Username = "john"
			u.Email = "init@example.com"
		} else {
			u.Email = "updated@example.com"
		}
		return u, nil
	}); err != nil {
		t.Fatalf("Error setting up TestWatchAndSyncTyped: %v", err)
	}
}

func TestWatchAndSync(t *testing.T) {
	kv, err := testObj.js.CreateKeyValue(&nats.KeyValueConfig{
		Bucket:      "TEST_BUCKET",
		Description: "test bucket for testing purpose",
		Storage:     nats.FileStorage,
		Compression: true,
	})
	if err != nil {
		t.Fatalf("Error creating key-value store: %v", err)
	}

	result := 0
	response := 0
	expected := 1000

	if err := WatchAndSync(testObj.ctx, kv, "", true, func(key string, val []byte) {
		response++
		t.Logf("Detected update - key: %s, value: %s", key, string(val))
	}); err != nil {
		response--
		t.Fatalf("Error setting up WatchAndSync: %v", err)
	}

	wg := sync.WaitGroup{}
	key := uuid.NewString()

	load := func() {
		defer wg.Done()

		if err = SafeWrite(kv, key, func(current []byte) ([]byte, error) {
			result++
			return []byte(fmt.Sprintf("hello world, %d", time.Now().UnixNano())), nil
		}); err != nil {
			result--
			t.Fatalf("Error writing to key: %v", err)
		}
	}

	for i := 0; i < expected; i++ {
		wg.Add(1)
		load()
	}

	wg.Wait()

	if result < response {
		t.Fatalf("Expected %d updates, got %d", response, result)
	}
}
