package nats

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/inovacc/utils/v2/reflection"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
)

type Payload interface {
	Marshal() ([]byte, error)
	Unmarshal([]byte) error
}

type PayloadFactory[P Payload] func() P

// SafeWrite tries to write data into NATS KV with CAS retry logic.
func SafeWrite(kv nats.KeyValue, key string, modifyFn func(current []byte) ([]byte, error)) error {
	for attempt := 0; attempt < 3; attempt++ {
		entry, err := kv.Get(key)
		switch {
		case errors.Is(err, nats.ErrKeyNotFound):
			newData, modErr := modifyFn(nil)
			if modErr != nil {
				return modErr
			}

			if _, err = kv.Create(key, newData); err == nil {
				return nil
			}

			if errors.Is(err, nats.ErrKeyExists) {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return fmt.Errorf("failed to create key %q: %w", key, err)

		case err != nil:
			return fmt.Errorf("failed to get key %q: %w", key, err)
		}

		newData, modErr := modifyFn(entry.Value())
		if modErr != nil {
			return modErr
		}

		if _, err = kv.Update(key, newData, entry.Revision()); err == nil {
			return nil
		}
		if errors.Is(err, nats.ErrKeyExists) {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		return fmt.Errorf("failed to update key %q: %w", key, err)
	}
	return fmt.Errorf("max retries reached for key %q", key)
}

// SafeWriteTyped tries to write data into NATS KV with CAS retry logic, using generics of Payload interface
func SafeWriteTyped[P Payload](kv nats.KeyValue, key string, newPayload PayloadFactory[P], modifyFn func(current P) (P, error)) error {
	for attempt := 0; attempt < 3; attempt++ {
		entry, err := kv.Get(key)

		switch {
		case errors.Is(err, nats.ErrKeyNotFound):
			newP, err := modifyFn(newPayload())
			if err != nil {
				return err
			}

			data, err := newP.Marshal()
			if err != nil {
				return err
			}

			if _, err = kv.Create(key, data); err == nil {
				return nil
			}

			if errors.Is(err, nats.ErrKeyExists) {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return fmt.Errorf("failed to create key %q: %w", key, err)

		case err != nil:
			return fmt.Errorf("failed to get key %q: %w", key, err)
		}

		current := newPayload()
		if err := current.Unmarshal(entry.Value()); err != nil {
			return fmt.Errorf("unmarshal failed for key %q: %w", key, err)
		}

		modified, err := modifyFn(current)
		if err != nil {
			return err
		}

		data, err := modified.Marshal()
		if err != nil {
			return err
		}

		if _, err = kv.Update(key, data, entry.Revision()); err == nil {
			return nil
		}

		if errors.Is(err, nats.ErrKeyExists) {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		return fmt.Errorf("failed to update key %q: %w", key, err)
	}
	return fmt.Errorf("max retries reached for key %q", key)
}

// WatchAndSync watches a KV bucket prefix and runs syncFn on each update.
// If skipHistory is true, it skips all existing entries on startup.
func WatchAndSync(ctx context.Context, kv nats.KeyValue, prefix string, skipHistory bool, syncFn func(key string, val []byte)) error {
	var opts []nats.WatchOpt
	if skipHistory {
		opts = append(opts, nats.UpdatesOnly())
	}

	watcher, err := kv.Watch(fmt.Sprintf("%s>", prefix), opts...)
	if err != nil {
		return fmt.Errorf("unable to start KV watch: %w", err)
	}

	go func() {
		defer watcher.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case update, ok := <-watcher.Updates():
				if !ok || update == nil || update.Value() == nil || update.Operation() == nats.KeyValueDelete {
					continue
				}
				syncFn(update.Key(), update.Value())
			}
		}
	}()
	return nil
}

// WatchAndSyncTyped adds JSON decoding of values into a provided type.
// If skipHistory is true, it avoids processing existing entries on startup.
func WatchAndSyncTyped[T any](ctx context.Context, kv nats.KeyValue, prefix string, skipHistory bool, syncFn func(key string, t T)) error {
	return WatchAndSync(ctx, kv, prefix, skipHistory, func(key string, val []byte) {
		var typed T
		if err := json.Unmarshal(val, &typed); err == nil {
			syncFn(key, typed)
		}
	})
}

type BulkInit struct {
	js nats.JetStreamContext
}

func NewBulkInit(js nats.JetStreamContext) *BulkInit {
	return &BulkInit{
		js: js,
	}
}

func (b *BulkInit) Init(buckets map[string]*nats.KeyValueConfig, include *nats.KeyValueConfig, kvs map[string]nats.KeyValue) error {
	for _, bucket := range buckets {
		if bucket.Description == "" {
			bucket.Description = b.formatDescription(bucket.Bucket)
		}

		reflection.MergeZeroFields(bucket, include)

		kv, err := b.js.CreateKeyValue(bucket)
		if err != nil {
			return fmt.Errorf("failed to create KV bucket %q: %w", bucket.Bucket, err)
		}
		kvs[kv.Bucket()] = kv
	}

	return nil
}

func (b *BulkInit) formatDescription(bucket string) string {
	clean := strings.TrimPrefix(bucket, "SFTP_KV_")
	clean = strings.TrimPrefix(clean, "KV_")

	parts := strings.Split(clean, "_")
	for i, part := range parts {
		parts[i] = strings.Title(strings.ToLower(part))
	}
	return fmt.Sprintf("Key Value Store for %s", strings.Join(parts, " "))
}
