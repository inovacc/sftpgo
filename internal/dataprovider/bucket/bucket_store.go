package bucket

import (
	"errors"
	"fmt"
	"github.com/nats-io/nats.go/jetstream"
	"strings"

	"github.com/nats-io/nats.go"
)

type KeyValueBucket struct {
	kv     nats.KeyValue
	root   string
	prefix string
}

func CreateKeyValueBucket(js nats.JetStreamContext, prefix string) (*KeyValueBucket, error) {
	keyValueBucket := &KeyValueBucket{
		prefix: prefix,
	}

	composeKey := keyValueBucket.composeKey("")

	var err error
	keyValueBucket.kv, err = js.CreateKeyValue(&nats.KeyValueConfig{Bucket: composeKey, Compression: true})
	if err != nil && !errors.Is(err, jetstream.ErrBucketExists) {
		return nil, fmt.Errorf("failed to create bucket: %w", err)
	}

	keyValueBucket.kv, err = js.KeyValue(composeKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get existing bucket: %w", err)
	}
	return keyValueBucket, nil
}

// Get return value from kv store by key.
// Ex: root.prefix.key
func (b *KeyValueBucket) Get(key string) (nats.KeyValueEntry, error) {
	return b.kv.Get(b.composeKey(key))
}

func (b *KeyValueBucket) Put(key string, value []byte) (uint64, error) {
	return b.kv.Put(b.composeKey(key), value)
}

func (b *KeyValueBucket) Create(key string, value []byte) (uint64, error) {
	return b.kv.Create(b.composeKey(key), value)
}

func (b *KeyValueBucket) Update(key string, value []byte, last uint64) (uint64, error) {
	return b.kv.Update(b.composeKey(key), value, last)
}

func (b *KeyValueBucket) Delete(key string, opts ...nats.DeleteOpt) error {
	return b.kv.Delete(b.composeKey(key), opts...)
}

func (b *KeyValueBucket) composeKey(key string) string {
	sb := strings.Builder{}

	if b.prefix != "" {
		sb.WriteString(b.prefix)
		if key != "" {
			sb.WriteString(".")
			sb.WriteString(strings.Trim(key, "."))
		}
	}
	return sb.String()
}
