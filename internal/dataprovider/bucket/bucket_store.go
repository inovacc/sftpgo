package bucket

import (
	"errors"
	"fmt"
	"github.com/nats-io/nats.go/jetstream"
	"strings"

	"github.com/nats-io/nats.go"
)

type KeyValueBucket struct {
	kv       nats.KeyValue
	prefix   string
	password []byte
	salt     []byte
}

func CreateKeyValueBucket(js nats.JetStreamContext, name string) (*KeyValueBucket, error) {
	kv, err := js.CreateKeyValue(&nats.KeyValueConfig{Bucket: name, Compression: true})
	if err != nil && !errors.Is(err, jetstream.ErrBucketExists) {
		return nil, err
	}

	if errors.Is(err, jetstream.ErrBucketExists) {
		kv, err = js.KeyValue(kv.Bucket())
		if err != nil {
			return nil, err
		}
	}
	return &KeyValueBucket{kv: kv, prefix: name}, nil
}

func (b *KeyValueBucket) SubBucket(name string) *KeyValueBucket {
	p := strings.Trim(name, ".")
	if b.prefix != "" {
		p = fmt.Sprintf("%s.%s", b.prefix, p)
	}
	return &KeyValueBucket{kv: b.kv, prefix: p, password: b.password}
}

// Get retrieves and decrypts value if password is set
func (b *KeyValueBucket) Get(key string) (nats.KeyValueEntry, error) {
	composeKey := b.composeKey(key)
	entry, err := b.kv.Get(composeKey)
	if err != nil {
		return nil, err
	}

	if b.password == nil {
		return entry, nil
	}

	plaintext, err := decrypt(entry.Value(), b.password, b.salt)
	if err != nil {
		return nil, err
	}

	return &secureEntry{
		KeyValueEntry: entry,
		value:         plaintext,
	}, nil
}

// Put encrypts value transparently if password is set
func (b *KeyValueBucket) Put(key string, value []byte) (uint64, error) {
	if b.password != nil {
		enc, err := encrypt(value, b.password, b.salt)
		if err != nil {
			return 0, err
		}
		value = enc
	}
	return b.kv.Put(b.composeKey(key), value)
}

func (b *KeyValueBucket) Create(key string, value []byte) (uint64, error) {
	if b.password != nil {
		enc, err := encrypt(value, b.password, b.salt)
		if err != nil {
			return 0, err
		}
		value = enc
	}
	return b.kv.Create(b.composeKey(key), value)
}

func (b *KeyValueBucket) Update(key string, value []byte, last uint64) (uint64, error) {
	if b.password != nil {
		enc, err := encrypt(value, b.password, b.salt)
		if err != nil {
			return 0, err
		}
		value = enc
	}
	return b.kv.Update(b.composeKey(key), value, last)
}

func (b *KeyValueBucket) Delete(key string, opts ...nats.DeleteOpt) error {
	return b.kv.Delete(b.composeKey(key), opts...)
}

func (b *KeyValueBucket) composeKey(key string) string {
	key = strings.Trim(key, ".")
	if b.prefix == "" {
		return key
	}
	return fmt.Sprintf("%s.%s", b.prefix, key)
}
