package dataprovider

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"reflect"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

type StdLogger struct {
	log *slog.Logger
}

func NewStdLogger() StdLogger {
	jsonHandler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level:     slog.LevelDebug,
		AddSource: false,
	})
	logger := slog.New(jsonHandler)
	slog.SetDefault(logger)
	return StdLogger{log: logger}
}

func (l StdLogger) Debug(msg string, args ...any) { l.log.Debug(msg, args...) }
func (l StdLogger) Info(msg string, args ...any)  { l.log.Info(msg, args...) }
func (l StdLogger) Warn(msg string, args ...any)  { l.log.Warn(msg, args...) }
func (l StdLogger) Error(msg string, args ...any) { l.log.Error(msg, args...) }

var (
	ErrBucketNotFound     = errors.New("bucket not found")
	ErrKeyAlreadyExists   = errors.New("key already exists")
	ErrMaxRetriesExceeded = errors.New("max retries reached")
	ErrKeyNotFound        = errors.New("key not found")
)

type Logger interface {
	Debug(msg string, args ...any)
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
}

type NatsCoreConfig struct {
	JS           nats.JetStreamContext
	MaxRetries   int
	RetryDelay   time.Duration
	StorageNames []string
	Logger       *slog.Logger
}

type NatsCore struct {
	js         nats.JetStreamContext
	kvStore    map[string]nats.KeyValue
	mu         sync.RWMutex
	maxRetries int
	retryDelay time.Duration
	log        *slog.Logger
}

func NewNatsCore(config *NatsCoreConfig) (*NatsCore, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}
	if config.Logger == nil {
		config.Logger = NewStdLogger().log
	}
	core := &NatsCore{
		js:         config.JS,
		kvStore:    make(map[string]nats.KeyValue),
		maxRetries: config.MaxRetries,
		retryDelay: config.RetryDelay,
		log:        config.Logger,
	}
	if err := core.initializeStorages(config.StorageNames); err != nil {
		return nil, err
	}
	return core, nil
}

func (c *NatsCoreConfig) Validate() error {
	if c.JS == nil {
		return errors.New("JetStream context is required")
	}
	if c.MaxRetries < 0 {
		return errors.New("max retries must be non-negative")
	}
	if c.RetryDelay < 0 {
		return errors.New("retry delay must be non-negative")
	}
	if len(c.StorageNames) == 0 {
		return errors.New("at least one storage name is required")
	}
	return nil
}

func (p *NatsCore) initializeStorages(storageNames []string) error {
	var errs []error
	for _, name := range storageNames {
		subBucket, err := p.CreateBucket(name)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to create bucket %q: %w", name, err))
			continue
		}
		p.kvStore[name] = subBucket
		p.log.Info("initialized bucket", "bucket", name)
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

func (p *NatsCore) getBucket(bucket string) (nats.KeyValue, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	kv, ok := p.kvStore[bucket]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrBucketNotFound, bucket)
	}
	return kv, nil
}

func (p *NatsCore) marshalItem(item Wrapper, key string) ([]byte, error) {
	data, err := item.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("marshal item for key %q: %w", key, err)
	}
	p.log.Debug("marshal item", "key", key, "data", string(data))
	return data, nil
}

func (p *NatsCore) unmarshalItem(data []byte, item Wrapper, key, bucket string) error {
	p.log.Debug("unmarshal item", "bucket", bucket, "key", key, "data", string(data))
	if err := item.UnmarshalJSON(data); err != nil {
		return fmt.Errorf("unmarshal key %q in bucket %q: %w", key, bucket, err)
	}
	return nil
}

func (p *NatsCore) CreateBucket(bucket string) (nats.KeyValue, error) {
	kv, err := p.js.CreateKeyValue(&nats.KeyValueConfig{Bucket: bucket, Compression: true})
	if err != nil && !errors.Is(err, jetstream.ErrBucketExists) {
		p.log.Error("create bucket failed",
			"bucket", bucket,
			"error", err)
		return nil, err
	}
	if errors.Is(err, jetstream.ErrBucketExists) {
		p.log.Info("bucket already exists", "bucket", bucket)
		return p.js.KeyValue(bucket)
	}
	p.log.Info("bucket created", "bucket", bucket)
	return kv, nil
}

func (p *NatsCore) DeleteBucket(bucket string) error {
	return p.js.DeleteKeyValue(bucket)
}

func (p *NatsCore) PutItem(bucket, key string, item Wrapper) (uint64, error) {
	kv, err := p.getBucket(bucket)
	if err != nil {
		return 0, err
	}
	data, err := p.marshalItem(item, key)
	if err != nil {
		return 0, err
	}
	revision, err := kv.Put(key, data)
	if err != nil {
		return 0, fmt.Errorf("put key %q in bucket %q: %w", key, bucket, err)
	}
	return revision, nil
}

func (p *NatsCore) GetItem(bucket, key string, item Wrapper) (uint64, error) {
	kv, err := p.getBucket(bucket)
	if err != nil {
		return 0, err
	}
	entry, err := kv.Get(key)
	if err != nil {
		return 0, fmt.Errorf("%w: key %q in bucket %q", ErrKeyNotFound, key, bucket)
	}
	if err := p.unmarshalItem(entry.Value(), item, key, bucket); err != nil {
		return 0, err
	}
	return entry.Revision(), nil
}

func (p *NatsCore) DeleteItem(bucket, key string) error {
	kv, err := p.getBucket(bucket)
	if err != nil {
		return err
	}
	if err := kv.Delete(key); err != nil {
		return fmt.Errorf("delete key %q in bucket %q: %w", key, bucket, err)
	}
	p.log.Info("item deleted", "bucket", bucket, "key", key)
	return nil
}

func (p *NatsCore) CreateItem(bucket, key string, item Wrapper) (uint64, error) {
	kv, err := p.getBucket(bucket)
	if err != nil {
		return 0, err
	}
	data, err := p.marshalItem(item, key)
	if err != nil {
		return 0, err
	}
	revision, err := kv.Create(key, data)
	if err != nil && errors.Is(err, nats.ErrKeyExists) {
		return 0, fmt.Errorf("%w: key %q in bucket %q", ErrKeyAlreadyExists, key, bucket)
	}
	return revision, err
}

func (p *NatsCore) GetAllItems(bucket string) ([][]byte, error) {
	kv, err := p.getBucket(bucket)
	if err != nil {
		return nil, err
	}
	keyList, err := kv.ListKeys()
	if err != nil {
		return nil, fmt.Errorf("list keys in bucket %q: %w", bucket, err)
	}
	var items [][]byte
	for key := range keyList.Keys() {
		entry, err := kv.Get(key)
		if err != nil {
			return nil, fmt.Errorf("get key %q in bucket %q: %w", key, bucket, err)
		}
		items = append(items, entry.Value())
	}
	p.log.Debug("get all items", "bucket", bucket, "items", items)
	return items, nil
}

func (p *NatsCore) UpdateItem(bucket, key string, item Wrapper) error {
	kv, err := p.getBucket(bucket)
	if err != nil {
		return err
	}
	clone := item.Clone()
	if clone == nil {
		return fmt.Errorf("failed to clone item for key %q", key)
	}
	data, err := p.marshalItem(item, key)
	if err != nil {
		return err
	}
	for attempt := 0; attempt < p.maxRetries; attempt++ {
		sequence, err := p.GetItem(bucket, key, clone)
		switch {
		case errors.Is(err, nats.ErrKeyNotFound):
			return fmt.Errorf("key %q not found: %w", key, err)
		case err != nil:
			return fmt.Errorf("failed to get key %q: %w", key, err)
		}
		if reflect.DeepEqual(clone.Get(), item.Get()) {
			return nil // No changes needed
		}
		if _, err = kv.Update(key, data, sequence); err == nil {
			return nil
		}
		if errors.Is(err, nats.ErrKeyExists) {
			p.log.Warn("key conflict, retrying", "key", key, "attempt", attempt)
			time.Sleep(p.retryDelay)
			continue
		}
		return fmt.Errorf("failed to update key %q: %w", key, err)
	}
	return fmt.Errorf("%w for key %q", ErrMaxRetriesExceeded, key)
}

func (p *NatsCore) ListItems(bucket string) ([]string, error) {
	kv, err := p.getBucket(bucket)
	if err != nil {
		return nil, err
	}
	keyList, err := kv.ListKeys()
	if err != nil {
		return nil, fmt.Errorf("list keys in bucket %q: %w", bucket, err)
	}
	result := make([]string, 0, 100)
	for key := range keyList.Keys() {
		result = append(result, key)
	}
	p.log.Debug("list items", "bucket", bucket, "keys", result)
	return result, nil
}

func (p *NatsCore) PurgeBucket(bucket string) error {
	kv, err := p.getBucket(bucket)
	if err != nil {
		return err
	}
	if err := kv.Purge(bucket); err != nil {
		return fmt.Errorf("purge bucket %q: %w", bucket, err)
	}
	p.log.Info("bucket purged", "bucket", bucket)
	return nil
}
