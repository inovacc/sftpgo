package bucket

import (
	"errors"
	"github.com/inovacc/utils/v2/uid"
	"github.com/nats-io/nats.go"
)

type UserStore struct {
	root *KeyValueBucket
	js   nats.JetStreamContext
}

func NewUserStore(js nats.JetStreamContext) (*UserStore, error) {
	kv, err := js.CreateKeyValue(&nats.KeyValueConfig{Bucket: "users"})
	if err != nil && !errors.Is(err, ErrBucketExists) {
		return nil, err
	}

	if errors.Is(err, ErrBucketExists) {
		kv, err = js.KeyValue("users")
		if err != nil {
			return nil, err
		}
	}

	return &UserStore{
		root: CreateKeyValueBucket(kv),
		js:   js,
	}, nil
}

func (u *UserStore) CreateUser(name string) (*KeyValueBucket, string, error) {
	id := uid.GenerateKSUID() //K-Sortable Unique Identifier
	kv, err := u.js.CreateKeyValue(&nats.KeyValueConfig{Bucket: id})
	if err != nil {
		return nil, "", err
	}

	if _, err := u.root.Put(name, []byte(id)); err != nil {
		return nil, "", err
	}
	return CreateKeyValueBucket(kv), id, nil
}

func (u *UserStore) GetUser(name string) (*KeyValueBucket, string, error) {
	entry, err := u.root.Get(name)
	if err != nil {
		return nil, "", err
	}

	bucketName := string(entry.Value())
	kv, err := u.js.KeyValue(bucketName)
	if err != nil {
		return nil, "", err
	}
	return CreateKeyValueBucket(kv), bucketName, nil
}

func (u *UserStore) GetUserSecure(name, password string) (*KeyValueBucket, string, error) {
	entry, err := u.root.Get(name)
	if err != nil {
		return nil, "", err
	}

	bucketName := string(entry.Value())
	kv, err := u.js.KeyValue(bucketName)
	if err != nil {
		return nil, "", err
	}
	bucket := CreateKeyValueBucket(kv)
	sub, err := bucket.SubBucketSecure("", password)
	return sub, bucketName, err
}
