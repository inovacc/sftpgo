package bucket

import "errors"

// Errors
var (
	ErrKeyValueConfigRequired = errors.New("nats: config required")
	ErrInvalidBucketName      = errors.New("nats: invalid bucket name")
	ErrInvalidKey             = errors.New("nats: invalid key")
	ErrKeyNotFound            = errors.New("nats: key not found")
	ErrKeyDeleted             = errors.New("nats: key was deleted")
	ErrHistoryToLarge         = errors.New("nats: history limited to a max of 64")
	ErrNoKeysFound            = errors.New("nats: no keys found")
	ErrBucketExists           = errors.New("nats: bucket already exists")
	ErrBadBucket              = errors.New("nats: bucket not valid key-value store")
	ErrBucketNotFound         = errors.New("nats: bucket not found")
	ErrCipherTooShort         = errors.New("crypto: cipher text too short")
	ErrInvalidPassword        = errors.New("auth: invalid password for secure bucket")
	ErrPasswordHashFailed     = errors.New("auth: failed to hash password")
	ErrNonceGeneration        = errors.New("crypto: failed to generate nonce")
	ErrCipherBlockCreate      = errors.New("crypto: failed to create cipher block")
	ErrCipherGCMCreate        = errors.New("crypto: failed to initialize GCM")
	ErrInvalidCipherBlock     = errors.New("crypto: failed to create cipher block")
	ErrCipherGCMCreation      = errors.New("crypto: failed to initialize GCM mode")
)
