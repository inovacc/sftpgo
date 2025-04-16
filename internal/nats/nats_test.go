package nats

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/inovacc/utils/v2/uid"
	"github.com/nats-io/nats.go"
	"log"
	"os"
	"sync"
	"testing"
	"time"
)

const (
	NatsDatabaseVersion = 32
	NatsKvAdmin         = "SFTP_KV_ADMIN"
	NatsKvGroup         = "SFTP_KV_GROUP"
	NatsKvRole          = "SFTP_KV_ROLE"
	NatsKvRule          = "SFTP_KV_RULE"
	NatsKvUser          = "SFTP_KV_USER"
	NatsKvFolder        = "SFTP_KV_FOLDER"
	NatsKvShare         = "SFTP_KV_SHARE"
	NatsKvApiKey        = "SFTP_KV_API_KEY"
	NatsKvEventAction   = "SFTP_KV_EVENT_ACTION"
	NatsKvEventRule     = "SFTP_KV_EVENT_RULE"
	NatsKvNode          = "SFTP_KV_NODE"
	NatsKvTask          = "SFTP_KV_TASK"
	NatsKvTransfer      = "SFTP_KV_TRANSFER"
	NatsKvDefender      = "SFTP_KV_DEFENDER"
	NatsKvIplist        = "SFTP_KV_IPLIST"
	NatsKvSession       = "SFTP_KV_SESSION"
	NatsKvConfig        = "SFTP_KV_CONFIG"
	NatsKvActions       = "SFTP_KV_ACTIONS"
	NatsKvSchemaVersion = "SFTP_KV_SCHEMA_VERSION"
	NatsKvBucketVersion = "SFTP_KV_BUCKET_VERSION"
	NatsKvDbVersion     = "SFTP_KV_DB_VERSION"
	usersBucketNATS     = "users"
	groupsBucketNATS    = "groups"
	foldersBucketNATS   = "folders"
	adminsBucketNATS    = "admins"
	apiKeysBucketNATS   = "api_keys"
	sharesBucketNATS    = "shares"
	actionsBucketNATS   = "events_actions"
	rulesBucketNATS     = "events_rules"
	rolesBucketNATS     = "roles"
	ipListsBucketNATS   = "ip_lists"
	configsBucketNATS   = "configs"
	dbVersionBucketNATS = "db_version"
	dbVersionKeyNATS    = "version"
	configsKeyNATS      = "configs"
)

var (
	testObj   testStruct
	bucketsKv = make(map[string]nats.KeyValue)
	buckets   = make(map[string]*nats.KeyValueConfig)
)

func init() {
	bucketNames := []string{
		NatsKvAdmin, NatsKvGroup, NatsKvRole, NatsKvRule, NatsKvUser, NatsKvFolder, NatsKvShare, NatsKvApiKey,
		NatsKvEventAction, NatsKvEventRule, NatsKvNode, NatsKvTask, NatsKvTransfer, NatsKvDefender, NatsKvIplist,
		NatsKvSession, NatsKvConfig, NatsKvActions, NatsKvSchemaVersion, NatsKvBucketVersion, NatsKvDbVersion,
		//usersBucketNATS, groupsBucketNATS, foldersBucketNATS, adminsBucketNATS, apiKeysBucketNATS, sharesBucketNATS,
		//actionsBucketNATS, rulesBucketNATS, rolesBucketNATS, ipListsBucketNATS, configsBucketNATS,
		//dbVersionBucketNATS, dbVersionKeyNATS, configsKeyNATS,
	}

	for _, name := range bucketNames {
		buckets[name] = &nats.KeyValueConfig{
			Bucket:      name,
			Storage:     nats.FileStorage,
			Compression: true,
		}
	}
}

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

	include := &nats.KeyValueConfig{
		Compression: true,
		Storage:     nats.FileStorage,
		TTL:         time.Hour * 24,
	}

	newBulkInit := NewBulkInit(testObj.js)
	if err := newBulkInit.Init(buckets, include, bucketsKv); err != nil {
		log.Fatalf("Error inserting bucket metadata")
	}

	os.Exit(m.Run())
}

func TestWatchAndSyncTyped(t *testing.T) {
	userFactory := func() *user {
		return &user{}
	}

	fn := func(u *user) (*user, error) {
		if u.Username == "" {
			u.Username = "john"
			u.Email = "init@example.com"
		} else {
			u.Email = "updated2@example.com"
		}
		return u, nil
	}

	if err := SafeWriteTyped[*user](bucketsKv[NatsKvUser], "users.john", userFactory, fn); err != nil {
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
	key := uid.GenerateUUID()

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
