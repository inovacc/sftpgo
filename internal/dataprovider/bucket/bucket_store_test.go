package bucket

import (
	"github.com/nats-io/nats.go"
)

var kv nats.KeyValue

//func TestMain(m *testing.M) {
//	nc, err := nats.Connect(nats.DefaultURL)
//	if err != nil {
//		log.Fatal(err)
//	}
//	defer nc.Drain()
//
//	js, err := nc.JetStream()
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	kv, err = js.CreateKeyValue(&nats.KeyValueConfig{
//		BucketStore: "users",
//	})
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	defer cleanupBucket(js, kv.BucketStore())
//
//	os.Exit(m.Run())
//}

// Structure:
// users
// ├── alice                        → viewer
// ├── bob                          → admin
// ├── carlos
// │   ├── email                    → carlos@example.com
// │   └── profile
// │       ├── age                  → 30
// │       └── location             → Madrid
// ├── user1                        → data1
// ├── user2                        → data2
// ├── user3                        → data3
// ├── user4                        → data4
// ├── user5                        → data5
// ├── user6
// │   └── account
// │       ├── params               → some parameters
// │       ├── username             → user6name
// │       └── acl                  → admin
// └── user7
//     └── account (secured)
//         ├── __secure__          → hashed("mysecret")
//         └── params              → some params
// └── evan (secured)
//     ├── email                   → carlos@example.com
//     └── profile
//         ├── age                 → 30
//         └── location            → Madrid
//
//func TestBucket(t *testing.T) {
//	users := CreateKeyValueBucket(kv)
//
//	// ──> alice
//	alice := users.SubBucket("alice")
//	alice.Put("email", []byte("alice@example.com"))
//	alice.Put("role", []byte("admin"))
//
//	// ──> bob
//	bob := users.SubBucket("bob")
//	bob.Put("email", []byte("bob@example.com"))
//	bob.Put("role", []byte("viewer"))
//
//	// ──> carlos
//	carlos := users.SubBucket("carlos")
//	carlos.Put("email", []byte("carlos@example.com"))
//
//	carlosProfile := carlos.SubBucket("profile")
//	carlosProfile.Put("age", []byte("28"))
//	carlosProfile.Put("city", []byte("Valencia"))
//
//	// ──> evan (secure)
//	evan, err := users.SubBucketSecure("evan", "super-secret")
//	if err != nil {
//		log.Fatal("Access denied:", err)
//	}
//	evan.Put("email", []byte("evan@example.com"))
//
//	profile := evan.SubBucket("profile")
//	profile.Put("age", []byte("30"))
//	profile.Put("location", []byte("Madrid"))
//
//	//// Basic flat users
//	//users.Put("alice", []byte("viewer"))
//	//users.Put("bob", []byte("admin"))
//	//
//	//// Nested user: carlos
//	//carlos := users.SubBucket("carlos")
//	//carlos.Put("email", []byte("carlos@example.com"))
//	//
//	//carlosProfile := carlos.SubBucket("profile")
//	//carlosProfile.Put("age", []byte("30"))
//	//carlosProfile.Put("location", []byte("Madrid"))
//	//
//	//// Flat user entries
//	//for i := 1; i <= 5; i++ {
//	//	key := fmt.Sprintf("user%b", rune('0'+i))
//	//	users.Put(key, []byte(fmt.Sprintf("data%b", rune('0'+i))))
//	//}
//	//
//	//// user6 nested fields (not secured)
//	//user6 := users.SubBucket("user6").SubBucket("account")
//	//user6.Put("params", []byte("some parameters"))
//	//user6.Put("username", []byte("user6name"))
//	//user6.Put("acl", []byte("admin"))
//	//
//	//// user7 secured account
//	//account, err := users.SubBucketSecure("user7.account", "mysecret")
//	//if err != nil {
//	//	log.Fatal("Access denied:", err)
//	//}
//	//account.Put("params", []byte("some params"))
//	//
//	//// evan secured and encrypted entries
//	//evan, err := users.SubBucketSecure("evan", "secret-pass")
//	//if err != nil {
//	//	log.Fatal("Access denied:", err)
//	//}
//	//evan.Put("email", []byte("carlos@example.com"))
//	//
//	//evanProfile := evan.SubBucket("profile")
//	//evanProfile.Put("age", []byte("30"))
//	//evanProfile.Put("location", []byte("Madrid"))
//}
//
//func cleanupBucket(js nats.JetStreamContext, bucketName string) {
//	if err := js.DeleteKeyValue(bucketName); err != nil {
//		log.Panicf("Warning: cleanup failed for bucket %s: %v", bucketName, err)
//	}
//}
