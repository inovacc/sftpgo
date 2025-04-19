// Copyright (C) 2019 Nicola Murino
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

// //go:build nats

package dataprovider

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/util"
	"github.com/drakkan/sftpgo/v2/internal/version"
	"github.com/drakkan/sftpgo/v2/internal/vfs"
	"github.com/inovacc/wrapper"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

const (
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
)

func init() {
	version.AddFeature("+nats")
}

type NATSProvider struct {
	js      nats.JetStreamContext
	ctx     context.Context
	cancel  context.CancelFunc
	kvStore map[string]nats.KeyValue
	mu      sync.RWMutex // For thread safety

	// Configuration
	maxRetries int
	retryDelay time.Duration
}

func initializeNATSProvider() error {
	url, err := getNATSConnectionString(false)
	if err != nil {
		providerLog(logger.LevelError, "error creating nats database handler, connection string: %q, error: %v", url, err)
		return err
	}

	opts, err := getNATSOptions()
	if err != nil {
		return err
	}

	nc, err := nats.Connect(url, opts...)
	if err != nil {
		providerLog(logger.LevelError, "error creating nats database handler, connection string: %q, error: %v", url, err)
		return err
	}

	js, err := nc.JetStream()
	if err != nil {
		providerLog(logger.LevelError, "error creating nats database handler, connection string: %q, error: %v", url, err)
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	db := &NATSProvider{
		js:         js,
		ctx:        ctx,
		cancel:     cancel,
		kvStore:    make(map[string]nats.KeyValue),
		maxRetries: 3,
		retryDelay: 10,
		mu:         sync.RWMutex{},
	}

	go func() {
		defer db.cancel()
		<-ctx.Done()
		cancel()
	}()

	storageNames := []string{
		usersBucketNATS, groupsBucketNATS, foldersBucketNATS, adminsBucketNATS, apiKeysBucketNATS, sharesBucketNATS,
		actionsBucketNATS, rulesBucketNATS, rolesBucketNATS, ipListsBucketNATS, configsBucketNATS, dbVersionBucketNATS,
		dbVersionKeyNATS,
	}

	for _, name := range storageNames {
		subBucket, err := db.createBucket(js, name)
		if err != nil {
			providerLog(logger.LevelError, "error creating nats database handler, bucket %q, error: %v", name, err)
			continue
		}
		db.kvStore[name] = subBucket
	}

	providerLog(logger.LevelDebug, "nats key store handle created")

	provider = db
	return err
}

func getNATSOptions() ([]nats.Option, error) {
	var opts []nats.Option

	tlsConfig := &tls.Config{}

	if config.RootCert != "" {
		rootCAs, err := x509.SystemCertPool()
		if err != nil {
			rootCAs = x509.NewCertPool()
		}
		rootCrt, err := os.ReadFile(config.RootCert)
		if err != nil {
			return nil, fmt.Errorf("unable to load root certificate %q: %w", config.RootCert, err)
		}
		if !rootCAs.AppendCertsFromPEM(rootCrt) {
			return nil, fmt.Errorf("unable to parse root certificate %q", config.RootCert)
		}
		tlsConfig.RootCAs = rootCAs
	}

	if config.ClientCert != "" && config.ClientKey != "" {
		cert, err := tls.LoadX509KeyPair(config.ClientCert, config.ClientKey)
		if err != nil {
			return nil, fmt.Errorf("unable to load key pair %q, %q: %w", config.ClientCert, config.ClientKey, err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	if config.SSLMode == 2 || config.SSLMode == 3 {
		tlsConfig.InsecureSkipVerify = true
	}

	if !filepath.IsAbs(config.Host) && !config.DisableSNI {
		tlsConfig.ServerName = config.Host
	}

	providerLog(logger.LevelInfo,
		"registering custom TLS config, root cert %q, client cert %q, client key %q, disable SNI? %v",
		config.RootCert, config.ClientCert, config.ClientKey, config.DisableSNI)

	opts = append(opts, nats.Secure(tlsConfig))
	return opts, nil
}

func getNATSConnectionString(redactedPwd bool) (string, error) {
	username := config.Username
	password := config.Password

	if redactedPwd && password != "" {
		password = "[redacted]"
	}

	host := config.Host
	port := config.Port

	userInfo := ""
	if username != "" {
		userInfo = username
		if password != "" {
			userInfo += ":" + password
		}
		userInfo += "@"
	}

	return fmt.Sprintf("nats://%s%s:%d", userInfo, host, port), nil
}

// core components

func (p *NATSProvider) createBucket(js nats.JetStreamContext, bucket string) (nats.KeyValue, error) {
	kv, err := js.CreateKeyValue(&nats.KeyValueConfig{
		Bucket:      bucket,
		Compression: true,
	})

	if err != nil && !errors.Is(err, jetstream.ErrBucketExists) {
		return nil, err
	}

	if errors.Is(err, jetstream.ErrBucketExists) {
		kv, err = js.KeyValue(bucket)
		if err != nil {
			return nil, err
		}
	}
	return kv, nil
}

func (p *NATSProvider) fetchKeys(ctx context.Context, kv nats.KeyValue, keysChan chan<- string, errChan chan<- error) {
	defer close(keysChan)

	keyList, err := kv.ListKeys()
	if err != nil {
		errChan <- err
		return
	}

	for key := range keyList.Keys() {
		select {
		case keysChan <- key:
		case <-ctx.Done():
			return
		}
	}
}

func (p *NATSProvider) putItem(bucket string, key string, item wrapper.Wrapper) error {
	kv, ok := p.kvStore[bucket]
	if !ok {
		return fmt.Errorf("bucket %q not found", bucket)
	}

	data, err := item.MarshalJSON()
	if err != nil {
		return fmt.Errorf("marshal item for key %q: %w", key, err)
	}

	if _, err = kv.Put(key, data); err != nil {
		return fmt.Errorf("put key %q in bucket %q: %w", key, bucket, err)
	}
	return nil
}

func (p *NATSProvider) getItem(bucket string, key string, item wrapper.Wrapper) error {
	kv, ok := p.kvStore[bucket]
	if !ok {
		return fmt.Errorf("bucket %q not found", bucket)
	}

	entry, err := kv.Get(key)
	if err != nil {
		return fmt.Errorf("getItem key %q in bucket %q: %w", key, bucket, err)
	}

	if err := item.UnmarshalJSON(entry.Value()); err != nil {
		return fmt.Errorf("unmarshal key %q in bucket %q: %w", key, bucket, err)
	}
	return nil
}

func (p *NATSProvider) deleteItem(bucket, key string) error {
	kv, ok := p.kvStore[bucket]
	if !ok {
		return fmt.Errorf("bucket %q not found", bucket)
	}

	if err := kv.Delete(key); err != nil {
		return fmt.Errorf("delete key %q in bucket %q: %w", key, bucket, err)
	}
	return nil
}

func (p *NATSProvider) listItem(bucket string) ([]string, error) {
	kv, ok := p.kvStore[bucket]
	if !ok {
		return nil, fmt.Errorf("bucket %q not found", bucket)
	}

	keyList, err := kv.ListKeys()
	if err != nil {
		return nil, fmt.Errorf("list keys in bucket %q: %w", bucket, err)
	}

	var result []string
	for key := range keyList.Keys() {
		result = append(result, key)
	}
	return result, nil
}

func (p *NATSProvider) getAllItems(bucketName string) ([][]byte, error) {
	kv, ok := p.kvStore[bucketName]
	if !ok {
		return nil, fmt.Errorf("bucket %q not found", bucketName)
	}

	keyList, err := kv.ListKeys()
	if err != nil {
		return nil, fmt.Errorf("list keys in bucket %q: %w", bucketName, err)
	}

	var items [][]byte
	for key := range keyList.Keys() {
		entry, err := kv.Get(key)
		if err != nil {
			return nil, fmt.Errorf("getItem key %q in bucket %q: %w", key, bucketName, err)
		}
		items = append(items, entry.Value())
	}
	return items, nil
}

func (p *NATSProvider) safeWrite(bucket string, key string, item wrapper.Wrapper, modifyFn func(wrapper.Wrapper) error) error {
	kv, ok := p.kvStore[bucket]
	if !ok {
		return fmt.Errorf("bucket %q not found", bucket)
	}

	for attempt := 0; attempt < 3; attempt++ {
		entry, err := kv.Get(key)
		switch {
		case errors.Is(err, nats.ErrKeyNotFound):
			// For new entries, apply modifications to the provided item
			if err := modifyFn(item); err != nil {
				return err
			}

			data, err := item.MarshalJSON()
			if err != nil {
				return fmt.Errorf("marshal data for key %q: %w", key, err)
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
			return fmt.Errorf("failed to getItem key %q: %w", key, err)
		}

		// For existing entries, unmarshal the current value first
		if err := item.UnmarshalJSON(entry.Value()); err != nil {
			return fmt.Errorf("unmarshal existing data for key %q: %w", key, err)
		}

		if err := modifyFn(item); err != nil {
			return err
		}

		data, err := item.MarshalJSON()
		if err != nil {
			return fmt.Errorf("marshal updated data for key %q: %w", key, err)
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

func (p *NATSProvider) watchAndSync(ctx context.Context, bucketName, prefix string, skipHistory bool, syncFn func(key string, val []byte)) error {
	kv, ok := p.kvStore[bucketName]
	if !ok {
		return fmt.Errorf("bucket %q not found", bucketName)
	}

	var opts []nats.WatchOpt
	if skipHistory {
		opts = append(opts, nats.UpdatesOnly())
	}

	watcher, err := kv.Watch(fmt.Sprintf("%s>", prefix), opts...)
	if err != nil {
		return fmt.Errorf("unable to start KV watch: %w", err)
	}

	go func() {
		defer func(watcher nats.KeyWatcher) {
			if err := watcher.Stop(); err != nil {
				providerLog(logger.LevelError, "failed to stop KV watcher: %v", err)
			}
		}(watcher)
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

// core components

func (p *NATSProvider) checkAvailability() error {
	wVersion := wrapper.NewWrapper(schemaVersion{})
	return p.getItem(dbVersionBucketNATS, dbVersionKeyNATS, wVersion)
}

func (p *NATSProvider) validateUserAndPass(username, password, ip, protocol string) (User, error) {
	user, err := p.userExists(username, "")
	if err != nil {
		providerLog(logger.LevelWarn, "error authenticating user %q: %v", username, err)
		return user, err
	}
	return checkUserAndPass(&user, password, ip, protocol)
}

func (p *NATSProvider) validateUserAndPubKey(username string, pubKey []byte, isSSHCert bool) (User, string, error) {
	if len(pubKey) == 0 {
		return User{}, "", errors.New("credentials cannot be null or empty")
	}

	user, err := p.userExists(username, "")
	if err != nil {
		providerLog(logger.LevelWarn, "error authenticating user %q: %v", username, err)
		return User{}, "", err
	}
	return checkUserAndPubKey(&user, pubKey, isSSHCert)
}

func (p *NATSProvider) updateAPIKeyLastUse(keyID string) error {
	bucket, err := p.getAPIKeysBucket()
	if err != nil {
		return err
	}

	entry, err := bucket.Get(keyID)
	if err != nil {
		return util.NewRecordNotFoundError(fmt.Sprintf("key %q does not exist, unable to update last use", keyID))
	}

	wAPIKey := wrapper.NewWrapper(APIKey{})
	if err = wAPIKey.UnmarshalJSON(entry.Value()); err != nil {
		return err
	}

	apiKey := wAPIKey.Get()
	apiKey.LastUseAt = util.GetTimeAsMsSinceEpoch(time.Now())
	wAPIKey.Set(apiKey)

	data, err := wAPIKey.MarshalJSON()
	if err != nil {
		return err
	}

	if _, err = bucket.Update(keyID, data, entry.Revision()); err != nil {
		providerLog(logger.LevelWarn, "error updating last use for key %q: %v", keyID, err)
		return err
	}

	providerLog(logger.LevelDebug, "last use updated for key %q", keyID)
	return nil
}

func (p *NATSProvider) getAdminSignature(username string) (string, error) {
	bucket, err := p.getAdminsBucket()
	if err != nil {
		return "", err
	}

	entry, err := bucket.Get(username)
	if err != nil {
		return "", err
	}

	wAdmin := wrapper.NewWrapper(Admin{})
	if err = wAdmin.UnmarshalJSON(entry.Value()); err != nil {
		return "", err
	}

	admin := wAdmin.Get()
	return strconv.FormatInt(admin.UpdatedAt, 10), nil
}

func (p *NATSProvider) getUserSignature(username string) (string, error) {
	bucket, err := p.getUsersBucket()
	if err != nil {
		return "", err
	}

	entry, err := bucket.Get(username)
	if err != nil {
		return "", err
	}

	wUser := wrapper.NewWrapper(User{})
	if err = wUser.UnmarshalJSON(entry.Value()); err != nil {
		return "", err
	}

	user := wUser.Get()
	return strconv.FormatInt(user.UpdatedAt, 10), nil
}

func (p *NATSProvider) setUpdatedAt(username string) {
	bucket, err := p.getUsersBucket()
	if err != nil {
		return
	}

	entry, err := bucket.Get(username)
	if err != nil {
		return
	}

	wUser := wrapper.NewWrapper(User{})
	if err = wUser.UnmarshalJSON(entry.Value()); err != nil {
		return
	}

	user := wUser.Get()
	user.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
	wUser.Set(user)

	data, err := wUser.MarshalJSON()
	if err != nil {
		return
	}

	if _, err = bucket.Update(username, data, entry.Revision()); err != nil {
		providerLog(logger.LevelWarn, "error updating last use for key %q: %v", username, err)
		return
	}
	setLastUserUpdate()
}

func (p *NATSProvider) updateLastLogin(username string) error {
	bucket, err := p.getUsersBucket()
	if err != nil {
		return err
	}

	entry, err := bucket.Get(username)
	if err != nil {
		return err
	}

	wUser := wrapper.NewWrapper(User{})
	if err = wUser.UnmarshalJSON(entry.Value()); err != nil {
		return err
	}

	user := wUser.Get()
	user.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
	wUser.Set(user)

	data, err := wUser.MarshalJSON()
	if err != nil {
		return err
	}

	if _, err = bucket.Update(username, data, entry.Revision()); err != nil {
		providerLog(logger.LevelWarn, "error updating last use for key %q: %v", username, err)
		return err
	}
	return nil
}

func (p *NATSProvider) updateAdminLastLogin(username string) error {
	bucket, err := p.getAdminsBucket()
	if err != nil {
		return err
	}

	entry, err := bucket.Get(username)
	if err != nil {
		return err
	}

	wAdmin := wrapper.NewWrapper(Admin{})
	if err = wAdmin.UnmarshalJSON(entry.Value()); err != nil {
		return err
	}

	admin := wAdmin.Get()
	admin.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
	wAdmin.Set(admin)

	data, err := wAdmin.MarshalJSON()
	if err != nil {
		return err
	}

	if _, err = bucket.Update(username, data, entry.Revision()); err != nil {
		providerLog(logger.LevelWarn, "error updating last use for key %q: %v", username, err)
		return err
	}
	return nil
}

func (p *NATSProvider) updateTransferQuota(username string, uploadSize, downloadSize int64, reset bool) error {
	bucket, err := p.getUsersBucket()
	if err != nil {
		return err
	}

	entry, err := bucket.Get(username)
	if err != nil {
		return util.NewRecordNotFoundError(fmt.Sprintf("username %q does not exist, unable to update transfer quota", username))
	}

	wUser := wrapper.NewWrapper(User{})
	if err = wUser.UnmarshalJSON(entry.Value()); err != nil {
		return err
	}

	user := wUser.Get()
	if !reset {
		user.UsedUploadDataTransfer += uploadSize
		user.UsedDownloadDataTransfer += downloadSize
	} else {
		user.UsedUploadDataTransfer = uploadSize
		user.UsedDownloadDataTransfer = downloadSize
	}
	user.LastQuotaUpdate = util.GetTimeAsMsSinceEpoch(time.Now())
	wUser.Set(user)

	data, err := wUser.MarshalJSON()
	if err != nil {
		return err
	}

	if _, err = bucket.Update(username, data, entry.Revision()); err != nil {
		providerLog(logger.LevelDebug, "error updating transfer quota for user %q: %v", username, err)
		return err
	}

	providerLog(logger.LevelDebug, "transfer quota updated for user %q, ul increment: %v dl increment: %v is reset? %v", username, uploadSize, downloadSize, reset)
	return nil
}

func (p *NATSProvider) updateQuota(username string, filesAdd int, sizeAdd int64, reset bool) error {
	bucket, err := p.getUsersBucket()
	if err != nil {
		return err
	}

	entry, err := bucket.Get(username)
	if err != nil {
		return util.NewRecordNotFoundError(fmt.Sprintf("username %q does not exist, unable to update quota", username))
	}

	wUser := wrapper.NewWrapper(User{})
	if err = wUser.UnmarshalJSON(entry.Value()); err != nil {
		return err
	}

	user := wUser.Get()
	if reset {
		user.UsedQuotaSize = sizeAdd
		user.UsedQuotaFiles = filesAdd
	} else {
		user.UsedQuotaSize += sizeAdd
		user.UsedQuotaFiles += filesAdd
	}
	user.LastQuotaUpdate = util.GetTimeAsMsSinceEpoch(time.Now())
	wUser.Set(user)

	data, err := wUser.MarshalJSON()
	if err != nil {
		return err
	}

	if _, err = bucket.Update(username, data, entry.Revision()); err != nil {
		providerLog(logger.LevelDebug, "error updating quota for user %q: %v", username, err)
		return err
	}

	providerLog(logger.LevelDebug, "quota updated for user %q, files increment: %v size increment: %v is reset? %v", username, filesAdd, sizeAdd, reset)
	return nil
}

func (p *NATSProvider) getUsedQuota(username string) (int, int64, int64, int64, error) {
	user, err := p.userExists(username, "")
	if err != nil {
		providerLog(logger.LevelError, "unable to get quota for user %v error: %v", username, err)
		return 0, 0, 0, 0, err
	}
	return user.UsedQuotaFiles, user.UsedQuotaSize, user.UsedUploadDataTransfer, user.UsedDownloadDataTransfer, err
}

func (p *NATSProvider) adminExists(username string) (Admin, error) {
	bucket, err := p.getAdminsBucket()
	if err != nil {
		return Admin{}, err
	}

	entry, err := bucket.Get(username)
	if err != nil {
		return Admin{}, util.NewRecordNotFoundError(fmt.Sprintf("admin %v does not exist", username))
	}

	wAdmin := wrapper.NewWrapper(Admin{})
	if err = wAdmin.UnmarshalJSON(entry.Value()); err != nil {
		return Admin{}, err
	}

	return wAdmin.Get(), nil
}

func (p *NATSProvider) addAdmin(admin *Admin) error {
	if err := admin.validate(); err != nil {
		return err
	}

	bucket, err := p.getAdminsBucket()
	if err != nil {
		return err
	}

	entry, err := bucket.Get(admin.Username)
	if err != nil {
		return util.NewI18nError(fmt.Errorf("%w: admin %q already exists", ErrDuplicatedKey, admin.Username), util.I18nErrorDuplicatedUsername)
	}

	groupBucket, err := p.getGroupsBucket()
	if err != nil {
		return err
	}

	rolesBucket, err := p.getRolesBucket()
	if err != nil {
		return err
	}

	admin.ID = time.Now().UnixNano()
	admin.LastLogin = 0
	admin.CreatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
	admin.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())

	sort.Slice(admin.Groups, func(i, j int) bool {
		return admin.Groups[i].Name < admin.Groups[j].Name
	})

	for idx := range admin.Groups {
		if err = p.addAdminToGroupMapping(admin.Username, admin.Groups[idx].Name, groupBucket); err != nil {
			return err
		}
	}

	if err = p.addAdminToRole(admin.Username, admin.Role, rolesBucket); err != nil {
		return err
	}

	wAdmin := wrapper.NewWrapper(Admin{})
	data, err := wAdmin.MarshalJSON()
	if err != nil {
		return err
	}

	if _, err = bucket.Update(admin.Username, data, entry.Revision()); err != nil {
		providerLog(logger.LevelDebug, "error updating quota for user %q: %v", admin.Username, err)
		return err
	}
	return nil
}

func (p *NATSProvider) updateAdmin(admin *Admin) error {
	if err := admin.validate(); err != nil {
		return err
	}

	bucket, err := p.getAdminsBucket()
	if err != nil {
		return err
	}

	entry, err := bucket.Get(admin.Username)
	if err != nil {
		return util.NewRecordNotFoundError(fmt.Sprintf("admin %v does not exist", admin.Username))
	}

	wOldAdmin := wrapper.NewWrapper(Admin{})
	if err = wOldAdmin.UnmarshalJSON(entry.Value()); err != nil {
		return err
	}

	oldAdmin := wOldAdmin.Get()

	groupBucket, err := p.getGroupsBucket()
	if err != nil {
		return err
	}

	rolesBucket, err := p.getRolesBucket()
	if err != nil {
		return err
	}

	if err = p.removeAdminFromRole(oldAdmin.Username, oldAdmin.Role, rolesBucket); err != nil {
		return err
	}

	for idx := range oldAdmin.Groups {
		if err = p.removeAdminFromGroupMapping(oldAdmin.Username, oldAdmin.Groups[idx].Name, groupBucket); err != nil {
			return err
		}
	}

	if err = p.addAdminToRole(admin.Username, admin.Role, rolesBucket); err != nil {
		return err
	}

	sort.Slice(admin.Groups, func(i, j int) bool {
		return admin.Groups[i].Name < admin.Groups[j].Name
	})

	for idx := range admin.Groups {
		if err = p.addAdminToGroupMapping(admin.Username, admin.Groups[idx].Name, groupBucket); err != nil {
			return err
		}
	}

	admin.ID = oldAdmin.ID
	admin.CreatedAt = oldAdmin.CreatedAt
	admin.LastLogin = oldAdmin.LastLogin
	admin.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())

	wAdmin := wrapper.NewWrapper(*admin)
	data, err := wAdmin.MarshalJSON()
	if err != nil {
		return err
	}

	_, err = bucket.Update(admin.Username, data, entry.Revision())
	return err
}

func (p *NATSProvider) deleteAdmin(admin Admin) error {
	bucket, err := p.getAdminsBucket()
	if err != nil {
		return err
	}

	entry, err := bucket.Get(admin.Username)
	if err != nil {
		return util.NewRecordNotFoundError(fmt.Sprintf("admin %v does not exist", admin.Username))
	}

	wOldAdmin := wrapper.NewWrapper(Admin{})
	if err = wOldAdmin.UnmarshalJSON(entry.Value()); err != nil {
		return err
	}

	oldAdmin := wOldAdmin.Get()

	if len(oldAdmin.Groups) > 0 {
		groupBucket, err := p.getGroupsBucket()
		if err != nil {
			return err
		}
		for idx := range oldAdmin.Groups {
			if err = p.removeAdminFromGroupMapping(oldAdmin.Username, oldAdmin.Groups[idx].Name, groupBucket); err != nil {
				return err
			}
		}
	}

	if oldAdmin.Role != "" {
		rolesBucket, err := p.getRolesBucket()
		if err != nil {
			return err
		}

		if err = p.removeAdminFromRole(oldAdmin.Username, oldAdmin.Role, rolesBucket); err != nil {
			return err
		}
	}

	if err := p.deleteRelatedAPIKey(admin.Username, APIKeyScopeAdmin); err != nil {
		return err
	}

	return bucket.Delete(admin.Username)
}

// func (p *NATSProvider) natsGetUserByUsernameQuery(role string) string {
//
// 	if role == "" {
// 		return fmt.Sprintf(`SELECT %s FROM %s u LEFT JOIN %s r on r.id = u.role_id WHERE u.username = %s AND u.deleted_at = 0`,
// 			selectUserFields, sqlTableUsers, sqlTableRoles, sqlPlaceholders[0])
// 	}
// 	return fmt.Sprintf(`SELECT %s FROM %s u LEFT JOIN %s r on r.id = u.role_id WHERE u.username = %s AND u.deleted_at = 0
// 		AND u.role_id is NOT NULL AND r.name = %s`,
// 		selectUserFields, sqlTableUsers, sqlTableRoles, sqlPlaceholders[0], sqlPlaceholders[1])
// }
//
// func (p *NATSProvider) validateUserAndTLSCert(username, protocol string, tlsCert *x509.Certificate) (User, error) {
// 	return sqlCommonValidateUserAndTLSCertificate(username, protocol, tlsCert, p.kvStore)
// }
//
// func (p *NATSProvider) validateUserAndPubKey(username string, publicKey []byte, isSSHCert bool) (User, string, error) {
// 	return sqlCommonValidateUserAndPubKey(username, publicKey, isSSHCert, p.kvStore)
// }
//
// func (p *NATSProvider) updateTransferQuota(username string, uploadSize, downloadSize int64, reset bool) error {
// 	return sqlCommonUpdateTransferQuota(username, uploadSize, downloadSize, reset, p.kvStore)
// }
//
// func (p *NATSProvider) updateQuota(username string, filesAdd int, sizeAdd int64, reset bool) error {
// 	return sqlCommonUpdateQuota(username, filesAdd, sizeAdd, reset, p.kvStore)
// }
//
// func (p *NATSProvider) getUsedQuota(username string) (int, int64, int64, int64, error) {
// 	return sqlCommonGetUsedQuota(username, p.kvStore)
// }
//
// func (p *NATSProvider) getAdminSignature(username string) (string, error) {
// 	return sqlCommonGetAdminSignature(username, p.kvStore)
// }
//
// func (p *NATSProvider) getUserSignature(username string) (string, error) {
// 	return sqlCommonGetUserSignature(username, p.kvStore)
// }
//
// func (p *NATSProvider) setUpdatedAt(username string) {
// 	sqlCommonSetUpdatedAt(username, p.kvStore)
// }
//
// func (p *NATSProvider) updateLastLogin(username string) error {
// 	return sqlCommonUpdateLastLogin(username, p.kvStore)
// }
//
// func (p *NATSProvider) updateAdminLastLogin(username string) error {
// 	return sqlCommonUpdateAdminLastLogin(username, p.kvStore)
// }

func (p *NATSProvider) userExists(username, role string) (User, error) {
	wUser := wrapper.NewWrapper(User{})
	kv, err := p.getUsersBucket()
	if err != nil {
		return User{}, err
	}

	entry, err := kv.Get(username)
	if err != nil {
		return User{}, err
	}

	if err := wUser.UnmarshalJSON(entry.Value()); err != nil {
		return User{}, err
	}

	foldersBucket, err := p.getFoldersBucket()
	if err != nil {
		return User{}, err
	}

	user, err := p.joinUserAndFolders(wUser.Get(), foldersBucket)
	if err != nil {
		return User{}, err
	}

	if !user.hasRole(role) {
		return User{}, util.NewRecordNotFoundError(fmt.Sprintf("username %q does not exist", username))
	}
	return user, nil

	// if user.DeletedAt > 0 {
	// 	return User{}, util.NewRecordNotFoundError("user not found")
	// }
	//
	// if role != "" {
	// 	if user.Role == "" {
	// 		return User{}, util.NewRecordNotFoundError("user has no role")
	// 	}
	//
	// 	rolesKV, ok := p.kvStore[rolesBucketNATS]
	// 	if !ok {
	// 		return User{}, fmt.Errorf("bucket %q not found", rolesBucketNATS)
	// 	}
	//
	// 	roleEntry, err := rolesKV.Get(user.Role)
	// 	if err != nil {
	// 		return User{}, fmt.Errorf("role not found: %v", err)
	// 	}
	//
	// 	wRole := wrapper.NewWrapper(Role{})
	// 	if err := wRole.UnmarshalJSON(roleEntry.Value()); err != nil {
	// 		return User{}, fmt.Errorf("unable to unmarshal role data: %v", err)
	// 	}
	//
	// 	roleObj := wRole.Get()
	//
	// 	if roleObj.Name != role {
	// 		return User{}, util.NewRecordNotFoundError("user role does not match")
	// 	}
	// }
	//
	// q := p.natsGetUserByUsernameQuery(role)
	// args := []any{username}
	// if role != "" {
	// 	args = append(args, role)
	// }
	//
	// row := dbHandle.QueryRowContext(ctx, q, args...)
	// user, err := getUserFromDbRow(row)
	// if err != nil {
	// 	return user, err
	// }
	//
	// user, err = getUserWithVirtualFolders(ctx, user, dbHandle)
	// if err != nil {
	// 	return user, err
	// }
	// return getUserWithGroups(ctx, user, dbHandle)
}

// func (p *NATSProvider) addUser(user *User) error {
// 	return p.normalizeError(sqlCommonAddUser(user, p.kvStore), fieldUsername)
// }
//
// func (p *NATSProvider) updateUser(user *User) error {
// 	return p.normalizeError(sqlCommonUpdateUser(user, p.kvStore), -1)
// }
//
// func (p *NATSProvider) deleteUser(user User, softDelete bool) error {
// 	return sqlCommonDeleteUser(user, softDelete, p.kvStore)
// }
//
// func (p *NATSProvider) updateUserPassword(username, password string) error {
// 	return sqlCommonUpdateUserPassword(username, password, p.kvStore)
// }
//
// func (p *NATSProvider) dumpUsers() ([]User, error) {
// 	return sqlCommonDumpUsers(p.kvStore)
// }
//
// func (p *NATSProvider) getRecentlyUpdatedUsers(after int64) ([]User, error) {
// 	return sqlCommonGetRecentlyUpdatedUsers(after, p.kvStore)
// }
//
// func (p *NATSProvider) getUsers(limit int, offset int, order, role string) ([]User, error) {
// 	return sqlCommonGetUsers(limit, offset, order, role, p.kvStore)
// }
//
// func (p *NATSProvider) getUsersForQuotaCheck(toFetch map[string]bool) ([]User, error) {
// 	return sqlCommonGetUsersForQuotaCheck(toFetch, p.kvStore)
// }
//
// func (p *NATSProvider) dumpFolders() ([]vfs.BaseVirtualFolder, error) {
// 	return sqlCommonDumpFolders(p.kvStore)
// }
//
// func (p *NATSProvider) getFolders(limit, offset int, order string, minimal bool) ([]vfs.BaseVirtualFolder, error) {
// 	return sqlCommonGetFolders(limit, offset, order, minimal, p.kvStore)
// }
//
// func (p *NATSProvider) getFolderByName(name string) (vfs.BaseVirtualFolder, error) {
// 	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
// 	defer cancel()
// 	return sqlCommonGetFolderByName(ctx, name, p.kvStore)
// }
//
// func (p *NATSProvider) addFolder(folder *vfs.BaseVirtualFolder) error {
// 	return p.normalizeError(sqlCommonAddFolder(folder, p.kvStore), fieldName)
// }
//
// func (p *NATSProvider) updateFolder(folder *vfs.BaseVirtualFolder) error {
// 	return sqlCommonUpdateFolder(folder, p.kvStore)
// }
//
// func (p *NATSProvider) deleteFolder(folder vfs.BaseVirtualFolder) error {
// 	return sqlCommonDeleteFolder(folder, p.kvStore)
// }
//
// func (p *NATSProvider) updateFolderQuota(name string, filesAdd int, sizeAdd int64, reset bool) error {
// 	return sqlCommonUpdateFolderQuota(name, filesAdd, sizeAdd, reset, p.kvStore)
// }
//
// func (p *NATSProvider) getUsedFolderQuota(name string) (int, int64, error) {
// 	return sqlCommonGetFolderUsedQuota(name, p.kvStore)
// }
//
// func (p *NATSProvider) getGroups(limit, offset int, order string, minimal bool) ([]Group, error) {
// 	return sqlCommonGetGroups(limit, offset, order, minimal, p.kvStore)
// }
//
// func (p *NATSProvider) getGroupsWithNames(names []string) ([]Group, error) {
// 	return sqlCommonGetGroupsWithNames(names, p.kvStore)
// }
//
// func (p *NATSProvider) getUsersInGroups(names []string) ([]string, error) {
// 	return sqlCommonGetUsersInGroups(names, p.kvStore)
// }
//
// func (p *NATSProvider) groupExists(name string) (Group, error) {
// 	return sqlCommonGetGroupByName(name, p.kvStore)
// }
//
// func (p *NATSProvider) addGroup(group *Group) error {
// 	return p.normalizeError(sqlCommonAddGroup(group, p.kvStore), fieldName)
// }
//
// func (p *NATSProvider) updateGroup(group *Group) error {
// 	return sqlCommonUpdateGroup(group, p.kvStore)
// }
//
// func (p *NATSProvider) deleteGroup(group Group) error {
// 	return sqlCommonDeleteGroup(group, p.kvStore)
// }
//
// func (p *NATSProvider) dumpGroups() ([]Group, error) {
// 	return sqlCommonDumpGroups(p.kvStore)
// }
//
// func (p *NATSProvider) adminExists(username string) (Admin, error) {
// 	return sqlCommonGetAdminByUsername(username, p.kvStore)
// }
//
// func (p *NATSProvider) addAdmin(admin *Admin) error {
// 	return p.normalizeError(sqlCommonAddAdmin(admin, p.kvStore), fieldUsername)
// }
//
// func (p *NATSProvider) updateAdmin(admin *Admin) error {
// 	return p.normalizeError(sqlCommonUpdateAdmin(admin, p.kvStore), -1)
// }
//
// func (p *NATSProvider) deleteAdmin(admin Admin) error {
// 	return sqlCommonDeleteAdmin(admin, p.kvStore)
// }
//
// func (p *NATSProvider) getAdmins(limit int, offset int, order string) ([]Admin, error) {
// 	return sqlCommonGetAdmins(limit, offset, order, p.kvStore)
// }
//
// func (p *NATSProvider) dumpAdmins() ([]Admin, error) {
// 	return sqlCommonDumpAdmins(p.kvStore)
// }
//
// func (p *NATSProvider) validateAdminAndPass(username, password, ip string) (Admin, error) {
// 	return sqlCommonValidateAdminAndPass(username, password, ip, p.kvStore)
// }
//
// func (p *NATSProvider) apiKeyExists(keyID string) (APIKey, error) {
// 	return sqlCommonGetAPIKeyByID(keyID, p.kvStore)
// }
//
// func (p *NATSProvider) addAPIKey(apiKey *APIKey) error {
// 	return p.normalizeError(sqlCommonAddAPIKey(apiKey, p.kvStore), -1)
// }
//
// func (p *NATSProvider) updateAPIKey(apiKey *APIKey) error {
// 	return p.normalizeError(sqlCommonUpdateAPIKey(apiKey, p.kvStore), -1)
// }
//
// func (p *NATSProvider) deleteAPIKey(apiKey APIKey) error {
// 	return sqlCommonDeleteAPIKey(apiKey, p.kvStore)
// }
//
// func (p *NATSProvider) getAPIKeys(limit int, offset int, order string) ([]APIKey, error) {
// 	return sqlCommonGetAPIKeys(limit, offset, order, p.kvStore)
// }
//
// func (p *NATSProvider) dumpAPIKeys() ([]APIKey, error) {
// 	return sqlCommonDumpAPIKeys(p.kvStore)
// }
//
// func (p *NATSProvider) updateAPIKeyLastUse(keyID string) error {
// 	return sqlCommonUpdateAPIKeyLastUse(keyID, p.kvStore)
// }
//
// func (p *NATSProvider) shareExists(shareID, username string) (Share, error) {
// 	return sqlCommonGetShareByID(shareID, username, p.kvStore)
// }
//
// func (p *NATSProvider) addShare(share *Share) error {
// 	return p.normalizeError(sqlCommonAddShare(share, p.kvStore), fieldName)
// }
//
// func (p *NATSProvider) updateShare(share *Share) error {
// 	return p.normalizeError(sqlCommonUpdateShare(share, p.kvStore), -1)
// }
//
// func (p *NATSProvider) deleteShare(share Share) error {
// 	return sqlCommonDeleteShare(share, p.kvStore)
// }
//
// func (p *NATSProvider) getShares(limit int, offset int, order, username string) ([]Share, error) {
// 	return sqlCommonGetShares(limit, offset, order, username, p.kvStore)
// }
//
// func (p *NATSProvider) dumpShares() ([]Share, error) {
// 	return sqlCommonDumpShares(p.kvStore)
// }
//
// func (p *NATSProvider) updateShareLastUse(shareID string, numTokens int) error {
// 	return sqlCommonUpdateShareLastUse(shareID, numTokens, p.kvStore)
// }
//
// func (p *NATSProvider) getDefenderHosts(from int64, limit int) ([]DefenderEntry, error) {
// 	return sqlCommonGetDefenderHosts(from, limit, p.kvStore)
// }
//
// func (p *NATSProvider) getDefenderHostByIP(ip string, from int64) (DefenderEntry, error) {
// 	return sqlCommonGetDefenderHostByIP(ip, from, p.kvStore)
// }
//
// func (p *NATSProvider) isDefenderHostBanned(ip string) (DefenderEntry, error) {
// 	return sqlCommonIsDefenderHostBanned(ip, p.kvStore)
// }
//
// func (p *NATSProvider) updateDefenderBanTime(ip string, minutes int) error {
// 	return sqlCommonDefenderIncrementBanTime(ip, minutes, p.kvStore)
// }
//
// func (p *NATSProvider) deleteDefenderHost(ip string) error {
// 	return sqlCommonDeleteDefenderHost(ip, p.kvStore)
// }
//
// func (p *NATSProvider) addDefenderEvent(ip string, score int) error {
// 	return sqlCommonAddDefenderHostAndEvent(ip, score, p.kvStore)
// }
//
// func (p *NATSProvider) setDefenderBanTime(ip string, banTime int64) error {
// 	return sqlCommonSetDefenderBanTime(ip, banTime, p.kvStore)
// }
//
// func (p *NATSProvider) cleanupDefender(from int64) error {
// 	return sqlCommonDefenderCleanup(from, p.kvStore)
// }
//
// func (p *NATSProvider) addActiveTransfer(transfer ActiveTransfer) error {
// 	return sqlCommonAddActiveTransfer(transfer, p.kvStore)
// }
//
// func (p *NATSProvider) updateActiveTransferSizes(ulSize, dlSize, transferID int64, connectionID string) error {
// 	return sqlCommonUpdateActiveTransferSizes(ulSize, dlSize, transferID, connectionID, p.kvStore)
// }
//
// func (p *NATSProvider) removeActiveTransfer(transferID int64, connectionID string) error {
// 	return sqlCommonRemoveActiveTransfer(transferID, connectionID, p.kvStore)
// }
//
// func (p *NATSProvider) cleanupActiveTransfers(before time.Time) error {
// 	return sqlCommonCleanupActiveTransfers(before, p.kvStore)
// }
//
// func (p *NATSProvider) getActiveTransfers(from time.Time) ([]ActiveTransfer, error) {
// 	return sqlCommonGetActiveTransfers(from, p.kvStore)
// }
//
// func (p *NATSProvider) addSharedSession(session Session) error {
// 	return sqlCommonAddSession(session, p.kvStore)
// }
//
// func (p *NATSProvider) deleteSharedSession(key string, sessionType SessionType) error {
// 	return sqlCommonDeleteSession(key, sessionType, p.kvStore)
// }
//
// func (p *NATSProvider) getSharedSession(key string, sessionType SessionType) (Session, error) {
// 	return sqlCommonGetSession(key, sessionType, p.kvStore)
// }
//
// func (p *NATSProvider) cleanupSharedSessions(sessionType SessionType, before int64) error {
// 	return sqlCommonCleanupSessions(sessionType, before, p.kvStore)
// }
//
// func (p *NATSProvider) getEventActions(limit, offset int, order string, minimal bool) ([]BaseEventAction, error) {
// 	return sqlCommonGetEventActions(limit, offset, order, minimal, p.kvStore)
// }
//
// func (p *NATSProvider) dumpEventActions() ([]BaseEventAction, error) {
// 	return sqlCommonDumpEventActions(p.kvStore)
// }
//
// func (p *NATSProvider) eventActionExists(name string) (BaseEventAction, error) {
// 	return sqlCommonGetEventActionByName(name, p.kvStore)
// }
//
// func (p *NATSProvider) addEventAction(action *BaseEventAction) error {
// 	return p.normalizeError(sqlCommonAddEventAction(action, p.kvStore), fieldName)
// }
//
// func (p *NATSProvider) updateEventAction(action *BaseEventAction) error {
// 	return sqlCommonUpdateEventAction(action, p.kvStore)
// }
//
// func (p *NATSProvider) deleteEventAction(action BaseEventAction) error {
// 	return sqlCommonDeleteEventAction(action, p.kvStore)
// }
//
// func (p *NATSProvider) getEventRules(limit, offset int, order string) ([]EventRule, error) {
// 	return sqlCommonGetEventRules(limit, offset, order, p.kvStore)
// }
//
// func (p *NATSProvider) dumpEventRules() ([]EventRule, error) {
// 	return sqlCommonDumpEventRules(p.kvStore)
// }
//
// func (p *NATSProvider) getRecentlyUpdatedRules(after int64) ([]EventRule, error) {
// 	return sqlCommonGetRecentlyUpdatedRules(after, p.kvStore)
// }
//
// func (p *NATSProvider) eventRuleExists(name string) (EventRule, error) {
// 	return sqlCommonGetEventRuleByName(name, p.kvStore)
// }
//
// func (p *NATSProvider) addEventRule(rule *EventRule) error {
// 	return p.normalizeError(sqlCommonAddEventRule(rule, p.kvStore), fieldName)
// }
//
// func (p *NATSProvider) updateEventRule(rule *EventRule) error {
// 	return sqlCommonUpdateEventRule(rule, p.kvStore)
// }
//
// func (p *NATSProvider) deleteEventRule(rule EventRule, softDelete bool) error {
// 	return sqlCommonDeleteEventRule(rule, softDelete, p.kvStore)
// }
//
// func (p *NATSProvider) getTaskByName(name string) (Task, error) {
// 	return sqlCommonGetTaskByName(name, p.kvStore)
// }
//
// func (p *NATSProvider) addTask(name string) error {
// 	return sqlCommonAddTask(name, p.kvStore)
// }
//
// func (p *NATSProvider) updateTask(name string, version int64) error {
// 	return sqlCommonUpdateTask(name, version, p.kvStore)
// }
//
// func (p *NATSProvider) updateTaskTimestamp(name string) error {
// 	return sqlCommonUpdateTaskTimestamp(name, p.kvStore)
// }
//
// func (p *NATSProvider) addNode() error {
// 	return sqlCommonAddNode(p.kvStore)
// }
//
// func (p *NATSProvider) getNodeByName(name string) (Node, error) {
// 	return sqlCommonGetNodeByName(name, p.kvStore)
// }
//
// func (p *NATSProvider) getNodes() ([]Node, error) {
// 	return sqlCommonGetNodes(p.kvStore)
// }
//
// func (p *NATSProvider) updateNodeTimestamp() error {
// 	return sqlCommonUpdateNodeTimestamp(p.kvStore)
// }
//
// func (p *NATSProvider) cleanupNodes() error {
// 	return sqlCommonCleanupNodes(p.kvStore)
// }
//
// func (p *NATSProvider) roleExists(name string) (Role, error) {
// 	return sqlCommonGetRoleByName(name, p.kvStore)
// }
//
// func (p *NATSProvider) addRole(role *Role) error {
// 	return p.normalizeError(sqlCommonAddRole(role, p.kvStore), fieldName)
// }
//
// func (p *NATSProvider) updateRole(role *Role) error {
// 	return sqlCommonUpdateRole(role, p.kvStore)
// }
//
// func (p *NATSProvider) deleteRole(role Role) error {
// 	return sqlCommonDeleteRole(role, p.kvStore)
// }
//
// func (p *NATSProvider) getRoles(limit int, offset int, order string, minimal bool) ([]Role, error) {
// 	return sqlCommonGetRoles(limit, offset, order, minimal, p.kvStore)
// }
//
// func (p *NATSProvider) dumpRoles() ([]Role, error) {
// 	return sqlCommonDumpRoles(p.kvStore)
// }
//
// func (p *NATSProvider) ipListEntryExists(ipOrNet string, listType IPListType) (IPListEntry, error) {
// 	return sqlCommonGetIPListEntry(ipOrNet, listType, p.kvStore)
// }
//
// func (p *NATSProvider) addIPListEntry(entry *IPListEntry) error {
// 	return p.normalizeError(sqlCommonAddIPListEntry(entry, p.kvStore), fieldIPNet)
// }
//
// func (p *NATSProvider) updateIPListEntry(entry *IPListEntry) error {
// 	return sqlCommonUpdateIPListEntry(entry, p.kvStore)
// }
//
// func (p *NATSProvider) deleteIPListEntry(entry IPListEntry, softDelete bool) error {
// 	return sqlCommonDeleteIPListEntry(entry, softDelete, p.kvStore)
// }
//
// func (p *NATSProvider) getIPListEntries(listType IPListType, filter, from, order string, limit int) ([]IPListEntry, error) {
// 	return sqlCommonGetIPListEntries(listType, filter, from, order, limit, p.kvStore)
// }
//
// func (p *NATSProvider) getRecentlyUpdatedIPListEntries(after int64) ([]IPListEntry, error) {
// 	return sqlCommonGetRecentlyUpdatedIPListEntries(after, p.kvStore)
// }
//
// func (p *NATSProvider) dumpIPListEntries() ([]IPListEntry, error) {
// 	return sqlCommonDumpIPListEntries(p.kvStore)
// }
//
// func (p *NATSProvider) countIPListEntries(listType IPListType) (int64, error) {
// 	return sqlCommonCountIPListEntries(listType, p.kvStore)
// }
//
// func (p *NATSProvider) getListEntriesForIP(ip string, listType IPListType) ([]IPListEntry, error) {
// 	return sqlCommonGetListEntriesForIP(ip, listType, p.kvStore)
// }
//
// func (p *NATSProvider) getConfigs() (Configs, error) {
// 	return sqlCommonGetConfigs(p.kvStore)
// }
//
// func (p *NATSProvider) setConfigs(configs *Configs) error {
// 	return sqlCommonSetConfigs(configs, p.kvStore)
// }
//
// func (p *NATSProvider) setFirstDownloadTimestamp(username string) error {
// 	return sqlCommonSetFirstDownloadTimestamp(username, p.kvStore)
// }
//
// func (p *NATSProvider) setFirstUploadTimestamp(username string) error {
// 	return sqlCommonSetFirstUploadTimestamp(username, p.kvStore)
// }
//
// func (p *NATSProvider) close() error {
// 	return p.kvStore.Close()
// }
//
// func (p *NATSProvider) reloadConfig() error {
// 	return nil
// }
//
// // initializeDatabase creates the initial database structure
// func (p *NATSProvider) initializeDatabase() error {
// 	dbVersion, err := sqlCommonGetDatabaseVersion(p.kvStore, false)
// 	if err == nil && dbVersion.Version > 0 {
// 		return ErrNoInitRequired
// 	}
// 	if errors.Is(err, sql.ErrNoRows) {
// 		return errSchemaVersionEmpty
// 	}
// 	logger.InfoToConsole("creating initial database schema, version 29")
// 	providerLog(logger.LevelInfo, "creating initial database schema, version 29")
// 	initialSQL := sqlReplaceAll(mysqlInitialSQL)
//
// 	return sqlCommonExecSQLAndUpdateDBVersion(p.kvStore, strings.Split(initialSQL, ";"), 29, true)
// }
//
// func (p *NATSProvider) migrateDatabase() error {
// 	dbVersion, err := sqlCommonGetDatabaseVersion(p.kvStore, true)
// 	if err != nil {
// 		return err
// 	}
//
// 	switch version := dbVersion.Version; {
// 	case version == sqlDatabaseVersion:
// 		providerLog(logger.LevelDebug, "sql database is up to date, current version: %d", version)
// 		return ErrNoInitRequired
// 	case version < 29:
// 		err = errSchemaVersionTooOld(version)
// 		providerLog(logger.LevelError, "%v", err)
// 		logger.ErrorToConsole("%v", err)
// 		return err
// 	case version == 29:
// 		return updateNATSDatabaseFromV29(p.kvStore)
// 	case version == 30:
// 		return updateNATSDatabaseFromV30(p.kvStore)
// 	case version == 31:
// 		return updateNATSDatabaseFromV31(p.kvStore)
// 	default:
// 		if version > sqlDatabaseVersion {
// 			providerLog(logger.LevelError, "database schema version %d is newer than the supported one: %d", version,
// 				sqlDatabaseVersion)
// 			logger.WarnToConsole("database schema version %d is newer than the supported one: %d", version,
// 				sqlDatabaseVersion)
// 			return nil
// 		}
// 		return fmt.Errorf("database schema version not handled: %d", version)
// 	}
// }
//
// func (p *NATSProvider) revertDatabase(targetVersion int) error {
// 	dbVersion, err := sqlCommonGetDatabaseVersion(p.kvStore, true)
// 	if err != nil {
// 		return err
// 	}
// 	if dbVersion.Version == targetVersion {
// 		return errors.New("current version match target version, nothing to do")
// 	}
//
// 	switch dbVersion.Version {
// 	case 30:
// 		return downgradeNATSDatabaseFromV30(p.kvStore)
// 	case 31:
// 		return downgradeNATSDatabaseFromV31(p.kvStore)
// 	case 32:
// 		return downgradeNATSDatabaseFromV32(p.kvStore)
// 	default:
// 		return fmt.Errorf("database schema version not handled: %d", dbVersion.Version)
// 	}
// }
//
// func (p *NATSProvider) resetDatabase() error {
// 	sql := sqlReplaceAll(mysqlResetSQL)
// 	return sqlCommonExecSQLAndUpdateDBVersion(p.kvStore, strings.Split(sql, ";"), 0, false)
// }
//
// func (p *NATSProvider) normalizeError(err error, fieldType int) error {
// 	if err == nil {
// 		return nil
// 	}
// 	var mysqlErr *mysql.NATSError
// 	if errors.As(err, &mysqlErr) {
// 		switch mysqlErr.Number {
// 		case 1062:
// 			var message string
// 			switch fieldType {
// 			case fieldUsername:
// 				message = util.I18nErrorDuplicatedUsername
// 			case fieldIPNet:
// 				message = util.I18nErrorDuplicatedIPNet
// 			default:
// 				message = util.I18nErrorDuplicatedName
// 			}
// 			return util.NewI18nError(
// 				fmt.Errorf("%w: %s", ErrDuplicatedKey, err.Error()),
// 				message,
// 			)
// 		case 1452:
// 			return fmt.Errorf("%w: %s", ErrForeignKeyViolated, err.Error())
// 		}
// 	}
// 	return err
// }
//
// func updateNATSDatabaseFromV29(dbHandle *sql.DB) error {
// 	if err := updateNATSDatabaseFrom29To30(dbHandle); err != nil {
// 		return err
// 	}
// 	return updateNATSDatabaseFromV30(dbHandle)
// }
//
// func updateNATSDatabaseFromV30(dbHandle *sql.DB) error {
// 	if err := updateNATSDatabaseFrom30To31(dbHandle); err != nil {
// 		return err
// 	}
// 	return updateNATSDatabaseFromV31(dbHandle)
// }
//
// func updateNATSDatabaseFromV31(dbHandle *sql.DB) error {
// 	return updateSQLDatabaseFrom31To32(dbHandle)
// }
//
// func downgradeNATSDatabaseFromV30(dbHandle *sql.DB) error {
// 	return downgradeNATSDatabaseFrom30To29(dbHandle)
// }
//
// func downgradeNATSDatabaseFromV31(dbHandle *sql.DB) error {
// 	if err := downgradeNATSDatabaseFrom31To30(dbHandle); err != nil {
// 		return err
// 	}
// 	return downgradeNATSDatabaseFromV30(dbHandle)
// }
//
// func downgradeNATSDatabaseFromV32(dbHandle *sql.DB) error {
// 	if err := downgradeSQLDatabaseFrom32To31(dbHandle); err != nil {
// 		return err
// 	}
// 	return downgradeNATSDatabaseFromV31(dbHandle)
// }
//
// func updateNATSDatabaseFrom29To30(dbHandle *sql.DB) error {
// 	logger.InfoToConsole("updating database schema version: 29 -> 30")
// 	providerLog(logger.LevelInfo, "updating database schema version: 29 -> 30")
//
// 	sql := strings.ReplaceAll(mysqlV30SQL, "{{shares}}", sqlTableShares)
// 	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, strings.Split(sql, ";"), 30, true)
// }
//
// func downgradeNATSDatabaseFrom30To29(dbHandle *sql.DB) error {
// 	logger.InfoToConsole("downgrading database schema version: 30 -> 29")
// 	providerLog(logger.LevelInfo, "downgrading database schema version: 30 -> 29")
//
// 	sql := strings.ReplaceAll(mysqlV30DownSQL, "{{shares}}", sqlTableShares)
// 	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, strings.Split(sql, ";"), 29, false)
// }
//
// func updateNATSDatabaseFrom30To31(dbHandle *sql.DB) error {
// 	logger.InfoToConsole("updating database schema version: 30 -> 31")
// 	providerLog(logger.LevelInfo, "updating database schema version: 30 -> 31")
//
// 	sql := strings.ReplaceAll(mysqlV31SQL, "{{shared_sessions}}", sqlTableSharedSessions)
// 	sql = strings.ReplaceAll(sql, "{{prefix}}", config.SQLTablesPrefix)
// 	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, strings.Split(sql, ";"), 31, true)
// }
//
// func downgradeNATSDatabaseFrom31To30(dbHandle *sql.DB) error {
// 	logger.InfoToConsole("downgrading database schema version: 31 -> 30")
// 	providerLog(logger.LevelInfo, "downgrading database schema version: 31 -> 30")
//
// 	sql := strings.ReplaceAll(mysqlV31DownSQL, "{{shared_sessions}}", sqlTableSharedSessions)
// 	sql = strings.ReplaceAll(sql, "{{prefix}}", config.SQLTablesPrefix)
// 	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, strings.Split(sql, ";"), 30, false)
// }
//
// func (p *NATSProvider) checkUserAndPass(user *User, password, ip, protocol string) (User, error) {
// 	if err := user.LoadAndApplyGroupSettings(); err != nil {
// 		return *user, err
// 	}
//
// 	if err := user.CheckLoginConditions(); err != nil {
// 		return *user, err
// 	}
//
// 	if protocol != protocolHTTP && user.MustChangePassword() {
// 		return *user, errors.New("login not allowed, password change required")
// 	}
//
// 	if user.Filters.IsAnonymous {
// 		user.setAnonymousSettings()
// 		return *user, nil
// 	}
//
// 	password, err := checkUserPasscode(user, password, protocol)
// 	if err != nil {
// 		return *user, ErrInvalidCredentials
// 	}
//
// 	if user.Password == "" || password == "" {
// 		return *user, errors.New("credentials cannot be null or empty")
// 	}
//
// 	if !user.Filters.Hooks.CheckPasswordDisabled {
// 		hookResponse, err := executeCheckPasswordHook(user.Username, password, ip, protocol)
// 		if err != nil {
// 			providerLog(logger.LevelDebug, "error executing check password hook for user %q, ip %v, protocol %v: %v", user.Username, ip, protocol, err)
// 			return *user, errors.New("unable to check credentials")
// 		}
//
// 		switch hookResponse.Status {
// 		case -1:
// 			// no hook configured
// 		case 1:
// 			providerLog(logger.LevelDebug, "password accepted by check password hook for user %q, ip %v, protocol %v",
// 				user.Username, ip, protocol)
// 			return *user, nil
// 		case 2:
// 			providerLog(logger.LevelDebug, "partial success from check password hook for user %q, ip %v, protocol %v",
// 				user.Username, ip, protocol)
// 			password = hookResponse.ToVerify
// 		default:
// 			providerLog(logger.LevelDebug, "password rejected by check password hook for user %q, ip %v, protocol %v, status: %v",
// 				user.Username, ip, protocol, hookResponse.Status)
// 			return *user, ErrInvalidCredentials
// 		}
// 	}
//
// 	match, err := isPasswordOK(user, password)
// 	if !match {
// 		err = ErrInvalidCredentials
// 	}
// 	return *user, err
// }

func (p *NATSProvider) getFoldersBucket() (nats.KeyValue, error) {
	kv, ok := p.kvStore[foldersBucketNATS]
	if !ok {
		return nil, fmt.Errorf("bucket %q not found", foldersBucketNATS)
	}
	return kv, nil
}

func (p *NATSProvider) getSharesBucket() (nats.KeyValue, error) {
	kv, ok := p.kvStore[sharesBucketNATS]
	if !ok {
		return nil, fmt.Errorf("bucket %q not found", sharesBucketNATS)
	}
	return kv, nil
}

func (p *NATSProvider) getAPIKeysBucket() (nats.KeyValue, error) {
	kv, ok := p.kvStore[apiKeysBucketNATS]
	if !ok {
		return nil, fmt.Errorf("bucket %q not found", apiKeysBucketNATS)
	}
	return kv, nil
}

func (p *NATSProvider) getAdminsBucket() (nats.KeyValue, error) {
	kv, ok := p.kvStore[adminsBucketNATS]
	if !ok {
		return nil, fmt.Errorf("bucket %q not found", adminsBucketNATS)
	}
	return kv, nil
}

func (p *NATSProvider) getUsersBucket() (nats.KeyValue, error) {
	kv, ok := p.kvStore[usersBucketNATS]
	if !ok {
		return nil, fmt.Errorf("bucket %q not found", usersBucketNATS)
	}
	return kv, nil
}

func (p *NATSProvider) getGroupsBucket() (nats.KeyValue, error) {
	kv, ok := p.kvStore[rolesBucketNATS]
	if !ok {
		return nil, fmt.Errorf("bucket %q not found", rolesBucketNATS)
	}
	return kv, nil
}

func (p *NATSProvider) getRolesBucket() (nats.KeyValue, error) {
	kv, ok := p.kvStore[foldersBucketNATS]
	if !ok {
		return nil, fmt.Errorf("bucket %q not found", foldersBucketNATS)
	}
	return kv, nil
}

func (p *NATSProvider) getIPListsBucket() (nats.KeyValue, error) {
	kv, ok := p.kvStore[rolesBucketNATS]
	if !ok {
		return nil, fmt.Errorf("bucket %q not found", rolesBucketNATS)
	}
	return kv, nil
}

func (p *NATSProvider) getActionsBucket() (nats.KeyValue, error) {
	kv, ok := p.kvStore[actionsBucketNATS]
	if !ok {
		return nil, fmt.Errorf("bucket %q not found", actionsBucketNATS)
	}
	return kv, nil
}

func (p *NATSProvider) getRulesBucket() (nats.KeyValue, error) {
	kv, ok := p.kvStore[rolesBucketNATS]
	if !ok {
		return nil, fmt.Errorf("bucket %q not found", rolesBucketNATS)
	}
	return kv, nil
}

func (p *NATSProvider) joinUserAndFolders(user User, foldersBucket nats.KeyValue) (User, error) {
	if len(user.VirtualFolders) > 0 {
		var folders []vfs.VirtualFolder
		for idx := range user.VirtualFolders {
			folder := &user.VirtualFolders[idx]
			baseFolder, err := p.folderExistsInternal(folder.Name, foldersBucket)
			if err != nil {
				continue
			}
			folder.BaseVirtualFolder = baseFolder
			folders = append(folders, *folder)
		}
		user.VirtualFolders = folders
	}
	user.SetEmptySecretsIfNil()
	return user, nil
}

func (p *NATSProvider) folderExistsInternal(name string, bucket nats.KeyValue) (vfs.BaseVirtualFolder, error) {
	entry, err := bucket.Get(name)
	if err != nil {
		return vfs.BaseVirtualFolder{}, util.NewRecordNotFoundError(fmt.Sprintf("folder %q does not exist", name))
	}

	wFolder := wrapper.NewWrapper(vfs.BaseVirtualFolder{})
	if err := wFolder.UnmarshalJSON(entry.Value()); err != nil {
		return vfs.BaseVirtualFolder{}, err
	}
	return wFolder.Get(), err
}
