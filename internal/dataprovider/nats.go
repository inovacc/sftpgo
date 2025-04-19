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

func (p *NATSProvider) getAdmins(limit int, offset int, order string) ([]Admin, error) {
	admins := make([]Admin, 0, limit)
	bucket, err := p.getAdminsBucket()
	if err != nil {
		return nil, err
	}

	keys, err := bucket.Keys()
	if err != nil {
		return nil, err
	}

	if order == OrderDESC {
		sort.Sort(sort.Reverse(sort.StringSlice(keys)))
	} else {
		sort.Strings(keys)
	}

	start := offset
	end := offset + limit
	if start >= len(keys) {
		return admins, nil
	}

	if end > len(keys) {
		end = len(keys)
	}

	for _, key := range keys[start:end] {
		entry, err := bucket.Get(key)
		if err != nil {
			continue
		}

		wAdmin := wrapper.NewWrapper(Admin{})
		if err = wAdmin.UnmarshalJSON(entry.Value()); err != nil {
			return nil, err
		}

		admin := wAdmin.Get()
		admin.HideConfidentialData()
		admins = append(admins, admin)
	}
	return admins, nil
}

func (p *NATSProvider) dumpAdmins() ([]Admin, error) {
	admins := make([]Admin, 0, 30)
	bucket, err := p.getAdminsBucket()
	if err != nil {
		return nil, err
	}

	keys, err := bucket.Keys()
	if err != nil {
		return nil, err
	}

	for _, key := range keys {
		entry, err := bucket.Get(key)
		if err != nil {
			continue
		}

		wAdmin := wrapper.NewWrapper(Admin{})
		if err = wAdmin.UnmarshalJSON(entry.Value()); err != nil {
			return nil, err
		}

		admins = append(admins, wAdmin.Get())
	}
	return admins, nil
}

func (p *NATSProvider) userExists(username, role string) (User, error) {
	bucket, err := p.getUsersBucket()
	if err != nil {
		return User{}, err
	}

	entry, err := bucket.Get(username)
	if err != nil {
		return User{}, util.NewRecordNotFoundError(fmt.Sprintf("username %q does not exist", username))
	}

	wUser := wrapper.NewWrapper(User{})
	if err = wUser.UnmarshalJSON(entry.Value()); err != nil {
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
}

func (p *NATSProvider) addUser(user *User) error {
	if err := ValidateUser(user); err != nil {
		return err
	}

	bucket, err := p.getUsersBucket()
	if err != nil {
		return err
	}

	entry, err := bucket.Get(user.Username)
	if err == nil {
		return util.NewI18nError(
			fmt.Errorf("%w: username %v already exists", ErrDuplicatedKey, user.Username),
			util.I18nErrorDuplicatedUsername,
		)
	}

	foldersBucket, err := p.getFoldersBucket()
	if err != nil {
		return err
	}

	groupBucket, err := p.getGroupsBucket()
	if err != nil {
		return err
	}

	rolesBucket, err := p.getRolesBucket()
	if err != nil {
		return err
	}

	user.ID = time.Now().UnixNano()
	user.LastQuotaUpdate = 0
	user.UsedQuotaSize = 0
	user.UsedQuotaFiles = 0
	user.UsedUploadDataTransfer = 0
	user.UsedDownloadDataTransfer = 0
	user.LastLogin = 0
	user.FirstDownload = 0
	user.FirstUpload = 0
	user.CreatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
	user.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())

	if err := p.addUserToRole(user.Username, user.Role, rolesBucket); err != nil {
		return err
	}

	sort.Slice(user.VirtualFolders, func(i, j int) bool {
		return user.VirtualFolders[i].Name < user.VirtualFolders[j].Name
	})
	for idx := range user.VirtualFolders {
		if err = p.addRelationToFolderMapping(user.VirtualFolders[idx].Name, user, nil, foldersBucket); err != nil {
			return err
		}
	}

	sort.Slice(user.Groups, func(i, j int) bool {
		return user.Groups[i].Name < user.Groups[j].Name
	})

	for idx := range user.Groups {
		if err = p.addUserToGroupMapping(user.Username, user.Groups[idx].Name, groupBucket); err != nil {
			return err
		}
	}

	wUser := wrapper.NewWrapper(User{})
	data, err := wUser.MarshalJSON()
	if err != nil {
		return err
	}

	_, err = bucket.Update(user.Username, data, entry.Revision())
	return err
}

func (p *NATSProvider) updateUser(user *User) error {
	if err := ValidateUser(user); err != nil {
		return err
	}

	bucket, err := p.getUsersBucket()
	if err != nil {
		return err
	}

	entry, err := bucket.Get(user.Username)
	if err != nil {
		return util.NewRecordNotFoundError(fmt.Sprintf("username %q does not exist", user.Username))
	}

	wOldUser := wrapper.NewWrapper(User{})
	if err = wOldUser.UnmarshalJSON(entry.Value()); err != nil {
		return err
	}

	oldUser := wOldUser.Get()

	if err = p.updateUserRelations(user, oldUser); err != nil {
		return err
	}

	user.ID = oldUser.ID
	user.LastQuotaUpdate = oldUser.LastQuotaUpdate
	user.UsedQuotaSize = oldUser.UsedQuotaSize
	user.UsedQuotaFiles = oldUser.UsedQuotaFiles
	user.UsedUploadDataTransfer = oldUser.UsedUploadDataTransfer
	user.UsedDownloadDataTransfer = oldUser.UsedDownloadDataTransfer
	user.LastLogin = oldUser.LastLogin
	user.FirstDownload = oldUser.FirstDownload
	user.FirstUpload = oldUser.FirstUpload
	user.CreatedAt = oldUser.CreatedAt
	user.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())

	wUser := wrapper.NewWrapper(User{})
	data, err := wUser.MarshalJSON()
	if err != nil {
		return err
	}

	if _, err := bucket.Update(user.Username, data, entry.Revision()); err != nil {
		return err
	}

	setLastUserUpdate()
	return nil
}

func (p *NATSProvider) deleteUser(user User, _ bool) error {
	bucket, err := p.getUsersBucket()
	if err != nil {
		return err
	}

	entry, err := bucket.Get(user.Username)
	if err != nil {
		return util.NewRecordNotFoundError(fmt.Sprintf("username %q does not exist", user.Username))
	}

	wOldUser := wrapper.NewWrapper(User{})
	if err = wOldUser.UnmarshalJSON(entry.Value()); err != nil {
		return err
	}

	oldUser := wOldUser.Get()

	foldersBucket, err := p.getFoldersBucket()
	if err != nil {
		return err
	}

	groupBucket, err := p.getGroupsBucket()
	if err != nil {
		return err
	}

	rolesBucket, err := p.getRolesBucket()
	if err != nil {
		return err
	}

	if err := p.removeUserFromRole(oldUser.Username, oldUser.Role, rolesBucket); err != nil {
		return err
	}

	for idx := range oldUser.VirtualFolders {
		if err = p.removeRelationFromFolderMapping(oldUser.VirtualFolders[idx], oldUser.Username, "", foldersBucket); err != nil {
			return err
		}
	}

	for idx := range oldUser.Groups {
		if err = p.removeUserFromGroupMapping(oldUser.Username, oldUser.Groups[idx].Name, groupBucket); err != nil {
			return err
		}
	}

	if err := p.deleteRelatedAPIKey(user.Username, APIKeyScopeUser); err != nil {
		return err
	}

	if err := p.deleteRelatedShares(user.Username); err != nil {
		return err
	}
	return bucket.Delete(user.Username)
}

func (p *NATSProvider) updateUserPassword(username, password string) error {
	bucket, err := p.getUsersBucket()
	if err != nil {
		return err
	}

	entry, err := bucket.Get(username)
	if err != nil {
		return util.NewRecordNotFoundError(fmt.Sprintf("username %q does not exist", username))
	}

	wUser := wrapper.NewWrapper(User{})
	if err = wUser.UnmarshalJSON(entry.Value()); err != nil {
		return err
	}

	user := wUser.Get()

	user.Password = password
	user.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())

	wUser.Set(user)
	data, err := wUser.MarshalJSON()
	if err != nil {
		return err
	}

	_, err = bucket.Update(username, data, entry.Revision())
	return err
}

func (p *NATSProvider) dumpUsers() ([]User, error) {
	users := make([]User, 0, 100)
	bucket, err := p.getUsersBucket()
	if err != nil {
		return nil, err
	}

	foldersBucket, err := p.getFoldersBucket()
	if err != nil {
		return nil, err
	}

	keys, err := bucket.Keys()
	if err != nil {
		return nil, err
	}

	for _, key := range keys {
		entry, err := bucket.Get(key)
		if err != nil {
			continue
		}

		wUser := wrapper.NewWrapper(User{})
		if err := wUser.UnmarshalJSON(entry.Value()); err != nil {
			return nil, err
		}

		user, err := p.joinUserAndFolders(wUser.Get(), foldersBucket)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	return users, nil
}

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

func (p *NATSProvider) getRecentlyUpdatedUsers(after int64) ([]User, error) {
	if getLastUserUpdate() < after {
		return nil, nil
	}

	users := make([]User, 0, 10)

	bucket, err := p.getUsersBucket()
	if err != nil {
		return nil, err
	}

	foldersBucket, err := p.getFoldersBucket()
	if err != nil {
		return nil, err
	}

	groupsBucket, err := p.getGroupsBucket()
	if err != nil {
		return nil, err
	}

	keys, err := bucket.Keys()
	if err != nil {
		return nil, err
	}

	for _, key := range keys {
		entry, err := bucket.Get(key)
		if err != nil {
			continue
		}

		wUser := wrapper.NewWrapper(User{})
		if err = wUser.UnmarshalJSON(entry.Value()); err != nil {
			return nil, err
		}

		user := wUser.Get()

		if user.UpdatedAt < after {
			continue
		}

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

		if len(user.Groups) > 0 {
			groupMapping := make(map[string]Group)
			for idx := range user.Groups {
				group, err := p.groupExistsInternal(user.Groups[idx].Name, groupsBucket)
				if err != nil {
					continue
				}

				groupMapping[group.Name] = group
			}
			user.applyGroupSettings(groupMapping)
		}

		user.SetEmptySecretsIfNil()
		users = append(users, user)
	}
	return users, err
}

func (p *NATSProvider) getUsersForQuotaCheck(toFetch map[string]bool) ([]User, error) {
	users := make([]User, 0, 10)

	bucket, err := p.getUsersBucket()
	if err != nil {
		return nil, err
	}

	foldersBucket, err := p.getFoldersBucket()
	if err != nil {
		return nil, err
	}

	groupsBucket, err := p.getGroupsBucket()
	if err != nil {
		return nil, err
	}

	for username, needFolders := range toFetch {
		entry, err := bucket.Get(username)
		if err != nil {
			continue
		}

		wUser := wrapper.NewWrapper(User{})
		if err = wUser.UnmarshalJSON(entry.Value()); err != nil {
			return nil, err
		}

		user := wUser.Get()

		if needFolders && len(user.VirtualFolders) > 0 {
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

		if len(user.Groups) > 0 {
			groupMapping := make(map[string]Group)
			for idx := range user.Groups {
				group, err := p.groupExistsInternal(user.Groups[idx].Name, groupsBucket)
				if err != nil {
					continue
				}

				groupMapping[group.Name] = group
			}
			user.applyGroupSettings(groupMapping)
		}

		user.SetEmptySecretsIfNil()
		user.PrepareForRendering()
		users = append(users, user)
	}
	return users, nil
}

func (p *NATSProvider) getUsers(limit int, offset int, order, role string) ([]User, error) {
	users := make([]User, 0, limit)
	if limit <= 0 {
		return users, nil
	}

	bucket, err := p.getUsersBucket()
	if err != nil {
		return nil, err
	}

	foldersBucket, err := p.getFoldersBucket()
	if err != nil {
		return nil, err
	}

	keys, err := bucket.Keys()
	if err != nil {
		return nil, err
	}

	if order == OrderDESC {
		sort.Sort(sort.Reverse(sort.StringSlice(keys)))
	} else {
		sort.Strings(keys)
	}

	start := offset
	end := offset + limit
	if start >= len(keys) {
		return users, nil
	}

	if end > len(keys) {
		end = len(keys)
	}

	for _, key := range keys[start:end] {
		entry, err := bucket.Get(key)
		if err != nil {
			continue
		}

		wUser := wrapper.NewWrapper(User{})
		if err := wUser.UnmarshalJSON(entry.Value()); err != nil {
			return nil, err
		}

		user, err := p.joinUserAndFolders(wUser.Get(), foldersBucket)
		if err != nil {
			return nil, err
		}

		if !user.hasRole(role) {
			continue
		}

		user.PrepareForRendering()
		users = append(users, user)
	}
	return users, nil
}

func (p *NATSProvider) dumpFolders() ([]vfs.BaseVirtualFolder, error) {
	folders := make([]vfs.BaseVirtualFolder, 0, 50)
	bucket, err := p.getFoldersBucket()
	if err != nil {
		return nil, err
	}

	keys, err := bucket.Keys()
	if err != nil {
		return nil, err
	}

	for _, key := range keys {
		entry, err := bucket.Get(key)
		if err != nil {
			continue
		}

		wFolder := wrapper.NewWrapper(vfs.BaseVirtualFolder{})
		if err = wFolder.UnmarshalJSON(entry.Value()); err != nil {
			return nil, err
		}

		folders = append(folders, wFolder.Get())
	}
	return folders, nil
}

func (p *NATSProvider) getFolders(limit, offset int, order string, _ bool) ([]vfs.BaseVirtualFolder, error) {
	folders := make([]vfs.BaseVirtualFolder, 0, limit)
	if limit <= 0 {
		return folders, nil
	}

	bucket, err := p.getFoldersBucket()
	if err != nil {
		return nil, err
	}

	keys, err := bucket.Keys()
	if err != nil {
		return nil, err
	}

	if order == OrderDESC {
		sort.Sort(sort.Reverse(sort.StringSlice(keys)))
	} else {
		sort.Strings(keys)
	}

	start := offset
	end := offset + limit
	if start >= len(keys) {
		return folders, nil
	}

	if end > len(keys) {
		end = len(keys)
	}

	for _, key := range keys[start:end] {
		entry, err := bucket.Get(key)
		if err != nil {
			continue
		}

		wFolder := wrapper.NewWrapper(vfs.BaseVirtualFolder{})
		if err = wFolder.UnmarshalJSON(entry.Value()); err != nil {
			return nil, err
		}

		folder := wFolder.Get()
		folder.PrepareForRendering()
		folders = append(folders, folder)
	}
	return folders, nil
}

func (p *NATSProvider) getFolderByName(name string) (vfs.BaseVirtualFolder, error) {
	bucket, err := p.getFoldersBucket()
	if err != nil {
		return vfs.BaseVirtualFolder{}, err
	}

	folder, err := p.folderExistsInternal(name, bucket)
	return folder, err
}

func (p *NATSProvider) addFolder(folder *vfs.BaseVirtualFolder) error {
	if err := ValidateFolder(folder); err != nil {
		return err
	}

	bucket, err := p.getFoldersBucket()
	if err != nil {
		return err
	}

	entry, err := bucket.Get(folder.Name)
	if err != nil {
		return util.NewI18nError(fmt.Errorf("%w: folder %q already exists", ErrDuplicatedKey, folder.Name), util.I18nErrorDuplicatedUsername)
	}

	folder.Users = nil
	folder.Groups = nil

	wFolder := wrapper.NewWrapper(vfs.BaseVirtualFolder{})
	if err := wFolder.UnmarshalJSON(entry.Value()); err != nil {
		return err
	}

	wFolder.Set(*folder)

	data, err := wFolder.MarshalJSON()
	if err != nil {
		return err
	}

	_, err = bucket.Update(folder.Name, data, entry.Revision())
	return err
}

func (p *NATSProvider) updateFolder(folder *vfs.BaseVirtualFolder) error {
	if err := ValidateFolder(folder); err != nil {
		return err
	}

	bucket, err := p.getFoldersBucket()
	if err != nil {
		return err
	}

	entry, err := bucket.Get(folder.Name)
	if err != nil {
		return util.NewRecordNotFoundError(fmt.Sprintf("folder %v does not exist", folder.Name))
	}

	wOldFolder := wrapper.NewWrapper(vfs.BaseVirtualFolder{})
	if err = wOldFolder.UnmarshalJSON(entry.Value()); err != nil {
		return err
	}

	oldFolder := wOldFolder.Get()

	folder.ID = oldFolder.ID
	folder.LastQuotaUpdate = oldFolder.LastQuotaUpdate
	folder.UsedQuotaFiles = oldFolder.UsedQuotaFiles
	folder.UsedQuotaSize = oldFolder.UsedQuotaSize
	folder.Users = oldFolder.Users
	folder.Groups = oldFolder.Groups

	wFolder := wrapper.NewWrapper(*folder)
	data, err := wFolder.MarshalJSON()
	if err != nil {
		return err
	}

	_, err = bucket.Update(folder.Name, data, entry.Revision())
	return err
}
