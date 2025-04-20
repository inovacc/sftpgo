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

//go:build !nonats
// +build !nonats

package dataprovider

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/inovacc/wrapper"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/util"
	"github.com/drakkan/sftpgo/v2/internal/version"
	"github.com/drakkan/sftpgo/v2/internal/vfs"
)

const (
	currentDatabaseVersionNATS = 32
	usersBucketNATS            = "users"
	groupsBucketNATS           = "groups"
	foldersBucketNATS          = "folders"
	adminsBucketNATS           = "admins"
	apiKeysBucketNATS          = "api_keys"
	sharesBucketNATS           = "shares"
	actionsBucketNATS          = "events_actions"
	rulesBucketNATS            = "events_rules"
	rolesBucketNATS            = "roles"
	ipListsBucketNATS          = "ip_lists"
	configsBucketNATS          = "configs"
	dbVersionBucketNATS        = "db_version"
	dbVersionKeyNATS           = "version"
	dbMetadataNATS             = "metadata"
)

var storageNames = []string{
	usersBucketNATS, groupsBucketNATS, foldersBucketNATS, adminsBucketNATS, apiKeysBucketNATS, sharesBucketNATS,
	actionsBucketNATS, rulesBucketNATS, rolesBucketNATS, ipListsBucketNATS, configsBucketNATS, dbVersionBucketNATS,
	dbVersionKeyNATS, dbMetadataNATS,
}

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

	for _, name := range storageNames {
		subBucket, err := db.createBucket(db.js, name)
		if err != nil {
			providerLog(logger.LevelError, "error creating nats database handler, bucket %q, error: %v", name, err)
			return err
		}
		db.kvStore[name] = subBucket
	}

	provider = db
	return err
}

func getNATSOptions() ([]nats.Option, error) {
	var opts []nats.Option

	// tlsConfig := &tls.Config{}
	//
	// if config.RootCert != "" {
	// 	rootCAs, err := x509.SystemCertPool()
	// 	if err != nil {
	// 		rootCAs = x509.NewCertPool()
	// 	}
	// 	rootCrt, err := os.ReadFile(config.RootCert)
	// 	if err != nil {
	// 		return nil, fmt.Errorf("unable to load root certificate %q: %w", config.RootCert, err)
	// 	}
	// 	if !rootCAs.AppendCertsFromPEM(rootCrt) {
	// 		return nil, fmt.Errorf("unable to parse root certificate %q", config.RootCert)
	// 	}
	// 	tlsConfig.RootCAs = rootCAs
	// }
	//
	// if config.ClientCert != "" && config.ClientKey != "" {
	// 	cert, err := tls.LoadX509KeyPair(config.ClientCert, config.ClientKey)
	// 	if err != nil {
	// 		return nil, fmt.Errorf("unable to load key pair %q, %q: %w", config.ClientCert, config.ClientKey, err)
	// 	}
	// 	tlsConfig.Certificates = []tls.Certificate{cert}
	// }
	//
	// if config.SSLMode == 2 || config.SSLMode == 3 {
	// 	tlsConfig.InsecureSkipVerify = true
	// }
	//
	// if !filepath.IsAbs(config.Host) && !config.DisableSNI {
	// 	tlsConfig.ServerName = config.Host
	// }
	//
	// providerLog(logger.LevelInfo, "registering custom TLS config, root cert %q, client cert %q, client key %q, disable SNI? %v", config.RootCert, config.ClientCert, config.ClientKey, config.DisableSNI)
	//
	// opts = append(opts, nats.Secure(tlsConfig))
	return opts, nil
}

func getNATSConnectionString(redactedPwd bool) (string, error) {
	// username := config.Username
	// password := config.Password
	//
	// if redactedPwd && password != "" {
	// 	password = "[redacted]"
	// }
	//
	// host := config.Host
	// port := config.Port
	//
	// userInfo := ""
	// if username != "" {
	// 	userInfo = username
	// 	if password != "" {
	// 		userInfo += ":" + password
	// 	}
	// 	userInfo += "@"
	// }
	//
	// return fmt.Sprintf("nats://%s%s:%d", userInfo, host, port), nil
	return nats.DefaultURL, nil
}

func (p *NATSProvider) validateUserAndTLSCert(username, protocol string, tlsCert *x509.Certificate) (User, error) {
	var user User
	if tlsCert == nil {
		return user, errors.New("TLS certificate cannot be null or empty")
	}

	user, err := p.userExists(username, "")
	if err != nil {
		providerLog(logger.LevelWarn, "error authenticating user %q: %v", username, err)
		return user, err
	}

	return checkUserAndTLSCertificate(&user, protocol, tlsCert)
}

func (p *NATSProvider) validateAdminAndPass(username, password, ip string) (Admin, error) {
	admin, err := p.adminExists(username)
	if err != nil {
		providerLog(logger.LevelWarn, "error authenticating admin %q: %v", username, err)
		return admin, err
	}
	err = admin.checkUserAndPass(password, ip)
	return admin, err
}

func (p *NATSProvider) getDefenderHosts(_ int64, _ int) ([]DefenderEntry, error) {
	return nil, ErrNotImplemented
}

func (p *NATSProvider) getDefenderHostByIP(_ string, _ int64) (DefenderEntry, error) {
	return DefenderEntry{}, ErrNotImplemented
}

func (p *NATSProvider) isDefenderHostBanned(_ string) (DefenderEntry, error) {
	return DefenderEntry{}, ErrNotImplemented
}

func (p *NATSProvider) updateDefenderBanTime(_ string, _ int) error {
	return ErrNotImplemented
}

func (p *NATSProvider) deleteDefenderHost(_ string) error {
	return ErrNotImplemented
}

func (p *NATSProvider) addDefenderEvent(_ string, _ int) error {
	return ErrNotImplemented
}

func (p *NATSProvider) setDefenderBanTime(_ string, _ int64) error {
	return ErrNotImplemented
}

func (p *NATSProvider) cleanupDefender(_ int64) error {
	return ErrNotImplemented
}

func (p *NATSProvider) addActiveTransfer(_ ActiveTransfer) error {
	return ErrNotImplemented
}

func (p *NATSProvider) updateActiveTransferSizes(_, _, _ int64, _ string) error {
	return ErrNotImplemented
}

func (p *NATSProvider) removeActiveTransfer(_ int64, _ string) error {
	return ErrNotImplemented
}

func (p *NATSProvider) cleanupActiveTransfers(_ time.Time) error {
	return ErrNotImplemented
}

func (p *NATSProvider) getActiveTransfers(_ time.Time) ([]ActiveTransfer, error) {
	return nil, ErrNotImplemented
}

func (p *NATSProvider) addSharedSession(_ Session) error {
	return ErrNotImplemented
}

func (p *NATSProvider) deleteSharedSession(_ string, _ SessionType) error {
	return ErrNotImplemented
}

func (p *NATSProvider) getSharedSession(_ string, _ SessionType) (Session, error) {
	return Session{}, ErrNotImplemented
}

func (p *NATSProvider) cleanupSharedSessions(_ SessionType, _ int64) error {
	return ErrNotImplemented
}

func (p *NATSProvider) getEventActions(limit, offset int, order string, _ bool) ([]BaseEventAction, error) {
	if limit <= 0 {
		return nil, nil
	}

	bucket, err := p.getActionsBucket()
	if err != nil {
		return nil, err
	}

	keys, err := bucket.Keys()
	if err != nil {
		return nil, err
	}

	if order == OrderDESC {
		slices.Reverse(keys)
	}

	actions := make([]BaseEventAction, 0, limit)
	itNum := 0

	for _, k := range keys {
		itNum++
		if itNum <= offset {
			continue
		}

		entry, err := bucket.Get(k)
		if err != nil && errors.Is(err, nats.ErrKeyNotFound) {
			continue
		}

		wAction := wrapper.NewWrapper(BaseEventAction{})
		if err := wAction.UnmarshalJSON(entry.Value()); err != nil {
			return nil, err
		}

		action := wAction.Get()

		action.PrepareForRendering()
		actions = append(actions, action)

		if len(actions) >= limit {
			break
		}
	}

	return actions, nil
}

func (p *NATSProvider) getTaskByName(_ string) (Task, error) {
	return Task{}, ErrNotImplemented
}

func (p *NATSProvider) addTask(_ string) error {
	return ErrNotImplemented
}

func (p *NATSProvider) updateTask(_ string, _ int64) error {
	return ErrNotImplemented
}

func (p *NATSProvider) updateTaskTimestamp(_ string) error {
	return ErrNotImplemented
}

func (p *NATSProvider) addNode() error {
	return ErrNotImplemented
}

func (p *NATSProvider) getNodeByName(_ string) (Node, error) {
	return Node{}, ErrNotImplemented
}

func (p *NATSProvider) getNodes() ([]Node, error) {
	return nil, ErrNotImplemented
}

func (p *NATSProvider) updateNodeTimestamp() error {
	return ErrNotImplemented
}

func (p *NATSProvider) cleanupNodes() error {
	return ErrNotImplemented
}

func (p *NATSProvider) resetDatabase() error {
	for _, name := range storageNames {
		kv, err := p.js.KeyValue(name)
		if err != nil {
			if errors.Is(err, nats.ErrBucketNotFound) {
				continue
			}
			return fmt.Errorf("unable to get bucket %v: %w", name, err)
		}
		if err := kv.Purge(name); err != nil {
			return fmt.Errorf("unable to purge bucket %v: %w", name, err)
		}
	}
	return nil
}

func (p *NATSProvider) createBucket(js nats.JetStreamContext, bucket string) (nats.KeyValue, error) {
	kv, err := js.CreateKeyValue(&nats.KeyValueConfig{Bucket: bucket, Compression: true})
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
	if err != nil && errors.Is(err, nats.ErrKeyNotFound) {
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

	if entry == nil && entry.Revision() == 0 {
		_, err := bucket.Put(keyID, data)
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
	if err != nil && errors.Is(err, nats.ErrKeyNotFound) {
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
	if err != nil && errors.Is(err, nats.ErrKeyNotFound) {
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
	if err != nil && errors.Is(err, nats.ErrKeyNotFound) {
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

	if entry == nil && entry.Revision() == 0 {
		_, _ = bucket.Put(username, data)
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
	if err != nil && errors.Is(err, nats.ErrKeyNotFound) {
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

	if entry == nil && entry.Revision() == 0 {
		_, err := bucket.Put(username, data)
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
	if err != nil && errors.Is(err, nats.ErrKeyNotFound) {
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

	if entry == nil && entry.Revision() == 0 {
		_, err := bucket.Put(username, data)
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
	if err != nil && errors.Is(err, nats.ErrKeyNotFound) {
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

	if entry == nil && entry.Revision() == 0 {
		_, err := bucket.Put(username, data)
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
	if err != nil && errors.Is(err, nats.ErrKeyNotFound) {
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

	if entry == nil && entry.Revision() == 0 {
		_, err := bucket.Put(username, data)
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
	if err != nil && errors.Is(err, nats.ErrKeyNotFound) {
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
	if err != nil && !errors.Is(err, nats.ErrKeyNotFound) {
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
	wAdmin.Set(*admin)

	data, err := wAdmin.MarshalJSON()
	if err != nil {
		return err
	}

	if entry == nil && entry.Revision() == 0 {
		_, err := bucket.Put(admin.Username, data)
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
	if err != nil && errors.Is(err, nats.ErrKeyNotFound) {
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

	if entry == nil && entry.Revision() == 0 {
		_, err := bucket.Put(admin.Username, data)
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
	if err != nil && errors.Is(err, nats.ErrKeyNotFound) {
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
	if err != nil && errors.Is(err, nats.ErrKeyNotFound) {
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
		if err != nil && errors.Is(err, nats.ErrKeyNotFound) {
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
		if err != nil && errors.Is(err, nats.ErrKeyNotFound) {
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
	if err != nil && errors.Is(err, nats.ErrKeyNotFound) {
		return User{}, util.NewRecordNotFoundError(fmt.Sprintf("username %q does not exist", username))
	}

	foldersBucket, err := p.getFoldersBucket()
	if err != nil {
		return User{}, err
	}

	user, err := p.joinUserAndFolders(entry.Value(), foldersBucket)
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
	if err == nil && errors.Is(err, nats.ErrKeyNotFound) {
		return util.NewI18nError(fmt.Errorf("%w: username %v already exists", ErrDuplicatedKey, user.Username), util.I18nErrorDuplicatedUsername)
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

	if entry == nil && entry.Revision() == 0 {
		_, err := bucket.Put(user.Username, data)
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
	if err != nil && errors.Is(err, nats.ErrKeyNotFound) {
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

	setLastUserUpdate()

	if entry == nil && entry.Revision() == 0 {
		_, err := bucket.Put(user.Username, data)
		return err
	}

	if _, err := bucket.Update(user.Username, data, entry.Revision()); err != nil {
		return err
	}

	return nil
}

func (p *NATSProvider) deleteUser(user User, _ bool) error {
	bucket, err := p.getUsersBucket()
	if err != nil {
		return err
	}

	entry, err := bucket.Get(user.Username)
	if err != nil && errors.Is(err, nats.ErrKeyNotFound) {
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
	if err != nil && errors.Is(err, nats.ErrKeyNotFound) {
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

	if entry == nil && entry.Revision() == 0 {
		_, err := bucket.Put(username, data)
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
		if err != nil && errors.Is(err, nats.ErrKeyNotFound) {
			continue
		}

		user, err := p.joinUserAndFolders(entry.Value(), foldersBucket)
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

func (p *NATSProvider) getConfigsBucket() (nats.KeyValue, error) {
	kv, ok := p.kvStore[dbMetadataNATS]
	if !ok {
		return nil, fmt.Errorf("bucket %q not found", dbMetadataNATS)
	}
	return kv, nil
}

func (p *NATSProvider) folderExistsInternal(name string, bucket nats.KeyValue) (vfs.BaseVirtualFolder, error) {
	entry, err := bucket.Get(name)
	if err != nil && errors.Is(err, nats.ErrKeyNotFound) {
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
		if err != nil && errors.Is(err, nats.ErrKeyNotFound) {
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
		if err != nil && errors.Is(err, nats.ErrKeyNotFound) {
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
		if err != nil && errors.Is(err, nats.ErrKeyNotFound) {
			continue
		}

		user, err := p.joinUserAndFolders(entry.Value(), foldersBucket)
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
		if err != nil && errors.Is(err, nats.ErrKeyNotFound) {
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
		if err != nil && errors.Is(err, nats.ErrKeyNotFound) {
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
	if err != nil && errors.Is(err, nats.ErrKeyNotFound) {
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

	if entry == nil && entry.Revision() == 0 {
		_, err := bucket.Put(folder.Name, data)
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
	if err != nil && errors.Is(err, nats.ErrKeyNotFound) {
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

	if entry == nil && entry.Revision() == 0 {
		_, err := bucket.Put(folder.Name, data)
		return err
	}

	_, err = bucket.Update(folder.Name, data, entry.Revision())
	return err
}

func (p *NATSProvider) deleteFolderMappings(folder vfs.BaseVirtualFolder) error {
	usersBucket, err := p.getUsersBucket()
	if err != nil {
		return err
	}

	groupsBucket, err := p.getGroupsBucket()
	if err != nil {
		return err
	}

	for _, username := range folder.Users {
		entry, err := usersBucket.Get(username)
		if err != nil {
			continue
		}

		wUser := wrapper.NewWrapper(User{})
		if err = wUser.UnmarshalJSON(entry.Value()); err != nil {
			return err
		}

		user := wUser.Get()

		var folders []vfs.VirtualFolder
		for _, userFolder := range user.VirtualFolders {
			if folder.Name != userFolder.Name {
				folders = append(folders, userFolder)
			}
		}

		user.VirtualFolders = folders

		data, err := wUser.MarshalJSON()
		if err != nil {
			return err
		}

		_, err = usersBucket.Update(user.Username, data, entry.Revision())
		if err != nil {
			return err
		}
	}

	for _, groupname := range folder.Groups {
		entry, err := groupsBucket.Get(groupname)
		if err != nil {
			continue
		}

		wGroup := wrapper.NewWrapper(Group{})
		if err = wGroup.UnmarshalJSON(entry.Value()); err != nil {
			return err
		}

		group := wGroup.Get()

		var folders []vfs.VirtualFolder
		for _, groupFolder := range group.VirtualFolders {
			if folder.Name != groupFolder.Name {
				folders = append(folders, groupFolder)
			}
		}

		group.VirtualFolders = folders

		data, err := wGroup.MarshalJSON()
		if err != nil {
			return err
		}

		_, err = groupsBucket.Update(group.Name, data, entry.Revision())
		if err != nil {
			return err
		}
	}
	return nil
}

func (p *NATSProvider) deleteFolder(baseFolder vfs.BaseVirtualFolder) error {
	bucket, err := p.getFoldersBucket()
	if err != nil {
		return err
	}

	entry, err := bucket.Get(baseFolder.Name)
	if err != nil && errors.Is(err, nats.ErrKeyNotFound) {
		return util.NewRecordNotFoundError(fmt.Sprintf("folder %v does not exist", baseFolder.Name))
	}

	wFolder := wrapper.NewWrapper(vfs.BaseVirtualFolder{})
	if err = wFolder.UnmarshalJSON(entry.Value()); err != nil {
		return err
	}

	folder := wFolder.Get()

	if err = p.deleteFolderMappings(folder); err != nil {
		return err
	}
	return bucket.Delete(folder.Name)
}

func (p *NATSProvider) updateFolderQuota(name string, filesAdd int, sizeAdd int64, reset bool) error {
	bucket, err := p.getFoldersBucket()
	if err != nil {
		return err
	}

	entry, err := bucket.Get(name)
	if err != nil && errors.Is(err, nats.ErrKeyNotFound) {
		return util.NewRecordNotFoundError(fmt.Sprintf("folder %q does not exist, unable to update quota", name))
	}

	wFolder := wrapper.NewWrapper(vfs.BaseVirtualFolder{})
	if err = wFolder.UnmarshalJSON(entry.Value()); err != nil {
		return err
	}

	folder := wFolder.Get()

	if reset {
		folder.UsedQuotaSize = sizeAdd
		folder.UsedQuotaFiles = filesAdd
	} else {
		folder.UsedQuotaSize += sizeAdd
		folder.UsedQuotaFiles += filesAdd
	}
	folder.LastQuotaUpdate = util.GetTimeAsMsSinceEpoch(time.Now())

	data, err := wFolder.MarshalJSON()
	if err != nil {
		return err
	}

	_, err = bucket.Update(folder.Name, data, entry.Revision())
	return err
}

func (p *NATSProvider) getUsedFolderQuota(name string) (int, int64, error) {
	folder, err := p.getFolderByName(name)
	if err != nil {
		providerLog(logger.LevelError, "unable to get quota for folder %q error: %v", name, err)
		return 0, 0, err
	}

	return folder.UsedQuotaFiles, folder.UsedQuotaSize, err
}

func (p *NATSProvider) getGroups(limit, offset int, order string, _ bool) ([]Group, error) {
	groups := make([]Group, 0, limit)
	if limit <= 0 {
		return groups, nil
	}

	bucket, err := p.getGroupsBucket()
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
		return groups, nil
	}

	if end > len(keys) {
		end = len(keys)
	}

	for _, key := range keys[start:end] {
		entry, err := bucket.Get(key)
		if err != nil {
			continue
		}

		group, err := p.joinGroupAndFolders(entry.Value(), foldersBucket)
		if err != nil {
			return nil, err
		}

		group.PrepareForRendering()
		groups = append(groups, group)
	}
	return groups, nil
}

func (p *NATSProvider) getGroupsWithNames(names []string) ([]Group, error) {
	var groups []Group
	bucket, err := p.getGroupsBucket()
	if err != nil {
		return nil, err
	}

	foldersBucket, err := p.getFoldersBucket()
	if err != nil {
		return nil, err
	}

	for _, name := range names {
		entry, err := bucket.Get(name)
		if err != nil {
			continue
		}

		group, err := p.joinGroupAndFolders(entry.Value(), foldersBucket)
		if err != nil {
			return nil, err
		}

		groups = append(groups, group)
	}
	return groups, nil
}

func (p *NATSProvider) getUsersInGroups(names []string) ([]string, error) {
	var usernames []string
	bucket, err := p.getGroupsBucket()
	if err != nil {
		return nil, err
	}

	for _, name := range names {
		entry, err := bucket.Get(name)
		if err != nil {
			continue
		}

		wGroup := wrapper.NewWrapper(Group{})
		if err = wGroup.UnmarshalJSON(entry.Value()); err != nil {
			return nil, err
		}

		group := wGroup.Get()
		usernames = append(usernames, group.Users...)
	}
	return usernames, nil
}

func (p *NATSProvider) groupExists(name string) (Group, error) {
	bucket, err := p.getGroupsBucket()
	if err != nil {
		return Group{}, err
	}

	entry, err := bucket.Get(name)
	if err != nil && errors.Is(err, nats.ErrKeyNotFound) {
		return Group{}, util.NewRecordNotFoundError(fmt.Sprintf("group %q does not exist", name))
	}

	foldersBucket, err := p.getFoldersBucket()
	if err != nil {
		return Group{}, err
	}
	return p.joinGroupAndFolders(entry.Value(), foldersBucket)
}

func (p *NATSProvider) addGroup(group *Group) error {
	if err := group.validate(); err != nil {
		return err
	}

	bucket, err := p.getGroupsBucket()
	if err != nil {
		return err
	}

	entry, err := bucket.Get(group.Name)
	if err == nil && errors.Is(err, nats.ErrKeyNotFound) {
		return util.NewI18nError(fmt.Errorf("%w: group %q already exists", ErrDuplicatedKey, group.Name), util.I18nErrorDuplicatedUsername)
	}

	group.ID = time.Now().UnixNano()
	group.CreatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
	group.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
	group.Users = nil
	group.Admins = nil

	sort.Slice(group.VirtualFolders, func(i, j int) bool {
		return group.VirtualFolders[i].Name < group.VirtualFolders[j].Name
	})

	foldersBucket, err := p.getFoldersBucket()
	if err != nil {
		return err
	}

	for idx := range group.VirtualFolders {
		if err = p.addRelationToFolderMapping(group.VirtualFolders[idx].Name, nil, group, foldersBucket); err != nil {
			return err
		}
	}

	wGroup := wrapper.NewWrapper(*group)
	data, err := wGroup.MarshalJSON()
	if err != nil {
		return err
	}

	_, err = bucket.Update(group.Name, data, entry.Revision())
	return err
}

func (p *NATSProvider) updateGroup(group *Group) error {
	if err := group.validate(); err != nil {
		return err
	}

	bucket, err := p.getGroupsBucket()
	if err != nil {
		return err
	}

	entry, err := bucket.Get(group.Name)
	if err != nil && errors.Is(err, nats.ErrKeyNotFound) {
		return util.NewRecordNotFoundError(fmt.Sprintf("group %q does not exist", group.Name))
	}

	wOldGroup := wrapper.NewWrapper(Group{})
	if err = wOldGroup.UnmarshalJSON(entry.Value()); err != nil {
		return err
	}

	oldGroup := wOldGroup.Get()

	foldersBucket, err := p.getFoldersBucket()
	if err != nil {
		return err
	}

	for idx := range oldGroup.VirtualFolders {
		if err = p.removeRelationFromFolderMapping(oldGroup.VirtualFolders[idx], "", oldGroup.Name, foldersBucket); err != nil {
			return err
		}
	}

	sort.Slice(group.VirtualFolders, func(i, j int) bool {
		return group.VirtualFolders[i].Name < group.VirtualFolders[j].Name
	})

	for idx := range group.VirtualFolders {
		if err = p.addRelationToFolderMapping(group.VirtualFolders[idx].Name, nil, group, foldersBucket); err != nil {
			return err
		}
	}

	group.ID = oldGroup.ID
	group.CreatedAt = oldGroup.CreatedAt
	group.Users = oldGroup.Users
	group.Admins = oldGroup.Admins
	group.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())

	wGroup := wrapper.NewWrapper(Group{})
	data, err := wGroup.MarshalJSON()
	if err != nil {
		return err
	}

	_, err = bucket.Update(group.Name, data, entry.Revision())
	return err
}

func (p *NATSProvider) deleteGroup(group Group) error {
	bucket, err := p.getGroupsBucket()
	if err != nil {
		return err
	}

	entry, err := bucket.Get(group.Name)
	if err != nil && errors.Is(err, nats.ErrKeyNotFound) {
		return util.NewRecordNotFoundError(fmt.Sprintf("group %q does not exist", group.Name))
	}

	wOldGroup := wrapper.NewWrapper(Group{})
	if err = wOldGroup.UnmarshalJSON(entry.Value()); err != nil {
		return err
	}

	oldGroup := wOldGroup.Get()

	if len(oldGroup.Users) > 0 {
		return util.NewValidationError(fmt.Sprintf("the group %q is referenced, it cannot be removed", oldGroup.Name))
	}

	if len(oldGroup.VirtualFolders) > 0 {
		foldersBucket, err := p.getFoldersBucket()
		if err != nil {
			return err
		}

		for idx := range oldGroup.VirtualFolders {
			if err = p.removeRelationFromFolderMapping(oldGroup.VirtualFolders[idx], "", oldGroup.Name, foldersBucket); err != nil {
				return err
			}
		}
	}

	if len(oldGroup.Admins) > 0 {
		adminsBucket, err := p.getAdminsBucket()
		if err != nil {
			return err
		}

		for idx := range oldGroup.Admins {
			if err = p.removeGroupFromAdminMapping(oldGroup.Name, oldGroup.Admins[idx], adminsBucket); err != nil {
				return err
			}
		}
	}
	return bucket.Delete(group.Name)
}

func (p *NATSProvider) dumpGroups() ([]Group, error) {
	groups := make([]Group, 0, 50)
	bucket, err := p.getGroupsBucket()
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

		group, err := p.joinGroupAndFolders(entry.Value(), foldersBucket)
		if err != nil {
			return nil, err
		}

		groups = append(groups, group)
	}
	return groups, nil
}

func (p *NATSProvider) apiKeyExists(keyID string) (APIKey, error) {
	bucket, err := p.getAPIKeysBucket()
	if err != nil {
		return APIKey{}, err
	}

	entry, err := bucket.Get(keyID)
	if err != nil && errors.Is(err, nats.ErrKeyNotFound) {
		return APIKey{}, util.NewRecordNotFoundError(fmt.Sprintf("API key %v does not exist", keyID))
	}

	wAPIKey := wrapper.NewWrapper(APIKey{})
	if err = wAPIKey.UnmarshalJSON(entry.Value()); err != nil {
		return APIKey{}, err
	}
	return wAPIKey.Get(), nil
}

func (p *NATSProvider) updateAPIKey(apiKey *APIKey) error {
	if err := apiKey.validate(); err != nil {
		return err
	}

	bucket, err := p.getAPIKeysBucket()
	if err != nil {
		return err
	}

	entry, err := bucket.Get(apiKey.KeyID)
	if err != nil && errors.Is(err, nats.ErrKeyNotFound) {
		return util.NewRecordNotFoundError(fmt.Sprintf("API key %v does not exist", apiKey.KeyID))
	}

	wOldAPIKey := wrapper.NewWrapper(APIKey{})
	if err = wOldAPIKey.UnmarshalJSON(entry.Value()); err != nil {
		return err
	}

	oldAPIKey := wOldAPIKey.Get()

	apiKey.ID = oldAPIKey.ID
	apiKey.KeyID = oldAPIKey.KeyID
	apiKey.Key = oldAPIKey.Key
	apiKey.CreatedAt = oldAPIKey.CreatedAt
	apiKey.LastUseAt = oldAPIKey.LastUseAt
	apiKey.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())

	if apiKey.User != "" {
		if _, err := p.userExists(apiKey.User, ""); err != nil {
			return fmt.Errorf("%w: related user %q does not exists", ErrForeignKeyViolated, apiKey.User)
		}
	}
	if apiKey.Admin != "" {
		if _, err := p.adminExists(apiKey.Admin); err != nil {
			return fmt.Errorf("%w: related admin %q does not exists", ErrForeignKeyViolated, apiKey.Admin)
		}
	}

	wAPIKey := wrapper.NewWrapper(APIKey{})
	data, err := wAPIKey.MarshalJSON()
	if err != nil {
		return err
	}

	_, err = bucket.Update(apiKey.KeyID, data, entry.Revision())
	return err
}

func (p *NATSProvider) deleteAPIKey(apiKey APIKey) error {
	bucket, err := p.getAPIKeysBucket()
	if err != nil {
		return err
	}

	if _, err = bucket.Get(apiKey.KeyID); err != nil && errors.Is(err, nats.ErrKeyNotFound) {
		return util.NewRecordNotFoundError(fmt.Sprintf("API key %v does not exist", apiKey.KeyID))
	}
	return bucket.Delete(apiKey.KeyID)
}

func (p *NATSProvider) getAPIKeys(limit int, offset int, order string) ([]APIKey, error) {
	apiKeys := make([]APIKey, 0, limit)

	bucket, err := p.getAPIKeysBucket()
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
		return apiKeys, nil
	}

	if end > len(keys) {
		end = len(keys)
	}

	for _, key := range keys[start:end] {
		entry, err := bucket.Get(key)
		if err != nil {
			continue
		}

		wAPIKey := wrapper.NewWrapper(APIKey{})
		if err = wAPIKey.UnmarshalJSON(entry.Value()); err != nil {
			return nil, err
		}

		apiKey := wAPIKey.Get()
		apiKey.HideConfidentialData()
		apiKeys = append(apiKeys, apiKey)
	}
	return apiKeys, nil
}

func (p *NATSProvider) dumpAPIKeys() ([]APIKey, error) {
	apiKeys := make([]APIKey, 0, 30)
	bucket, err := p.getAPIKeysBucket()
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

		wAPIKey := wrapper.NewWrapper(APIKey{})
		if err = wAPIKey.UnmarshalJSON(entry.Value()); err != nil {
			return nil, err
		}

		apiKeys = append(apiKeys, wAPIKey.Get())
	}
	return apiKeys, nil
}

func (p *NATSProvider) shareExists(shareID, username string) (Share, error) {
	bucket, err := p.getSharesBucket()
	if err != nil {
		return Share{}, err
	}

	entry, err := bucket.Get(shareID)
	if err != nil && errors.Is(err, nats.ErrKeyNotFound) {
		return Share{}, util.NewRecordNotFoundError(fmt.Sprintf("Share %v does not exist", shareID))
	}

	wShare := wrapper.NewWrapper(Share{})
	if err = wShare.UnmarshalJSON(entry.Value()); err != nil {
		return Share{}, err
	}

	share := wShare.Get()

	if username != "" && share.Username != username {
		return Share{}, util.NewRecordNotFoundError(fmt.Sprintf("Share %v does not exist", shareID))
	}
	return share, nil
}

func (p *NATSProvider) addShare(share *Share) error {
	if err := share.validate(); err != nil {
		return err
	}

	bucket, err := p.getSharesBucket()
	if err != nil {
		return err
	}

	entry, err := bucket.Get(share.ShareID)
	if err == nil && errors.Is(err, nats.ErrKeyNotFound) {
		return fmt.Errorf("share %q already exists", share.ShareID)
	}

	share.ID = time.Now().UnixNano()

	if !share.IsRestore {
		share.CreatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
		share.UpdatedAt = share.CreatedAt
		share.LastUseAt = 0
		share.UsedTokens = 0
	}

	if share.CreatedAt == 0 {
		share.CreatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
	}

	if share.UpdatedAt == 0 {
		share.UpdatedAt = share.CreatedAt
	}

	if _, err := p.userExists(share.Username, ""); err != nil {
		return util.NewValidationError(fmt.Sprintf("related user %q does not exists", share.Username))
	}

	wShare := wrapper.NewWrapper(Share{})
	data, err := wShare.MarshalJSON()
	if err != nil {
		return err
	}

	_, err = bucket.Update(share.ShareID, data, entry.Revision())
	return err
}

func (p *NATSProvider) addAPIKey(apiKey *APIKey) error {
	if err := apiKey.validate(); err != nil {
		return err
	}

	bucket, err := p.getAPIKeysBucket()
	if err != nil {
		return err
	}

	apiKey.ID = time.Now().UnixNano()
	apiKey.CreatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
	apiKey.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
	apiKey.LastUseAt = 0

	if apiKey.User != "" {
		if _, err := p.userExists(apiKey.User, ""); err != nil {
			return fmt.Errorf("%w: related user %q does not exists", ErrForeignKeyViolated, apiKey.User)
		}
	}

	if apiKey.Admin != "" {
		if _, err := p.adminExists(apiKey.Admin); err != nil {
			return fmt.Errorf("%w: related admin %q does not exists", ErrForeignKeyViolated, apiKey.Admin)
		}
	}

	wAPIKey := wrapper.NewWrapper(*apiKey)
	data, err := wAPIKey.MarshalJSON()
	if err != nil {
		return err
	}

	entry, err := bucket.Get(apiKey.KeyID)
	if err == nil {
		_, err = bucket.Update(apiKey.KeyID, data, entry.Revision())
	} else {
		_, err = bucket.Create(apiKey.KeyID, data)
	}
	return err
}

func (p *NATSProvider) getShares(limit int, offset int, order, username string) ([]Share, error) {
	shares := make([]Share, 0, limit)
	bucket, err := p.getSharesBucket()
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

	itNum := 0
	for _, key := range keys {
		entry, err := bucket.Get(key)
		if err != nil {
			continue
		}

		wShare := wrapper.NewWrapper(Share{})
		if err = wShare.UnmarshalJSON(entry.Value()); err != nil {
			return nil, err
		}

		share := wShare.Get()

		if share.Username != username {
			continue
		}

		itNum++
		if itNum <= offset {
			continue
		}

		share.HideConfidentialData()
		shares = append(shares, share)
		if len(shares) >= limit {
			break
		}
	}
	return shares, nil
}

func (p *NATSProvider) dumpShares() ([]Share, error) {
	shares := make([]Share, 0, 30)
	bucket, err := p.getSharesBucket()
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

		wShare := wrapper.NewWrapper(Share{})
		if err = wShare.UnmarshalJSON(entry.Value()); err != nil {
			return nil, err
		}
		shares = append(shares, wShare.Get())
	}
	return shares, nil
}

func (p *NATSProvider) updateShareLastUse(shareID string, numTokens int) error {
	bucket, err := p.getSharesBucket()
	if err != nil {
		return err
	}

	entry, err := bucket.Get(shareID)
	if err != nil && errors.Is(err, nats.ErrKeyNotFound) {
		return util.NewRecordNotFoundError(fmt.Sprintf("share %q does not exist, unable to update last use", shareID))
	}

	wShare := wrapper.NewWrapper(Share{})
	if err = wShare.UnmarshalJSON(entry.Value()); err != nil {
		return err
	}

	share := wShare.Get()

	share.LastUseAt = util.GetTimeAsMsSinceEpoch(time.Now())
	share.UsedTokens += numTokens

	data, err := wShare.MarshalJSON()
	if err != nil {
		return err
	}

	_, err = bucket.Update(shareID, data, entry.Revision())
	if err != nil {
		providerLog(logger.LevelWarn, "error updating last use for share %q: %v", shareID, err)
		return err
	}

	providerLog(logger.LevelDebug, "last use updated for share %q", shareID)
	return nil
}

func (p *NATSProvider) updateShare(share *Share) error {
	if err := share.validate(); err != nil {
		return err
	}

	bucket, err := p.getSharesBucket()
	if err != nil {
		return err
	}

	entry, err := bucket.Get(share.ShareID)
	if err != nil && errors.Is(err, nats.ErrKeyNotFound) {
		return util.NewRecordNotFoundError(fmt.Sprintf("Share %v does not exist", share.ShareID))
	}

	wOldShare := wrapper.NewWrapper(Share{})
	if err = wOldShare.UnmarshalJSON(entry.Value()); err != nil {
		return err
	}

	oldShare := wOldShare.Get()

	if oldShare.Username != share.Username {
		return util.NewRecordNotFoundError(fmt.Sprintf("Share %v does not exist", share.ShareID))
	}

	share.ID = oldShare.ID
	share.ShareID = oldShare.ShareID
	if !share.IsRestore {
		share.UsedTokens = oldShare.UsedTokens
		share.CreatedAt = oldShare.CreatedAt
		share.LastUseAt = oldShare.LastUseAt
		share.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
	}
	if share.CreatedAt == 0 {
		share.CreatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
	}
	if share.UpdatedAt == 0 {
		share.UpdatedAt = share.CreatedAt
	}

	if _, err := p.userExists(share.Username, ""); err != nil {
		return util.NewValidationError(fmt.Sprintf("related user %q does not exists", share.Username))
	}

	wShare := wrapper.NewWrapper(*share)
	data, err := wShare.MarshalJSON()
	if err != nil {
		return err
	}

	_, err = bucket.Update(share.ShareID, data, entry.Revision())
	return err
}

func (p *NATSProvider) deleteShare(share Share) error {
	bucket, err := p.getSharesBucket()
	if err != nil {
		return err
	}

	entry, err := bucket.Get(share.ShareID)
	if err != nil && errors.Is(err, nats.ErrKeyNotFound) {
		return util.NewRecordNotFoundError(fmt.Sprintf("Share %v does not exist", share.ShareID))
	}

	wOldShare := wrapper.NewWrapper(Share{})
	if err = wOldShare.UnmarshalJSON(entry.Value()); err != nil {
		return err
	}

	oldShare := wOldShare.Get()

	if oldShare.Username != share.Username {
		return util.NewRecordNotFoundError(fmt.Sprintf("Share %v does not exist", share.ShareID))
	}

	_, err = bucket.Update(share.ShareID, nil, entry.Revision())
	return err
}

func (p *NATSProvider) dumpEventActions() ([]BaseEventAction, error) {
	actions := make([]BaseEventAction, 0, 50)
	bucket, err := p.getActionsBucket()
	if err != nil {
		return nil, err
	}

	keys, err := bucket.Keys()
	if err != nil && errors.Is(err, nats.ErrKeyNotFound) {
		return nil, err
	}

	for _, key := range keys {
		entry, err := bucket.Get(key)
		if err != nil {
			continue
		}

		wAction := wrapper.NewWrapper(BaseEventAction{})
		if err = wAction.UnmarshalJSON(entry.Value()); err != nil {
			return nil, err
		}

		actions = append(actions, wAction.Get())
	}
	return actions, nil
}

func (p *NATSProvider) eventActionExists(name string) (BaseEventAction, error) {
	bucket, err := p.getActionsBucket()
	if err != nil {
		return BaseEventAction{}, err
	}

	entry, err := bucket.Get(name)
	if err != nil && errors.Is(err, nats.ErrKeyNotFound) {
		return BaseEventAction{}, util.NewRecordNotFoundError(fmt.Sprintf("action %q does not exist", name))
	}

	wAction := wrapper.NewWrapper(BaseEventAction{})
	if err = wAction.UnmarshalJSON(entry.Value()); err != nil {
		return BaseEventAction{}, err
	}
	return wAction.Get(), nil
}

func (p *NATSProvider) addEventAction(action *BaseEventAction) error {
	if err := action.validate(); err != nil {
		return err
	}

	bucket, err := p.getActionsBucket()
	if err != nil {
		return err
	}

	if _, err := bucket.Get(action.Name); err == nil {
		return util.NewI18nError(fmt.Errorf("%w: event action %q already exists", ErrDuplicatedKey, action.Name), util.I18nErrorDuplicatedName)
	}

	action.ID = time.Now().UnixNano()
	action.Rules = nil

	wAction := wrapper.NewWrapper(*action)
	data, err := wAction.MarshalJSON()
	if err != nil {
		return err
	}

	_, err = bucket.Create(action.Name, data)
	return err
}

func (p *NATSProvider) updateEventAction(action *BaseEventAction) error {
	if err := action.validate(); err != nil {
		return err
	}

	bucket, err := p.getActionsBucket()
	if err != nil {
		return err
	}

	entry, err := bucket.Get(action.Name)
	if err != nil && errors.Is(err, nats.ErrKeyNotFound) {
		return util.NewRecordNotFoundError(fmt.Sprintf("event action %s does not exist", action.Name))
	}

	wOldAction := wrapper.NewWrapper(BaseEventAction{})
	if err = wOldAction.UnmarshalJSON(entry.Value()); err != nil {
		return err
	}

	oldAction := wOldAction.Get()

	action.ID = oldAction.ID
	action.Name = oldAction.Name
	action.Rules = nil

	if len(oldAction.Rules) > 0 {
		rulesBucket, err := p.getRulesBucket()
		if err != nil {
			return err
		}

		var relatedRules []string
		for _, ruleName := range oldAction.Rules {
			ruleEntry, err := rulesBucket.Get(ruleName)
			if err == nil {
				relatedRules = append(relatedRules, ruleName)
				wRule := wrapper.NewWrapper(EventRule{})
				if err := wRule.UnmarshalJSON(ruleEntry.Value()); err != nil {
					return err
				}

				rule := wRule.Get()
				rule.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())

				wUpdatedRule := wrapper.NewWrapper(rule)
				data, err := wUpdatedRule.MarshalJSON()
				if err != nil {
					return err
				}

				if _, err = rulesBucket.Update(rule.Name, data, ruleEntry.Revision()); err != nil {
					return err
				}
				setLastRuleUpdate()
			}
		}
		action.Rules = relatedRules
	}

	wAction := wrapper.NewWrapper(*action)
	data, err := wAction.MarshalJSON()
	if err != nil {
		return err
	}

	_, err = bucket.Update(action.Name, data, entry.Revision())
	return err
}

func (p *NATSProvider) deleteEventAction(action BaseEventAction) error {
	bucket, err := p.getActionsBucket()
	if err != nil {
		return err
	}

	entry, err := bucket.Get(action.Name)
	if err != nil && errors.Is(err, nats.ErrKeyNotFound) {
		return util.NewRecordNotFoundError(fmt.Sprintf("action %s does not exist", action.Name))
	}

	wOldAction := wrapper.NewWrapper(BaseEventAction{})
	if err = wOldAction.UnmarshalJSON(entry.Value()); err != nil {
		return err
	}

	oldAction := wOldAction.Get()

	if len(oldAction.Rules) > 0 {
		return util.NewValidationError(fmt.Sprintf("action %s is referenced, it cannot be removed", oldAction.Name))
	}

	_, err = bucket.Update(action.Name, nil, entry.Revision())
	return err
}

func (p *NATSProvider) getEventRules(limit, offset int, order string) ([]EventRule, error) {
	if limit <= 0 {
		return nil, nil
	}

	rules := make([]EventRule, 0, limit)
	bucket, err := p.getRulesBucket()
	if err != nil {
		return nil, err
	}

	actionsBucket, err := p.getActionsBucket()
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
		return rules, nil
	}

	if end > len(keys) {
		end = len(keys)
	}

	for _, key := range keys[start:end] {
		entry, err := bucket.Get(key)
		if err != nil {
			continue
		}

		rule, err := p.joinRuleAndActions(entry.Value(), actionsBucket)
		if err != nil {
			return nil, err
		}
		rule.PrepareForRendering()
		rules = append(rules, rule)
	}
	return rules, nil
}

func (p *NATSProvider) dumpEventRules() ([]EventRule, error) {
	rules := make([]EventRule, 0, 50)
	bucket, err := p.getRulesBucket()
	if err != nil {
		return nil, err
	}

	actionsBucket, err := p.getActionsBucket()
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

		rule, err := p.joinRuleAndActions(entry.Value(), actionsBucket)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

func (p *NATSProvider) getRecentlyUpdatedRules(after int64) ([]EventRule, error) {
	if getLastRuleUpdate() < after {
		return nil, nil
	}

	rules := make([]EventRule, 0, 10)
	rulesBucket, err := p.getRulesBucket()
	if err != nil {
		return nil, err
	}

	actionsBucket, err := p.getActionsBucket()
	if err != nil {
		return nil, err
	}

	keys, err := rulesBucket.Keys()
	if err != nil {
		return nil, err
	}

	for _, key := range keys {
		entry, err := rulesBucket.Get(key)
		if err != nil {
			continue
		}

		wRule := wrapper.NewWrapper(EventRule{})
		if err = wRule.UnmarshalJSON(entry.Value()); err != nil {
			return nil, err
		}

		rule := wRule.Get()

		if rule.UpdatedAt < after {
			continue
		}

		var actions []EventAction
		for idx := range rule.Actions {
			action := &rule.Actions[idx]
			actionEntry, err := actionsBucket.Get(action.Name)
			if err != nil {
				continue
			}

			wBaseAction := wrapper.NewWrapper(BaseEventAction{})
			if err = wBaseAction.UnmarshalJSON(actionEntry.Value()); err != nil {
				continue
			}

			baseAction := wBaseAction.Get()
			baseAction.Options.SetEmptySecretsIfNil()
			action.BaseEventAction = baseAction
			actions = append(actions, *action)
		}
		rule.Actions = actions
		rules = append(rules, rule)
	}
	return rules, nil
}

func (p *NATSProvider) eventRuleExists(name string) (EventRule, error) {
	rulesBucket, err := p.getRulesBucket()
	if err != nil {
		return EventRule{}, err
	}

	entry, err := rulesBucket.Get(name)
	if err != nil && errors.Is(err, nats.ErrKeyNotFound) {
		return EventRule{}, util.NewRecordNotFoundError(fmt.Sprintf("event rule %q does not exist", name))
	}

	actionsBucket, err := p.getActionsBucket()
	if err != nil {
		return EventRule{}, err
	}
	return p.joinRuleAndActions(entry.Value(), actionsBucket)
}

func (p *NATSProvider) addEventRule(rule *EventRule) error {
	if err := rule.validate(); err != nil {
		return err
	}

	rulesBucket, err := p.getRulesBucket()
	if err != nil {
		return err
	}

	actionsBucket, err := p.getActionsBucket()
	if err != nil {
		return err
	}

	_, err = rulesBucket.Get(rule.Name)
	if err == nil {
		return util.NewI18nError(fmt.Errorf("%w: event rule %q already exists", ErrDuplicatedKey, rule.Name), util.I18nErrorDuplicatedName)
	}

	rule.ID = time.Now().UnixNano()
	rule.CreatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
	rule.UpdatedAt = rule.CreatedAt

	for idx := range rule.Actions {
		if err = p.addRuleToActionMapping(rule.Name, rule.Actions[idx].Name, actionsBucket); err != nil {
			return err
		}
	}

	sort.Slice(rule.Actions, func(i, j int) bool {
		return rule.Actions[i].Order < rule.Actions[j].Order
	})

	wRule := wrapper.NewWrapper(*rule)
	data, err := wRule.MarshalJSON()
	if err != nil {
		return err
	}

	if _, err = rulesBucket.Create(rule.Name, data); err == nil {
		setLastRuleUpdate()
	}
	return err
}

func (p *NATSProvider) updateEventRule(rule *EventRule) error {
	if err := rule.validate(); err != nil {
		return err
	}

	rulesBucket, err := p.getRulesBucket()
	if err != nil {
		return err
	}

	actionsBucket, err := p.getActionsBucket()
	if err != nil {
		return err
	}

	entry, err := rulesBucket.Get(rule.Name)
	if err != nil && errors.Is(err, nats.ErrKeyNotFound) {
		return util.NewRecordNotFoundError(fmt.Sprintf("event rule %q does not exist", rule.Name))
	}

	wOldRule := wrapper.NewWrapper(EventRule{})
	if err = wOldRule.UnmarshalJSON(entry.Value()); err != nil {
		return err
	}

	oldRule := wOldRule.Get()

	for idx := range oldRule.Actions {
		if err = p.removeRuleFromActionMapping(rule.Name, oldRule.Actions[idx].Name, actionsBucket); err != nil {
			return err
		}
	}

	for idx := range rule.Actions {
		if err = p.addRuleToActionMapping(rule.Name, rule.Actions[idx].Name, actionsBucket); err != nil {
			return err
		}
	}

	rule.ID = oldRule.ID
	rule.CreatedAt = oldRule.CreatedAt
	rule.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())

	sort.Slice(rule.Actions, func(i, j int) bool {
		return rule.Actions[i].Order < rule.Actions[j].Order
	})

	wRule := wrapper.NewWrapper(*rule)
	data, err := wRule.MarshalJSON()
	if err != nil {
		return err
	}

	if _, err = rulesBucket.Update(rule.Name, data, entry.Revision()); err == nil {
		setLastRuleUpdate()
	}
	return err
}

func (p *NATSProvider) deleteEventRule(rule EventRule, _ bool) error {
	rulesBucket, err := p.getRulesBucket()
	if err != nil {
		return err
	}

	entry, err := rulesBucket.Get(rule.Name)
	if err != nil && errors.Is(err, nats.ErrKeyNotFound) {
		return util.NewRecordNotFoundError(fmt.Sprintf("event rule %q does not exist", rule.Name))
	}

	wOldRule := wrapper.NewWrapper(EventRule{})
	if err = wOldRule.UnmarshalJSON(entry.Value()); err != nil {
		return err
	}

	oldRule := wOldRule.Get()

	if len(oldRule.Actions) > 0 {
		actionsBucket, err := p.getActionsBucket()
		if err != nil {
			return err
		}

		for idx := range oldRule.Actions {
			if err = p.removeRuleFromActionMapping(rule.Name, oldRule.Actions[idx].Name, actionsBucket); err != nil {
				return err
			}
		}
	}

	_, err = rulesBucket.Update(rule.Name, nil, entry.Revision())
	return err
}

func (p *NATSProvider) roleExists(name string) (Role, error) {
	bucket, err := p.getRolesBucket()
	if err != nil {
		return Role{}, err
	}

	entry, err := bucket.Get(name)
	if err != nil && errors.Is(err, nats.ErrKeyNotFound) {
		return Role{}, util.NewRecordNotFoundError(fmt.Sprintf("role %q does not exist", name))
	}

	wRole := wrapper.NewWrapper(Role{})
	if err = wRole.UnmarshalJSON(entry.Value()); err != nil {
		return Role{}, err
	}
	return wRole.Get(), nil
}

func (p *NATSProvider) addRole(role *Role) error {
	if err := role.validate(); err != nil {
		return err
	}

	bucket, err := p.getRolesBucket()
	if err != nil {
		return err
	}

	if _, err = bucket.Get(role.Name); err == nil {
		return util.NewI18nError(fmt.Errorf("%w: role %q already exists", ErrDuplicatedKey, role.Name), util.I18nErrorDuplicatedName)
	}

	role.ID = time.Now().UnixNano()
	role.CreatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
	role.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
	role.Users = nil
	role.Admins = nil

	wRole := wrapper.NewWrapper(*role)
	data, err := wRole.MarshalJSON()
	if err != nil {
		return err
	}

	_, err = bucket.Create(role.Name, data)
	return err
}

func (p *NATSProvider) updateRole(role *Role) error {
	if err := role.validate(); err != nil {
		return err
	}

	bucket, err := p.getRolesBucket()
	if err != nil {
		return err
	}

	entry, err := bucket.Get(role.Name)
	if err != nil && errors.Is(err, nats.ErrKeyNotFound) {
		return fmt.Errorf("role %q does not exist", role.Name)
	}

	wOldRole := wrapper.NewWrapper(Role{})
	if err = wOldRole.UnmarshalJSON(entry.Value()); err != nil {
		return err
	}

	oldRole := wOldRole.Get()

	role.ID = oldRole.ID
	role.CreatedAt = oldRole.CreatedAt
	role.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
	role.Users = oldRole.Users
	role.Admins = oldRole.Admins

	wRole := wrapper.NewWrapper(*role)
	data, err := wRole.MarshalJSON()
	if err != nil {
		return err
	}

	_, err = bucket.Update(role.Name, data, entry.Revision())
	return err
}

func (p *NATSProvider) deleteRole(role Role) error {
	bucket, err := p.getRolesBucket()
	if err != nil {
		return err
	}

	entry, err := bucket.Get(role.Name)
	if err != nil && errors.Is(err, nats.ErrKeyNotFound) {
		return fmt.Errorf("role %q does not exist", role.Name)
	}

	wOldRole := wrapper.NewWrapper(Role{})
	if err = wOldRole.UnmarshalJSON(entry.Value()); err != nil {
		return err
	}

	oldRole := wOldRole.Get()

	if len(oldRole.Admins) > 0 {
		return util.NewValidationError(fmt.Sprintf("the role %q is referenced, it cannot be removed", oldRole.Name))
	}

	if len(oldRole.Users) > 0 {
		usersBucket, err := p.getUsersBucket()
		if err != nil {
			return err
		}

		for _, username := range oldRole.Users {
			if err := p.removeRoleFromUser(username, oldRole.Name, usersBucket); err != nil {
				return err
			}
		}
	}

	_, err = bucket.Update(role.Name, nil, entry.Revision())
	return err
}

func (p *NATSProvider) getRoles(limit int, offset int, order string, _ bool) ([]Role, error) {
	roles := make([]Role, 0, limit)
	if limit <= 0 {
		return roles, nil
	}

	bucket, err := p.getRolesBucket()
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
		return roles, nil
	}

	if end > len(keys) {
		end = len(keys)
	}

	for _, key := range keys[start:end] {
		entry, err := bucket.Get(key)
		if err != nil {
			continue
		}

		wRole := wrapper.NewWrapper(Role{})
		if err = wRole.UnmarshalJSON(entry.Value()); err != nil {
			return nil, err
		}
		roles = append(roles, wRole.Get())
	}
	return roles, nil
}

func (p *NATSProvider) dumpRoles() ([]Role, error) {
	roles := make([]Role, 0, 10)
	bucket, err := p.getRolesBucket()
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

		wRole := wrapper.NewWrapper(Role{})
		if err = wRole.UnmarshalJSON(entry.Value()); err != nil {
			return nil, err
		}
		roles = append(roles, wRole.Get())
	}
	return roles, nil
}

func (p *NATSProvider) ipListEntryExists(ipOrNet string, listType IPListType) (IPListEntry, error) {
	entry := IPListEntry{
		IPOrNet: ipOrNet,
		Type:    listType,
	}

	bucket, err := p.getIPListsBucket()
	if err != nil {
		return entry, err
	}

	kv, err := bucket.Get(entry.getKey())
	if err != nil && errors.Is(err, nats.ErrKeyNotFound) {
		return entry, util.NewRecordNotFoundError(fmt.Sprintf("entry %q does not exist", entry.IPOrNet))
	}

	wEntry := wrapper.NewWrapper(IPListEntry{})
	if err = wEntry.UnmarshalJSON(kv.Value()); err != nil {
		return entry, err
	}

	entry = wEntry.Get()
	entry.PrepareForRendering()
	return entry, nil
}

func (p *NATSProvider) addIPListEntry(entry *IPListEntry) error {
	if err := entry.validate(); err != nil {
		return err
	}

	bucket, err := p.getIPListsBucket()
	if err != nil {
		return err
	}

	_, err = bucket.Get(entry.getKey())
	if err == nil {
		return util.NewI18nError(fmt.Errorf("%w: entry %q already exists", ErrDuplicatedKey, entry.IPOrNet), util.I18nErrorDuplicatedIPNet)
	}

	entry.CreatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
	entry.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())

	wEntry := wrapper.NewWrapper(*entry)
	data, err := wEntry.MarshalJSON()
	if err != nil {
		return err
	}

	_, err = bucket.Create(entry.getKey(), data)
	return err
}

func (p *NATSProvider) updateIPListEntry(entry *IPListEntry) error {
	if err := entry.validate(); err != nil {
		return err
	}

	bucket, err := p.getIPListsBucket()
	if err != nil {
		return err
	}

	kv, err := bucket.Get(entry.getKey())
	if err != nil && errors.Is(err, nats.ErrKeyNotFound) {
		return fmt.Errorf("entry %q does not exist", entry.IPOrNet)
	}

	wOldEntry := wrapper.NewWrapper(IPListEntry{})
	if err = wOldEntry.UnmarshalJSON(kv.Value()); err != nil {
		return err
	}

	oldEntry := wOldEntry.Get()

	entry.CreatedAt = oldEntry.CreatedAt
	entry.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())

	wEntry := wrapper.NewWrapper(*entry)
	data, err := wEntry.MarshalJSON()
	if err != nil {
		return err
	}

	_, err = bucket.Update(entry.getKey(), data, kv.Revision())
	return err
}

func (p *NATSProvider) deleteIPListEntry(entry IPListEntry, _ bool) error {
	bucket, err := p.getIPListsBucket()
	if err != nil {
		return err
	}

	kv, err := bucket.Get(entry.getKey())
	if err != nil && errors.Is(err, nats.ErrKeyNotFound) {
		return fmt.Errorf("entry %q does not exist", entry.IPOrNet)
	}

	_, err = bucket.Update(entry.getKey(), nil, kv.Revision())
	return err
}

func (p *NATSProvider) getIPListEntries(listType IPListType, filter, from, order string, limit int) ([]IPListEntry, error) {
	entries := make([]IPListEntry, 0, 15)
	bucket, err := p.getIPListsBucket()
	if err != nil {
		return nil, err
	}

	keys, err := bucket.Keys()
	if err != nil {
		return nil, err
	}

	prefix := fmt.Sprintf("%d_", listType)
	var filteredKeys []string
	for _, key := range keys {
		if strings.HasPrefix(key, prefix) {
			filteredKeys = append(filteredKeys, key)
		}
	}

	if order == OrderDESC {
		sort.Sort(sort.Reverse(sort.StringSlice(filteredKeys)))
	} else {
		sort.Strings(filteredKeys)
	}

	for _, key := range filteredKeys {
		kv, err := bucket.Get(key)
		if err != nil {
			continue
		}

		wEntry := wrapper.NewWrapper(IPListEntry{})
		if err = wEntry.UnmarshalJSON(kv.Value()); err != nil {
			return nil, err
		}

		entry := wEntry.Get()

		if entry.satisfySearchConstraints(filter, from, order) {
			entry.PrepareForRendering()
			entries = append(entries, entry)
			if limit > 0 && len(entries) >= limit {
				break
			}
		}
	}
	return entries, nil
}

func (p *NATSProvider) getRecentlyUpdatedIPListEntries(_ int64) ([]IPListEntry, error) {
	return nil, ErrNotImplemented
}

func (p *NATSProvider) dumpIPListEntries() ([]IPListEntry, error) {
	entries := make([]IPListEntry, 0, 10)
	bucket, err := p.getIPListsBucket()
	if err != nil {
		return nil, err
	}

	keys, err := bucket.Keys()
	if err != nil {
		return nil, err
	}

	if len(keys) > ipListMemoryLimit {
		providerLog(logger.LevelInfo, "IP lists excluded from dump, too many entries: %d", len(keys))
		return entries, nil
	}

	for _, key := range keys {
		entry, err := bucket.Get(key)
		if err != nil {
			continue
		}

		wEntry := wrapper.NewWrapper(IPListEntry{})
		if err = wEntry.UnmarshalJSON(entry.Value()); err != nil {
			return nil, err
		}

		ipEntry := wEntry.Get()
		ipEntry.PrepareForRendering()
		entries = append(entries, ipEntry)
	}
	return entries, nil
}

func (p *NATSProvider) countIPListEntries(listType IPListType) (int64, error) {
	bucket, err := p.getIPListsBucket()
	if err != nil {
		return 0, err
	}

	keys, err := bucket.Keys()
	if err != nil {
		return 0, err
	}

	if listType == 0 {
		return int64(len(keys)), nil
	}

	prefix := fmt.Sprintf("%d_", listType)
	var count int64
	for _, key := range keys {
		if strings.HasPrefix(key, prefix) {
			count++
		}
	}
	return count, nil
}

func (p *NATSProvider) getListEntriesForIP(ip string, listType IPListType) ([]IPListEntry, error) {
	entries := make([]IPListEntry, 0, 3)
	ipAddr, err := netip.ParseAddr(ip)
	if err != nil {
		return entries, fmt.Errorf("invalid ip address %s", ip)
	}

	var netType int
	var ipBytes []byte
	if ipAddr.Is4() || ipAddr.Is4In6() {
		netType = ipTypeV4
		as4 := ipAddr.As4()
		ipBytes = as4[:]
	} else {
		netType = ipTypeV6
		as16 := ipAddr.As16()
		ipBytes = as16[:]
	}

	bucket, err := p.getIPListsBucket()
	if err != nil {
		return nil, err
	}

	keys, err := bucket.Keys()
	if err != nil {
		return nil, err
	}

	prefix := fmt.Sprintf("%d_", listType)
	for _, key := range keys {
		if !strings.HasPrefix(key, prefix) {
			continue
		}

		entry, err := bucket.Get(key)
		if err != nil {
			continue
		}

		wEntry := wrapper.NewWrapper(IPListEntry{})
		if err = wEntry.UnmarshalJSON(entry.Value()); err != nil {
			return nil, err
		}

		ipEntry := wEntry.Get()

		if ipEntry.IPType == netType && bytes.Compare(ipBytes, ipEntry.First) >= 0 && bytes.Compare(ipBytes, ipEntry.Last) <= 0 {
			ipEntry.PrepareForRendering()
			entries = append(entries, ipEntry)
		}
	}
	return entries, nil
}

func (p *NATSProvider) getConfigs() (Configs, error) {
	bucket, err := p.getConfigsBucket()
	if err != nil {
		return Configs{}, err
	}

	entry, err := bucket.Get(configsBucketNATS)
	if err != nil && errors.Is(err, nats.ErrKeyNotFound) {
		return Configs{}, nil
	}

	wConfigs := wrapper.NewWrapper(Configs{})
	if err = wConfigs.UnmarshalJSON(entry.Value()); err != nil {
		return Configs{}, err
	}
	return wConfigs.Get(), nil
}

func (p *NATSProvider) setConfigs(configs *Configs) error {
	if err := configs.validate(); err != nil {
		return err
	}

	bucket, err := p.getConfigsBucket()
	if err != nil {
		return err
	}

	wConfigs := wrapper.NewWrapper(*configs)
	data, err := wConfigs.MarshalJSON()
	if err != nil {
		return err
	}

	_, err = bucket.Put(string(configsKey), data)
	return err
}

func (p *NATSProvider) setFirstDownloadTimestamp(username string) error {
	bucket, err := p.getUsersBucket()
	if err != nil {
		return err
	}

	entry, err := bucket.Get(username)
	if err != nil && errors.Is(err, nats.ErrKeyNotFound) {
		return util.NewRecordNotFoundError(fmt.Sprintf("username %q does not exist, unable to set download timestamp", username))
	}

	wUser := wrapper.NewWrapper(User{})
	if err = wUser.UnmarshalJSON(entry.Value()); err != nil {
		return err
	}

	user := wUser.Get()

	if user.FirstDownload > 0 {
		return util.NewGenericError(fmt.Sprintf("first download already set to %v", util.GetTimeFromMsecSinceEpoch(user.FirstDownload)))
	}

	user.FirstDownload = util.GetTimeAsMsSinceEpoch(time.Now())
	wUser = wrapper.NewWrapper(user)
	data, err := wUser.MarshalJSON()
	if err != nil {
		return err
	}

	_, err = bucket.Update(username, data, entry.Revision())
	return err
}

func (p *NATSProvider) setFirstUploadTimestamp(username string) error {
	bucket, err := p.getUsersBucket()
	if err != nil {
		return err
	}

	entry, err := bucket.Get(username)
	if err != nil && errors.Is(err, nats.ErrKeyNotFound) {
		return util.NewRecordNotFoundError(fmt.Sprintf("username %q does not exist, unable to set upload timestamp", username))
	}

	wUser := wrapper.NewWrapper(User{})
	if err = wUser.UnmarshalJSON(entry.Value()); err != nil {
		return err
	}

	user := wUser.Get()

	if user.FirstUpload > 0 {
		return util.NewGenericError(fmt.Sprintf("first upload already set to %v", util.GetTimeFromMsecSinceEpoch(user.FirstUpload)))
	}

	user.FirstUpload = util.GetTimeAsMsSinceEpoch(time.Now())
	wUser = wrapper.NewWrapper(user)
	data, err := wUser.MarshalJSON()
	if err != nil {
		return err
	}

	_, err = bucket.Update(username, data, entry.Revision())
	return err
}

func (p *NATSProvider) close() error {
	return nil
}

func (p *NATSProvider) reloadConfig() error {
	return nil
}

func (p *NATSProvider) initializeDatabase() error {
	providerLog(logger.LevelDebug, "nats key store handle created")
	return nil
}

func (p *NATSProvider) migrateDatabase() error {
	dbVersion, err := p.getDatabaseVersion()
	if err != nil {
		return err
	}

	switch ver := dbVersion.Version; {
	case ver == currentDatabaseVersionNATS:
		providerLog(logger.LevelDebug, "database is up to date, current ver: %d", ver)
		return ErrNoInitRequired
	case ver < 29:
		err = errSchemaVersionTooOld(ver)
		providerLog(logger.LevelError, "%ver", err)
		logger.ErrorToConsole("%ver", err)
		return err
	case ver == 29, ver == 30, ver == 31:
		logger.InfoToConsole("updating database schema ver: %d -> 32", ver)
		providerLog(logger.LevelInfo, "updating database schema ver: %d -> 32", ver)
		if err := updateEventActions(); err != nil {
			return err
		}
		return p.updateDatabaseVersion(32)
	default:
		if ver > currentDatabaseVersionNATS {
			providerLog(logger.LevelError, "database schema ver %d is newer than the supported one: %d", ver, currentDatabaseVersionNATS)
			logger.WarnToConsole("database schema ver %d is newer than the supported one: %d", ver, currentDatabaseVersionNATS)
			return nil
		}
		return fmt.Errorf("database schema ver not handled: %d", ver)
	}
}

func (p *NATSProvider) revertDatabase(targetVersion int) error {
	dbVersion, err := p.getDatabaseVersion()
	if err != nil {
		return err
	}

	if dbVersion.Version == targetVersion {
		return errors.New("current version match target version, nothing to do")
	}

	switch dbVersion.Version {
	case 30, 31, 32:
		logger.InfoToConsole("downgrading database schema version: %d -> 29", dbVersion.Version)
		providerLog(logger.LevelInfo, "downgrading database schema version: %d -> 29", dbVersion.Version)
		if dbVersion.Version == 32 {
			if err := restoreEventActions(); err != nil {
				return err
			}
		}
		return p.updateDatabaseVersion(29)
	default:
		return fmt.Errorf("database schema version not handled: %v", dbVersion.Version)
	}
}

func (p *NATSProvider) joinRuleAndActions(r []byte, actionsBucket nats.KeyValue) (EventRule, error) {
	var rule EventRule
	wRule := wrapper.NewWrapper(EventRule{})
	if err := wRule.UnmarshalJSON(r); err != nil {
		return rule, err
	}

	rule = wRule.Get()

	var actions []EventAction
	for idx := range rule.Actions {
		action := &rule.Actions[idx]
		entry, err := actionsBucket.Get(action.Name)
		if err != nil {
			continue
		}

		wBaseAction := wrapper.NewWrapper(BaseEventAction{})
		if err = wBaseAction.UnmarshalJSON(entry.Value()); err != nil {
			continue
		}

		baseAction := wBaseAction.Get()
		baseAction.Options.SetEmptySecretsIfNil()
		action.BaseEventAction = baseAction
		actions = append(actions, *action)
	}
	rule.Actions = actions
	return rule, nil
}

func (p *NATSProvider) joinGroupAndFolders(g []byte, foldersBucket nats.KeyValue) (Group, error) {
	var group Group
	wGroup := wrapper.NewWrapper(Group{})
	if err := wGroup.UnmarshalJSON(g); err != nil {
		return group, err
	}

	group = wGroup.Get()

	if len(group.VirtualFolders) > 0 {
		var folders []vfs.VirtualFolder
		for idx := range group.VirtualFolders {
			folder := &group.VirtualFolders[idx]
			baseFolder, err := p.folderExistsInternal(folder.Name, foldersBucket)
			if err != nil {
				continue
			}
			folder.BaseVirtualFolder = baseFolder
			folders = append(folders, *folder)
		}
		group.VirtualFolders = folders
	}

	group.SetEmptySecretsIfNil()
	return group, nil
}

func (p *NATSProvider) joinUserAndFolders(u []byte, foldersBucket nats.KeyValue) (User, error) {
	var user User
	wUser := wrapper.NewWrapper(User{})
	if err := wUser.UnmarshalJSON(u); err != nil {
		return user, err
	}

	user = wUser.Get()

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

func (p *NATSProvider) groupExistsInternal(name string, bucket nats.KeyValue) (Group, error) {
	var group Group
	entry, err := bucket.Get(name)
	if err != nil && errors.Is(err, nats.ErrKeyNotFound) {
		return group, util.NewRecordNotFoundError(fmt.Sprintf("group %q does not exist", name))
	}

	wGroup := wrapper.NewWrapper(Group{})
	if err = wGroup.UnmarshalJSON(entry.Value()); err != nil {
		return group, err
	}
	return wGroup.Get(), nil
}

func (p *NATSProvider) addFolderInternal(folder vfs.BaseVirtualFolder, bucket nats.KeyValue) error {
	folder.ID = time.Now().UnixNano()
	wFolder := wrapper.NewWrapper(folder)
	data, err := wFolder.MarshalJSON()
	if err != nil {
		return err
	}
	_, err = bucket.Create(folder.Name, data)
	return err
}

func (p *NATSProvider) removeRoleFromUser(username, role string, bucket nats.KeyValue) error {
	entry, err := bucket.Get(username)
	if err != nil && errors.Is(err, nats.ErrKeyNotFound) {
		providerLog(logger.LevelWarn, "user %q does not exist, cannot remove role %q", username, role)
		return nil
	}

	wUser := wrapper.NewWrapper(User{})
	if err = wUser.UnmarshalJSON(entry.Value()); err != nil {
		return err
	}
	user := wUser.Get()

	if user.Role == role {
		user.Role = ""
		wUser = wrapper.NewWrapper(user)
		data, err := wUser.MarshalJSON()
		if err != nil {
			return err
		}
		_, err = bucket.Update(user.Username, data, entry.Revision())
		return err
	}

	providerLog(logger.LevelError, "user %q does not have the expected role %q, actual %q", username, role, user.Role)
	return nil
}

func (p *NATSProvider) addAdminToRole(username, roleName string, bucket nats.KeyValue) error {
	if roleName == "" {
		return nil
	}

	entry, err := bucket.Get(roleName)
	if err != nil && errors.Is(err, nats.ErrKeyNotFound) {
		return fmt.Errorf("%w: role %q does not exist", ErrForeignKeyViolated, roleName)
	}

	wRole := wrapper.NewWrapper(Role{})
	if err = wRole.UnmarshalJSON(entry.Value()); err != nil {
		return err
	}
	role := wRole.Get()

	if !slices.Contains(role.Admins, username) {
		role.Admins = append(role.Admins, username)
		wRole = wrapper.NewWrapper(role)
		data, err := wRole.MarshalJSON()
		if err != nil {
			return err
		}
		_, err = bucket.Update(role.Name, data, entry.Revision())
		return err
	}
	return nil
}

func (p *NATSProvider) removeAdminFromRole(username, roleName string, bucket nats.KeyValue) error {
	if roleName == "" {
		return nil
	}

	entry, err := bucket.Get(roleName)
	if err != nil && errors.Is(err, nats.ErrKeyNotFound) {
		providerLog(logger.LevelWarn, "role %q does not exist, cannot remove admin %q", roleName, username)
		return nil
	}

	wRole := wrapper.NewWrapper(Role{})
	if err = wRole.UnmarshalJSON(entry.Value()); err != nil {
		return err
	}
	role := wRole.Get()

	if slices.Contains(role.Admins, username) {
		var admins []string
		for _, admin := range role.Admins {
			if admin != username {
				admins = append(admins, admin)
			}
		}
		role.Admins = util.RemoveDuplicates(admins, false)
		wRole = wrapper.NewWrapper(role)
		data, err := wRole.MarshalJSON()
		if err != nil {
			return err
		}
		_, err = bucket.Update(role.Name, data, entry.Revision())
		return err
	}
	return nil
}

func (p *NATSProvider) addUserToRole(username, roleName string, bucket nats.KeyValue) error {
	if roleName == "" {
		return nil
	}

	entry, err := bucket.Get(roleName)
	if err != nil && errors.Is(err, nats.ErrKeyNotFound) {
		return fmt.Errorf("%w: role %q does not exist", ErrForeignKeyViolated, roleName)
	}

	wRole := wrapper.NewWrapper(Role{})
	if err = wRole.UnmarshalJSON(entry.Value()); err != nil {
		return err
	}
	role := wRole.Get()

	if !slices.Contains(role.Users, username) {
		role.Users = append(role.Users, username)
		wRole = wrapper.NewWrapper(role)
		data, err := wRole.MarshalJSON()
		if err != nil {
			return err
		}
		_, err = bucket.Update(role.Name, data, entry.Revision())
		return err
	}
	return nil
}

func (p *NATSProvider) removeUserFromRole(username, roleName string, bucket nats.KeyValue) error {
	if roleName == "" {
		return nil
	}

	entry, err := bucket.Get(roleName)
	if err != nil && errors.Is(err, nats.ErrKeyNotFound) {
		providerLog(logger.LevelWarn, "role %q does not exist, cannot remove user %q", roleName, username)
		return nil
	}

	wRole := wrapper.NewWrapper(Role{})
	if err = wRole.UnmarshalJSON(entry.Value()); err != nil {
		return err
	}
	role := wRole.Get()

	if slices.Contains(role.Users, username) {
		var users []string
		for _, user := range role.Users {
			if user != username {
				users = append(users, user)
			}
		}
		users = util.RemoveDuplicates(users, false)
		role.Users = users
		wRole = wrapper.NewWrapper(role)
		data, err := wRole.MarshalJSON()
		if err != nil {
			return err
		}
		_, err = bucket.Update(role.Name, data, entry.Revision())
		return err
	}
	return nil
}

func (p *NATSProvider) addRuleToActionMapping(ruleName, actionName string, bucket nats.KeyValue) error {
	entry, err := bucket.Get(actionName)
	if err != nil && errors.Is(err, nats.ErrKeyNotFound) {
		return util.NewGenericError(fmt.Sprintf("action %q does not exist", actionName))
	}

	wAction := wrapper.NewWrapper(BaseEventAction{})
	if err = wAction.UnmarshalJSON(entry.Value()); err != nil {
		return err
	}
	action := wAction.Get()

	if !slices.Contains(action.Rules, ruleName) {
		action.Rules = append(action.Rules, ruleName)
		wAction = wrapper.NewWrapper(action)
		data, err := wAction.MarshalJSON()
		if err != nil {
			return err
		}
		_, err = bucket.Update(action.Name, data, entry.Revision())
		return err
	}
	return nil
}

func (p *NATSProvider) removeRuleFromActionMapping(ruleName, actionName string, bucket nats.KeyValue) error {
	entry, err := bucket.Get(actionName)
	if err != nil && errors.Is(err, nats.ErrKeyNotFound) {
		providerLog(logger.LevelWarn, "action %q does not exist, cannot remove from mapping", actionName)
		return nil
	}

	wAction := wrapper.NewWrapper(BaseEventAction{})
	if err = wAction.UnmarshalJSON(entry.Value()); err != nil {
		return err
	}
	action := wAction.Get()

	if slices.Contains(action.Rules, ruleName) {
		var rules []string
		for _, r := range action.Rules {
			if r != ruleName {
				rules = append(rules, r)
			}
		}
		action.Rules = util.RemoveDuplicates(rules, false)
		wAction = wrapper.NewWrapper(action)
		data, err := wAction.MarshalJSON()
		if err != nil {
			return err
		}
		_, err = bucket.Update(action.Name, data, entry.Revision())
		return err
	}
	return nil
}

func (p *NATSProvider) addUserToGroupMapping(username, groupname string, bucket nats.KeyValue) error {
	entry, err := bucket.Get(groupname)
	if err != nil && errors.Is(err, nats.ErrKeyNotFound) {
		return util.NewGenericError(fmt.Sprintf("group %q does not exist", groupname))
	}

	wGroup := wrapper.NewWrapper(Group{})
	if err = wGroup.UnmarshalJSON(entry.Value()); err != nil {
		return err
	}
	group := wGroup.Get()

	if !slices.Contains(group.Users, username) {
		group.Users = append(group.Users, username)
		wGroup = wrapper.NewWrapper(group)
		data, err := wGroup.MarshalJSON()
		if err != nil {
			return err
		}
		_, err = bucket.Update(group.Name, data, entry.Revision())
		return err
	}
	return nil
}

func (p *NATSProvider) removeUserFromGroupMapping(username, groupname string, bucket nats.KeyValue) error {
	entry, err := bucket.Get(groupname)
	if err != nil && errors.Is(err, nats.ErrKeyNotFound) {
		return util.NewRecordNotFoundError(fmt.Sprintf("group %q does not exist", groupname))
	}

	wGroup := wrapper.NewWrapper(Group{})
	if err = wGroup.UnmarshalJSON(entry.Value()); err != nil {
		return err
	}
	group := wGroup.Get()

	users := make([]string, 0)
	for _, u := range group.Users {
		if u != username {
			users = append(users, u)
		}
	}
	group.Users = util.RemoveDuplicates(users, false)
	wGroup = wrapper.NewWrapper(group)
	data, err := wGroup.MarshalJSON()
	if err != nil {
		return err
	}
	_, err = bucket.Update(group.Name, data, entry.Revision())
	return err
}

func (p *NATSProvider) addAdminToGroupMapping(username, groupname string, bucket nats.KeyValue) error {
	entry, err := bucket.Get(groupname)
	if err != nil && errors.Is(err, nats.ErrKeyNotFound) {
		return util.NewRecordNotFoundError(fmt.Sprintf("group %q does not exist", groupname))
	}

	wGroup := wrapper.NewWrapper(Group{})
	if err = wGroup.UnmarshalJSON(entry.Value()); err != nil {
		return err
	}
	group := wGroup.Get()

	if !slices.Contains(group.Admins, username) {
		group.Admins = append(group.Admins, username)
		wGroup = wrapper.NewWrapper(group)
		data, err := wGroup.MarshalJSON()
		if err != nil {
			return err
		}
		_, err = bucket.Update(group.Name, data, entry.Revision())
		return err
	}
	return nil
}

func (p *NATSProvider) removeAdminFromGroupMapping(username, groupname string, bucket nats.KeyValue) error {
	entry, err := bucket.Get(groupname)
	if err != nil && errors.Is(err, nats.ErrKeyNotFound) {
		return util.NewRecordNotFoundError(fmt.Sprintf("group %q does not exist", groupname))
	}

	wGroup := wrapper.NewWrapper(Group{})
	if err = wGroup.UnmarshalJSON(entry.Value()); err != nil {
		return err
	}
	group := wGroup.Get()

	admins := make([]string, 0)
	for _, a := range group.Admins {
		if a != username {
			admins = append(admins, a)
		}
	}
	group.Admins = util.RemoveDuplicates(admins, false)
	wGroup = wrapper.NewWrapper(group)
	data, err := wGroup.MarshalJSON()
	if err != nil {
		return err
	}
	_, err = bucket.Update(group.Name, data, entry.Revision())
	return err
}

func (p *NATSProvider) removeGroupFromAdminMapping(groupName, adminName string, bucket nats.KeyValue) error {
	entry, err := bucket.Get(adminName)
	if err != nil && errors.Is(err, nats.ErrKeyNotFound) {
		// the admin does not exist so there is no associated group
		return nil
	}

	wAdmin := wrapper.NewWrapper(Admin{})
	if err = wAdmin.UnmarshalJSON(entry.Value()); err != nil {
		return err
	}
	admin := wAdmin.Get()

	var newGroups []AdminGroupMapping
	for _, g := range admin.Groups {
		if g.Name != groupName {
			newGroups = append(newGroups, g)
		}
	}
	admin.Groups = newGroups
	wAdmin = wrapper.NewWrapper(admin)
	data, err := wAdmin.MarshalJSON()
	if err != nil {
		return err
	}
	_, err = bucket.Update(adminName, data, entry.Revision())
	return err
}

func (p *NATSProvider) addRelationToFolderMapping(folderName string, user *User, group *Group, bucket nats.KeyValue) error {
	entry, err := bucket.Get(folderName)
	if err != nil && errors.Is(err, nats.ErrKeyNotFound) {
		return util.NewGenericError(fmt.Sprintf("folder %q does not exist", folderName))
	}

	wFolder := wrapper.NewWrapper(vfs.BaseVirtualFolder{})
	if err = wFolder.UnmarshalJSON(entry.Value()); err != nil {
		return err
	}
	folder := wFolder.Get()

	updated := false
	if user != nil && !slices.Contains(folder.Users, user.Username) {
		folder.Users = append(folder.Users, user.Username)
		updated = true
	}
	if group != nil && !slices.Contains(folder.Groups, group.Name) {
		folder.Groups = append(folder.Groups, group.Name)
		updated = true
	}
	if !updated {
		return nil
	}

	wFolder = wrapper.NewWrapper(folder)
	data, err := wFolder.MarshalJSON()
	if err != nil {
		return err
	}
	_, err = bucket.Update(folder.Name, data, entry.Revision())
	return err
}

func (p *NATSProvider) removeRelationFromFolderMapping(folder vfs.VirtualFolder, username, groupname string, bucket nats.KeyValue) error {
	entry, err := bucket.Get(folder.Name)
	if err != nil && errors.Is(err, nats.ErrKeyNotFound) {
		// the folder does not exist so there is no associated user/group
		return nil
	}

	wFolder := wrapper.NewWrapper(vfs.BaseVirtualFolder{})
	if err = wFolder.UnmarshalJSON(entry.Value()); err != nil {
		return err
	}
	baseFolder := wFolder.Get()

	found := false
	if username != "" {
		found = true
		var newUserMapping []string
		for _, u := range baseFolder.Users {
			if u != username {
				newUserMapping = append(newUserMapping, u)
			}
		}
		baseFolder.Users = newUserMapping
	}
	if groupname != "" {
		found = true
		var newGroupMapping []string
		for _, g := range baseFolder.Groups {
			if g != groupname {
				newGroupMapping = append(newGroupMapping, g)
			}
		}
		baseFolder.Groups = newGroupMapping
	}
	if !found {
		return nil
	}

	wFolder = wrapper.NewWrapper(baseFolder)
	data, err := wFolder.MarshalJSON()
	if err != nil {
		return err
	}

	if entry == nil && entry.Revision() == 0 {
		_, err := bucket.Put(folder.Name, data)
		return err
	}

	_, err = bucket.Update(folder.Name, data, entry.Revision())
	return err
}

func (p *NATSProvider) updateUserRelations(user *User, oldUser User) error {
	foldersBucket, err := p.getFoldersBucket()
	if err != nil {
		return err
	}
	groupsBucket, err := p.getGroupsBucket()
	if err != nil {
		return err
	}
	rolesBucket, err := p.getRolesBucket()
	if err != nil {
		return err
	}

	for idx := range oldUser.VirtualFolders {
		err = p.removeRelationFromFolderMapping(oldUser.VirtualFolders[idx], oldUser.Username, "", foldersBucket)
		if err != nil {
			return err
		}
	}
	for idx := range oldUser.Groups {
		err = p.removeUserFromGroupMapping(user.Username, oldUser.Groups[idx].Name, groupsBucket)
		if err != nil {
			return err
		}
	}
	if err = p.removeUserFromRole(oldUser.Username, oldUser.Role, rolesBucket); err != nil {
		return err
	}

	sort.Slice(user.VirtualFolders, func(i, j int) bool {
		return user.VirtualFolders[i].Name < user.VirtualFolders[j].Name
	})
	for idx := range user.VirtualFolders {
		err = p.addRelationToFolderMapping(user.VirtualFolders[idx].Name, user, nil, foldersBucket)
		if err != nil {
			return err
		}
	}

	sort.Slice(user.Groups, func(i, j int) bool {
		return user.Groups[i].Name < user.Groups[j].Name
	})
	for idx := range user.Groups {
		err = p.addUserToGroupMapping(user.Username, user.Groups[idx].Name, groupsBucket)
		if err != nil {
			return err
		}
	}
	return p.addUserToRole(user.Username, user.Role, rolesBucket)
}

func (p *NATSProvider) adminExistsInternal(username string) error {
	bucket, err := p.getAdminsBucket()
	if err != nil {
		return err
	}
	_, err = bucket.Get(username)
	if err != nil && errors.Is(err, nats.ErrKeyNotFound) {
		return util.NewRecordNotFoundError(fmt.Sprintf("admin %v does not exist", username))
	}
	return nil
}

func (p *NATSProvider) userExistsInternal(username string) error {
	bucket, err := p.getUsersBucket()
	if err != nil {
		return err
	}
	_, err = bucket.Get(username)
	if err != nil && errors.Is(err, nats.ErrKeyNotFound) {
		return util.NewRecordNotFoundError(fmt.Sprintf("username %q does not exist", username))
	}
	return nil
}

func (p *NATSProvider) deleteRelatedShares(username string) error {
	bucket, err := p.getSharesBucket()
	if err != nil {
		return err
	}

	keys, err := bucket.Keys()
	if err != nil {
		return err
	}

	for _, k := range keys {
		entry, err := bucket.Get(k)
		if err != nil && errors.Is(err, nats.ErrKeyNotFound) {
			continue
		}

		wShare := wrapper.NewWrapper(Share{})
		if err = wShare.UnmarshalJSON(entry.Value()); err != nil {
			continue
		}
		share := wShare.Get()

		if share.Username == username {
			if err := bucket.Delete(share.ShareID); err != nil {
				return err
			}
		}
	}
	return nil
}

func (p *NATSProvider) deleteRelatedAPIKey(username string, scope APIKeyScope) error {
	bucket, err := p.getAPIKeysBucket()
	if err != nil {
		return err
	}

	keys, err := bucket.Keys()
	if err != nil {
		return err
	}

	for _, k := range keys {
		entry, err := bucket.Get(k)
		if err != nil && errors.Is(err, nats.ErrKeyNotFound) {
			continue
		}

		wAPIKey := wrapper.NewWrapper(APIKey{})
		if err = wAPIKey.UnmarshalJSON(entry.Value()); err != nil {
			continue
		}
		apiKey := wAPIKey.Get()

		if (scope == APIKeyScopeUser && apiKey.User == username) ||
			(scope == APIKeyScopeAdmin && apiKey.Admin == username) {
			if err := bucket.Delete(apiKey.KeyID); err != nil {
				return err
			}
		}
	}
	return nil
}

func (p *NATSProvider) getDatabaseVersion() (schemaVersion, error) {
	kv, ok := p.kvStore[dbMetadataNATS]
	if !ok {
		return schemaVersion{}, fmt.Errorf("bucket %q not found", dbMetadataNATS)
	}

	wVersion := wrapper.NewWrapper(schemaVersion{})

	entry, err := kv.Get(dbVersionKeyNATS)
	if err != nil {
		if errors.Is(err, nats.ErrKeyNotFound) {
			wVersion.Set(schemaVersion{Version: 29})

			data, err := wVersion.MarshalJSON()
			if err != nil {
				return schemaVersion{}, err
			}

			if _, err := kv.Put(dbVersionKeyNATS, data); err != nil {
				return wVersion.Get(), err
			}
			return wVersion.Get(), nil
		}
		return schemaVersion{}, err
	}

	if err = wVersion.UnmarshalJSON(entry.Value()); err != nil {
		return schemaVersion{}, err
	}
	return wVersion.Get(), nil
}

func (p *NATSProvider) updateDatabaseVersion(version int) error {
	kv, ok := p.kvStore[dbMetadataNATS]
	if !ok {
		return fmt.Errorf("bucket %q not found", dbMetadataNATS)
	}

	wVersion := wrapper.NewWrapper(schemaVersion{})

	entry, err := kv.Get(dbVersionBucketNATS)
	if err != nil {
		if errors.Is(err, nats.ErrKeyNotFound) {
			wVersion.Set(schemaVersion{Version: version})

			data, err := wVersion.MarshalJSON()
			if err != nil {
				return err
			}

			if _, err := kv.Put(dbVersionKeyNATS, data); err != nil {
				return err
			}
			return nil
		}
	}

	if err = wVersion.UnmarshalJSON(entry.Value()); err != nil {
		return err
	}

	data, err := wVersion.MarshalJSON()
	if err != nil {
		return err
	}

	_, err = kv.Put(dbVersionKeyNATS, data)
	return err
}
