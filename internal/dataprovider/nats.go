package dataprovider

////go:build nats

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/drakkan/sftpgo/v2/internal/dataprovider/bucket"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/util"
	"github.com/drakkan/sftpgo/v2/internal/version"
	"github.com/drakkan/sftpgo/v2/internal/vfs"
	"github.com/inovacc/utils/v2/reflection"
	"github.com/nats-io/nats.go"
	bolt "go.etcd.io/bbolt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"time"
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

var natsBuckets = make(map[string]*bucket.KeyValueBucket)

var storageNames = []string{
	usersBucketNATS, groupsBucketNATS, foldersBucketNATS, adminsBucketNATS, apiKeysBucketNATS, sharesBucketNATS,
	actionsBucketNATS, rulesBucketNATS, rolesBucketNATS, ipListsBucketNATS, configsBucketNATS, dbVersionBucketNATS,
	dbVersionKeyNATS,
}

func init() {
	version.AddFeature("+nats")
}

type NATSProvider struct {
	conn     *nats.Conn
	jsHandle nats.JetStreamContext
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

	for _, name := range storageNames {
		userStore, err := bucket.CreateKeyValueBucket(js, name)
		if err != nil {
			continue
		}
		natsBuckets[name] = userStore
	}

	if len(natsBuckets) != len(storageNames) {
		providerLog(logger.LevelError, "error creating nats database handler, connection string: %q, error: %v", url, err)
		return err
	}

	providerLog(logger.LevelDebug, "nats key store handle created")

	provider = &NATSProvider{
		jsHandle: js,
		conn:     nc,
	}
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

func (n *NATSProvider) getBucket(name string) (*bucket.KeyValueBucket, error) {
	kv, ok := natsBuckets[name]
	if !ok {
		return nil, fmt.Errorf("kv bucket %q not initialized", name)
	}
	return kv, nil
}

func (n *NATSProvider) getBoltDatabaseVersion() (schemaVersion, error) {
	kv, err := n.getDBVersionBucket()
	if err != nil {
		return schemaVersion{}, fmt.Errorf("unable to find database schema version bucket")
	}

	var dbVersion schemaVersion
	entry, err := kv.Get(dbVersionKeyNATS)
	if err != nil {
		dbVersion = schemaVersion{
			Version: 29,
		}
		return schemaVersion{}, nil
	}

	if err := dbVersion.Unmarshal(entry.Value()); err != nil {
		return schemaVersion{}, err
	}
	return dbVersion, err
}

func (n *NATSProvider) getUsersBucket() (*bucket.KeyValueBucket, error) {
	return n.getBucket(usersBucketNATS)
}

func (n *NATSProvider) getAdminsBucket() (*bucket.KeyValueBucket, error) {
	return n.getBucket(adminsBucketNATS)
}

func (n *NATSProvider) getGroupsBucket() (*bucket.KeyValueBucket, error) {
	return n.getBucket(groupsBucketNATS)
}

func (n *NATSProvider) getFoldersBucket() (*bucket.KeyValueBucket, error) {
	return n.getBucket(foldersBucketNATS)
}

func (n *NATSProvider) getAPIKeysBucket() (*bucket.KeyValueBucket, error) {
	return n.getBucket(apiKeysBucketNATS)
}

func (n *NATSProvider) getSharesBucket() (*bucket.KeyValueBucket, error) {
	return n.getBucket(sharesBucketNATS)
}

func (n *NATSProvider) getActionsBucket() (*bucket.KeyValueBucket, error) {
	return n.getBucket(actionsBucketNATS)
}

func (n *NATSProvider) getRulesBucket() (*bucket.KeyValueBucket, error) {
	return n.getBucket(rulesBucketNATS)
}

func (n *NATSProvider) getRolesBucket() (*bucket.KeyValueBucket, error) {
	return n.getBucket(rolesBucketNATS)
}

func (n *NATSProvider) getIPListsBucket() (*bucket.KeyValueBucket, error) {
	return n.getBucket(ipListsBucketNATS)
}

func (n *NATSProvider) getConfigsBucket() (*bucket.KeyValueBucket, error) {
	return n.getBucket(configsBucketNATS)
}

func (n *NATSProvider) getDBVersionBucket() (*bucket.KeyValueBucket, error) {
	return n.getBucket(dbVersionBucketNATS)
}

func (n *NATSProvider) userExists(username, role string) (User, error) {
	kv, err := n.getUsersBucket()
	if err != nil {
		return User{}, err
	}

	entry, err := kv.Get(username)
	if err != nil {
		if errors.Is(err, nats.ErrKeyNotFound) {
			return User{}, util.NewRecordNotFoundError(fmt.Sprintf("username %q does not exist", username))
		}
		return User{}, fmt.Errorf("kv get failed for username %q: %w", username, err)
	}

	var user User
	if err := user.Unmarshal(entry.Value()); err != nil {
		return User{}, fmt.Errorf("failed to decode user data: %w", err)
	}

	foldersKv, err := n.getFoldersBucket()
	if err != nil {
		return User{}, err
	}

	folderEntry, err := foldersKv.Get(username)
	if err != nil && !errors.Is(err, nats.ErrKeyNotFound) {
		return User{}, fmt.Errorf("failed to get folders from kv: %w", err)
	}

	user2, err := n.joinUserAndFolders(folderEntry.Value(), foldersKv)
	if err != nil {
		return User{}, fmt.Errorf("failed to join user and folders: %w", err)
	}

	reflection.MergeZeroFields(user2, user)

	if !user.hasRole(role) {
		return User{}, util.NewRecordNotFoundError(fmt.Sprintf("username %q does not exist", username))
	}
	return user, nil
}

func (n *NATSProvider) checkAvailability() error {
	kv, err := n.getConfigsBucket()
	if err != nil {
		return err
	}

	entry, err := kv.Get(dbVersionBucketNATS)
	if err != nil {
		return err
	}

	if entry.Value() != nil {
		return errors.New("version database is empty")
	}
	return nil
}

func (n *NATSProvider) validateUserAndTLSCert(username, protocol string, tlsCert *x509.Certificate) (User, error) {
	var user User
	if tlsCert == nil {
		return user, errors.New("TLS certificate cannot be null or empty")
	}

	user, err := n.userExists(username, "")
	if err != nil {
		providerLog(logger.LevelWarn, "error authenticating user %q: %v", username, err)
		return user, err
	}
	return checkUserAndTLSCertificate(&user, protocol, tlsCert)
}

func (n *NATSProvider) updateLastLogin(username string) error {
	kv, err := n.getUsersBucket()
	if err != nil {
		return err
	}

	entry, err := kv.Get(username)
	if err != nil {
		return util.NewRecordNotFoundError(fmt.Sprintf("username %q does not exist, unable to update last login", username))
	}

	var user User
	if err := user.Unmarshal(entry.Value()); err != nil {
		return err
	}

	user.LastLogin = util.GetTimeAsMsSinceEpoch(time.Now())

	buf, err := user.Marshal()
	if err != nil {
		return err
	}

	if _, err = kv.Put(username, buf); err != nil {
		providerLog(logger.LevelWarn, "error updating last login for user %q: %v", username, err)
		return err
	}
	providerLog(logger.LevelDebug, "last login updated for user %q", username)
	return nil
}

func (n *NATSProvider) validateUserAndPass(username, password, ip, protocol string) (User, error) {
	user, err := n.userExists(username, "")
	if err != nil {
		providerLog(logger.LevelWarn, "error authenticating user %q: %v", username, err)
		return user, err
	}
	return checkUserAndPass(&user, password, ip, protocol)
}

func (n *NATSProvider) validateAdminAndPass(username, password, ip string) (Admin, error) {
	admin, err := n.adminExists(username)
	if err != nil {
		providerLog(logger.LevelWarn, "error authenticating admin %q: %v", username, err)
		return admin, err
	}
	err = admin.checkUserAndPass(password, ip)
	return admin, err
}

func (n *NATSProvider) getAdminSignature(username string) (string, error) {
	kv, err := n.getAdminsBucket()
	if err != nil {
		return "", err
	}

	entry, err := kv.Get(username)
	if err != nil {
		return "", err
	}

	var admin Admin
	if err := admin.Unmarshal(entry.Value()); err != nil {
		return "", err
	}
	return strconv.FormatInt(admin.UpdatedAt, 10), nil
}

func (n *NATSProvider) getUserSignature(username string) (string, error) {
	kv, err := n.getUsersBucket()
	if err != nil {
		return "", err
	}

	var user User
	entry, err := kv.Get(username)
	if err != nil {
		return "", err
	}

	if err := user.Unmarshal(entry.Value()); err != nil {
		return "", err
	}
	return strconv.FormatInt(user.UpdatedAt, 10), nil
}

func (n *NATSProvider) validateUserAndPubKey(username string, pubKey []byte, isSSHCert bool) (User, string, error) {
	var user User
	if len(pubKey) == 0 {
		return user, "", errors.New("credentials cannot be null or empty")
	}

	user, err := n.userExists(username, "")
	if err != nil {
		providerLog(logger.LevelWarn, "error authenticating user %q: %v", username, err)
		return user, "", err
	}
	return checkUserAndPubKey(&user, pubKey, isSSHCert)
}

func (n *NATSProvider) getUsedQuota(username string) (int, int64, int64, int64, error) {
	user, err := n.userExists(username, "")
	if err != nil {
		providerLog(logger.LevelError, "unable to get quota for user %v error: %v", username, err)
		return 0, 0, 0, 0, err
	}
	return user.UsedQuotaFiles, user.UsedQuotaSize, user.UsedUploadDataTransfer, user.UsedDownloadDataTransfer, err
}

func (n *NATSProvider) addAdminToGroupMapping(username, groupName string, kv *bucket.KeyValueBucket) error {
	entry, err := kv.Get(groupName)
	if err != nil {
		return util.NewRecordNotFoundError(fmt.Sprintf("group %q does not exist", groupName))
	}

	var group Group
	if err := group.Unmarshal(entry.Value()); err != nil {
		return err
	}

	if !slices.Contains(group.Admins, username) {
		group.Admins = append(group.Admins, username)
		buf, err := group.Marshal()
		if err != nil {
			return err
		}

		if _, err := kv.Put(group.Name, buf); err != nil {
			return err
		}
	}
	return nil
}

func (n *NATSProvider) addAdminToRole(username, roleName string, kv *bucket.KeyValueBucket) error {
	if roleName == "" {
		return nil
	}

	entry, err := kv.Get(roleName)
	if err != nil {
		return fmt.Errorf("%w: role %q does not exist", ErrForeignKeyViolated, roleName)
	}

	var role Role
	if err := role.Unmarshal(entry.Value()); err != nil {
		return err
	}

	if !slices.Contains(role.Admins, username) {
		role.Admins = append(role.Admins, username)
		buf, err := role.Marshal()
		if err != nil {
			return err
		}

		if _, err := kv.Put(role.Name, buf); err != nil {
			return err
		}
	}
	return nil
}

func (n *NATSProvider) adminExists(username string) (Admin, error) {
	kv, err := n.getAdminsBucket()
	if err != nil {
		return Admin{}, err
	}

	entry, err := kv.Get(username)
	if err != nil {
		if errors.Is(err, nats.ErrKeyNotFound) {
			return Admin{}, util.NewRecordNotFoundError(fmt.Sprintf("admin %v does not exist", username))
		}
		return Admin{}, fmt.Errorf("failed to retrieve admin %q from KV store: %w", username, err)
	}

	var admin Admin
	if err := admin.Unmarshal(entry.Value()); err != nil {
		return Admin{}, fmt.Errorf("failed to unmarshal admin data: %w", err)
	}
	return admin, nil
}

func (n *NATSProvider) addAdmin(admin *Admin) error {
	if err := admin.validate(); err != nil {
		return err
	}

	kv, err := n.getAdminsBucket()
	if err != nil {
		return err
	}

	groupBucket, err := n.getGroupsBucket()
	if err != nil {
		return err
	}

	rolesBucket, err := n.getRolesBucket()
	if err != nil {
		return err
	}

	if _, err = kv.Get(admin.Username); err != nil {
		return util.NewI18nError(
			fmt.Errorf("%w: admin %q already exists", ErrDuplicatedKey, admin.Username),
			util.I18nErrorDuplicatedUsername,
		)
	}

	admin.ID = time.Now().UnixNano()
	admin.LastLogin = 0
	admin.CreatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
	admin.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())

	sort.Slice(admin.Groups, func(i, j int) bool {
		return admin.Groups[i].Name < admin.Groups[j].Name
	})

	for idx := range admin.Groups {
		err = n.addAdminToGroupMapping(admin.Username, admin.Groups[idx].Name, groupBucket)
		if err != nil {
			return err
		}
	}

	if err = n.addAdminToRole(admin.Username, admin.Role, rolesBucket); err != nil {
		return err
	}

	data, err := admin.Marshal()
	if err != nil {
		return err
	}

	if _, err = kv.Put(admin.Username, data); err != nil {
		return fmt.Errorf("failed to store admin in KV: %w", err)
	}
	return nil
}

func (n *NATSProvider) getUsedFolderQuota(name string) (int, int64, error) {
	folder, err := n.getFolderByName(name)
	if err != nil {
		providerLog(logger.LevelError, "unable to get quota for folder %q error: %v", name, err)
		return 0, 0, err
	}
	return folder.UsedQuotaFiles, folder.UsedQuotaSize, err
}

func (n *NATSProvider) updateAPIKeyLastUse(keyID string) error {
	kv, err := n.getAPIKeysBucket()
	if err != nil {
		return err
	}

	entry, err := kv.Get(keyID)
	if err != nil {
		return util.NewRecordNotFoundError(fmt.Sprintf("key %q does not exist, unable to update last use", keyID))
	}

	var apiKey APIKey
	if err = apiKey.Unmarshal(entry.Value()); err != nil {
		return err
	}

	apiKey.LastUseAt = util.GetTimeAsMsSinceEpoch(time.Now())

	buf, err := apiKey.Marshal()
	if err != nil {
		return err
	}

	if _, err = kv.Put(keyID, buf); err != nil {
		providerLog(logger.LevelWarn, "error updating last use for key %q: %v", keyID, err)
		return err
	}
	providerLog(logger.LevelDebug, "last use updated for key %q", keyID)
	return nil
}

func (n *NATSProvider) setUpdatedAt(username string) error {
	kv, err := n.getUsersBucket()
	if err != nil {
		return err
	}

	entry, err := kv.Get(username)
	if err != nil {
		return util.NewRecordNotFoundError(fmt.Sprintf("username %q does not exist, unable to update updated at", username))
	}

	var user User
	if err = user.Unmarshal(entry.Value()); err != nil {
		return err
	}

	user.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())

	buf, err := user.Marshal()
	if err != nil {
		return err
	}

	if _, err = kv.Put(username, buf); err != nil {
		providerLog(logger.LevelWarn, "error setting updated_at for user %q: %v", username, err)
		return err
	}

	providerLog(logger.LevelDebug, "updated at set for user %q", username)
	setLastUserUpdate()
	return nil
}

func (n *NATSProvider) folderExistsInternal(name string, kv *bucket.KeyValueBucket) (vfs.BaseVirtualFolder, error) {
	var folder vfs.BaseVirtualFolder

	entry, err := kv.Get(name)
	if err != nil {
		return folder, util.NewRecordNotFoundError(fmt.Sprintf("folder %q does not exist", name))
	}

	if err := folder.Unmarshal(entry.Value()); err != nil {
		return folder, fmt.Errorf("failed to decode folder data: %w", err)
	}
	return folder, nil
}

func (n *NATSProvider) updateAdminLastLogin(username string) error {
	kv, err := n.getAdminsBucket()
	if err != nil {
		return err
	}

	entry, err := kv.Get(username)
	if err != nil {
		return util.NewRecordNotFoundError(fmt.Sprintf("admin %q does not exist, unable to update last login", username))
	}

	var admin Admin
	if err = admin.Unmarshal(entry.Value()); err != nil {
		return err
	}

	admin.LastLogin = util.GetTimeAsMsSinceEpoch(time.Now())
	buf, err := admin.Marshal()
	if err != nil {
		return err
	}

	if _, err = kv.Put(username, buf); err == nil {
		providerLog(logger.LevelDebug, "last login updated for admin %q", username)
		return err
	}
	providerLog(logger.LevelWarn, "error updating last login for admin %q: %v", username, err)
	return err
}

func (n *NATSProvider) updateTransferQuota(username string, uploadSize, downloadSize int64, reset bool) error {
	kv, err := n.getUsersBucket()
	if err != nil {
		return err
	}

	entry, err := kv.Get(username)
	if err != nil {
		return util.NewRecordNotFoundError(fmt.Sprintf("username %q does not exist, unable to update transfer quota", username))
	}

	var user User
	if err = user.Unmarshal(entry.Value()); err != nil {
		return err
	}

	if !reset {
		user.UsedUploadDataTransfer += uploadSize
		user.UsedDownloadDataTransfer += downloadSize
	} else {
		user.UsedUploadDataTransfer = uploadSize
		user.UsedDownloadDataTransfer = downloadSize
	}

	user.LastQuotaUpdate = util.GetTimeAsMsSinceEpoch(time.Now())
	buf, err := json.Marshal(user)
	if err != nil {
		return err
	}

	if _, err = kv.Put(username, buf); err != nil {
		return err
	}

	providerLog(logger.LevelDebug, "transfer quota updated for user %q, ul increment: %v dl increment: %v is reset? %v", username, uploadSize, downloadSize, reset)
	return nil
}

func (n *NATSProvider) updateQuota(username string, filesAdd int, sizeAdd int64, reset bool) error {
	kv, err := n.getUsersBucket()
	if err != nil {
		return err
	}

	entry, err := kv.Get(username)
	if err != nil {
		return util.NewRecordNotFoundError(fmt.Sprintf("username %q does not exist, unable to update quota", username))
	}

	var user User
	if err = user.Unmarshal(entry.Value()); err != nil {
		return err
	}

	if reset {
		user.UsedQuotaSize = sizeAdd
		user.UsedQuotaFiles = filesAdd
	} else {
		user.UsedQuotaSize += sizeAdd
		user.UsedQuotaFiles += filesAdd
	}

	user.LastQuotaUpdate = util.GetTimeAsMsSinceEpoch(time.Now())
	buf, err := json.Marshal(user)
	if err != nil {
		return err
	}

	if _, err = kv.Put(username, buf); err != nil {
		return err
	}

	providerLog(logger.LevelDebug, "quota updated for user %q, files increment: %v size increment: %v is reset? %v", username, filesAdd, sizeAdd, reset)
	return nil
}

func (n *NATSProvider) updateAdmin(admin *Admin) error {
	if err := admin.validate(); err != nil {
		return err
	}

	kv, err := n.getAdminsBucket()
	if err != nil {
		return err
	}

	groupBucket, err := n.getGroupsBucket()
	if err != nil {
		return err
	}

	rolesBucket, err := n.getRolesBucket()
	if err != nil {
		return err
	}

	entry, err := kv.Get(admin.Username)
	if err != nil {
		return util.NewRecordNotFoundError(fmt.Sprintf("admin %v does not exist", admin.Username))
	}

	var oldAdmin Admin
	if err = oldAdmin.Unmarshal(entry.Value()); err != nil {
		return err
	}

	if err = n.removeAdminFromRole(oldAdmin.Username, oldAdmin.Role, rolesBucket); err != nil {
		return err
	}

	for idx := range oldAdmin.Groups {
		if err = n.removeAdminFromGroupMapping(oldAdmin.Username, oldAdmin.Groups[idx].Name, groupBucket); err != nil {
			return err
		}
	}

	if err = n.addAdminToRole(admin.Username, admin.Role, rolesBucket); err != nil {
		return err
	}

	sort.Slice(admin.Groups, func(i, j int) bool {
		return admin.Groups[i].Name < admin.Groups[j].Name
	})

	for idx := range admin.Groups {
		if err = n.addAdminToGroupMapping(admin.Username, admin.Groups[idx].Name, groupBucket); err != nil {
			return err
		}
	}

	admin.ID = oldAdmin.ID
	admin.CreatedAt = oldAdmin.CreatedAt
	admin.LastLogin = oldAdmin.LastLogin
	admin.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())

	buf, err := json.Marshal(admin)
	if err != nil {
		return err
	}

	if _, err := kv.Put(admin.Username, buf); err != nil {
		return err
	}
	return nil
}

func (n *NATSProvider) deleteAdmin(admin Admin) error {
	kv, err := n.getAdminsBucket()
	if err != nil {
		return err
	}

	entry, err := kv.Get(admin.Username)
	if err != nil {
		return util.NewRecordNotFoundError(fmt.Sprintf("admin %v does not exist", admin.Username))
	}

	var oldAdmin Admin
	if err = oldAdmin.Unmarshal(entry.Value()); err != nil {
		return err
	}

	if len(oldAdmin.Groups) > 0 {
		groupBucket, err := n.getGroupsBucket()
		if err != nil {
			return err
		}

		for idx := range oldAdmin.Groups {
			err = n.removeAdminFromGroupMapping(oldAdmin.Username, oldAdmin.Groups[idx].Name, groupBucket)
			if err != nil {
				return err
			}
		}
	}

	if oldAdmin.Role != "" {
		rolesBucket, err := n.getRolesBucket()
		if err != nil {
			return err
		}

		if err = n.removeAdminFromRole(oldAdmin.Username, oldAdmin.Role, rolesBucket); err != nil {
			return err
		}
	}

	if err := n.deleteRelatedAPIKey(admin.Username, APIKeyScopeAdmin); err != nil {
		return err
	}
	return kv.Delete(admin.Username)
}

func (n *NATSProvider) resetDatabase() error {
	for name, kvBucket := range natsBuckets {
		if err := kvBucket.Delete(name); err != nil {
			if !errors.Is(err, nats.ErrStreamNotFound) {
				return fmt.Errorf("unable to delete bucket %q: %w", name, err)
			}
		}
	}

	for _, name := range storageNames {
		userStore, err := bucket.CreateKeyValueBucket(n.jsHandle, name)
		if err != nil {
			return fmt.Errorf("unable to recreate bucket %q: %w", name, err)
		}
		natsBuckets[name] = userStore
	}

	return nil

}

func (n *NATSProvider) joinRuleAndActions(r []byte, kv *bucket.KeyValueBucket) (EventRule, error) {
	var rule EventRule
	if err := rule.Unmarshal(r); err != nil {
		return EventRule{}, err
	}

	var actions []EventAction
	for idx := range rule.Actions {
		action := &rule.Actions[idx]
		var baseAction BaseEventAction
		entry, err := kv.Get(action.Name)
		if err != nil {
			continue
		}

		if err = baseAction.Unmarshal(entry.Value()); err != nil {
			continue
		}

		baseAction.Options.SetEmptySecretsIfNil()
		action.BaseEventAction = baseAction
		actions = append(actions, *action)
	}
	rule.Actions = actions
	return rule, nil
}

func (n *NATSProvider) joinGroupAndFolders(g []byte, foldersBucket *bucket.KeyValueBucket) (Group, error) {
	var group Group
	if err := group.Unmarshal(g); err != nil {
		return Group{}, err
	}

	if len(group.VirtualFolders) > 0 {
		var folders []vfs.VirtualFolder
		for idx := range group.VirtualFolders {
			folder := &group.VirtualFolders[idx]
			baseFolder, err := n.folderExistsInternal(folder.Name, foldersBucket)
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

func (n *NATSProvider) joinUserAndFolders(u []byte, kv *bucket.KeyValueBucket) (User, error) {
	var user User
	if err := user.Unmarshal(u); err != nil {
		return User{}, err
	}

	if len(user.VirtualFolders) > 0 {
		var folders []vfs.VirtualFolder
		for idx := range user.VirtualFolders {
			folder := &user.VirtualFolders[idx]
			baseFolder, err := n.folderExistsInternal(folder.Name, kv)
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

func (n *NATSProvider) groupExistsInternal(name string, kv *bucket.KeyValueBucket) (Group, error) {
	entry, err := kv.Get(name)
	if err != nil {
		err := util.NewRecordNotFoundError(fmt.Sprintf("group %q does not exist", name))
		return Group{}, err
	}

	var group Group
	if err := group.Unmarshal(entry.Value()); err != nil {
		return Group{}, err
	}
	return group, err
}

func (n *NATSProvider) addFolderInternal(folder vfs.BaseVirtualFolder, kv *bucket.KeyValueBucket) error {
	folder.ID = time.Now().UnixNano()

	buf, err := folder.Marshal()
	if err != nil {
		return err
	}

	if _, err := kv.Put(folder.Name, buf); err != nil {
		return err
	}
	return nil
}

func (n *NATSProvider) removeRoleFromUser(username, role string, kv *bucket.KeyValueBucket) error {
	entry, err := kv.Get(username)
	if err != nil {
		providerLog(logger.LevelWarn, "user %q does not exist, cannot remove role %q", username, role)
		return nil
	}

	var user User
	if err := user.Unmarshal(entry.Value()); err != nil {
		return err
	}

	if user.Role == role {
		user.Role = ""
		buf, err := user.Marshal()
		if err != nil {
			return err
		}

		if _, err := kv.Put(user.Username, buf); err != nil {
			return err
		}
	}
	providerLog(logger.LevelError, "user %q does not have the expected role %q, actual %q", username, role, user.Role)
	return nil
}

func (n *NATSProvider) removeAdminFromRole(username, roleName string, kv *bucket.KeyValueBucket) error {
	if roleName == "" {
		return nil
	}

	entry, err := kv.Get(roleName)
	if err != nil {
		providerLog(logger.LevelWarn, "role %q does not exist, cannot remove admin %q", roleName, username)
		return nil
	}

	var role Role
	if err := role.Unmarshal(entry.Value()); err != nil {
		return err
	}

	if slices.Contains(role.Admins, username) {
		var admins []string
		for _, admin := range role.Admins {
			if admin != username {
				admins = append(admins, admin)
			}
		}

		role.Admins = util.RemoveDuplicates(admins, false)
		buf, err := role.Marshal()
		if err != nil {
			return err
		}

		if _, err := kv.Put(role.Name, buf); err != nil {
			return err
		}
	}
	return nil
}

func (n *NATSProvider) addUserToRole(username, roleName string, kv *bucket.KeyValueBucket) error {
	if roleName == "" {
		return nil
	}

	entry, err := kv.Get(roleName)
	if err != nil {
		return fmt.Errorf("%w: role %q does not exist", ErrForeignKeyViolated, roleName)
	}

	var role Role
	if err := role.Unmarshal(entry.Value()); err != nil {
		return err
	}

	if !slices.Contains(role.Users, username) {
		role.Users = append(role.Users, username)
		buf, err := role.Marshal()
		if err != nil {
			return err
		}

		if _, err := kv.Put(role.Name, buf); err != nil {
			return err
		}
	}
	return nil
}

func (n *NATSProvider) removeUserFromRole(username, roleName string, kv *bucket.KeyValueBucket) error {
	if roleName == "" {
		return nil
	}

	entry, err := kv.Get(roleName)
	if err != nil {
		providerLog(logger.LevelWarn, "role %q does not exist, cannot remove admin %q", roleName, username)
		return nil
	}

	var role Role
	if err := role.Unmarshal(entry.Value()); err != nil {
		return err
	}

	if slices.Contains(role.Users, username) {
		var users []string
		for _, user := range role.Users {
			if user != username {
				users = append(users, user)
			}
		}

		users = util.RemoveDuplicates(users, false)
		role.Users = users
		buf, err := role.Marshal()
		if err != nil {
			return err
		}

		if _, err := kv.Put(role.Name, buf); err != nil {
			return err
		}
	}
	return nil
}

func (n *NATSProvider) addRuleToActionMapping(ruleName, actionName string, kv *bucket.KeyValueBucket) error {
	entry, err := kv.Get(actionName)
	if err != nil {
		return util.NewGenericError(fmt.Sprintf("action %q does not exist", actionName))
	}

	var action BaseEventAction
	if err := action.Unmarshal(entry.Value()); err != nil {
		return err
	}

	if !slices.Contains(action.Rules, ruleName) {
		action.Rules = append(action.Rules, ruleName)
		buf, err := json.Marshal(action)
		if err != nil {
			return err
		}

		if _, err := kv.Put(action.Name, buf); err != nil {
			return err
		}
	}
	return nil
}

func (n *NATSProvider) removeRuleFromActionMapping(ruleName, actionName string, kv *bucket.KeyValueBucket) error {
	entry, err := kv.Get(actionName)
	if err != nil {
		providerLog(logger.LevelWarn, "action %q does not exist, cannot remove from mapping", actionName)
		return nil
	}

	var action BaseEventAction
	if err := action.Unmarshal(entry.Value()); err != nil {
		return err
	}

	if slices.Contains(action.Rules, ruleName) {
		var rules []string
		for _, r := range action.Rules {
			if r != ruleName {
				rules = append(rules, r)
			}
		}

		action.Rules = util.RemoveDuplicates(rules, false)

		buf, err := json.Marshal(action)
		if err != nil {
			return err
		}

		if _, err := kv.Put(action.Name, buf); err != nil {
			return err
		}
	}
	return nil
}

func (n *NATSProvider) addUserToGroupMapping(username, groupname string, kv *bucket.KeyValueBucket) error {
	entry, err := kv.Get(groupname)
	if err != nil {
		return util.NewGenericError(fmt.Sprintf("group %q does not exist", groupname))
	}

	var group Group
	if err := group.Unmarshal(entry.Value()); err != nil {
		return err
	}

	if !slices.Contains(group.Users, username) {
		group.Users = append(group.Users, username)
		buf, err := json.Marshal(group)
		if err != nil {
			return err
		}

		if _, err := kv.Put(group.Name, buf); err != nil {
			return err
		}
	}
	return nil
}

func (n *NATSProvider) removeUserFromGroupMapping(username, groupname string, kv *bucket.KeyValueBucket) error {
	entry, err := kv.Get(groupname)
	if err != nil {
		return util.NewRecordNotFoundError(fmt.Sprintf("group %q does not exist", groupname))
	}

	var group Group
	if err := group.Unmarshal(entry.Value()); err != nil {
		return err
	}

	var users []string
	for _, u := range group.Users {
		if u != username {
			users = append(users, u)
		}
	}

	group.Users = util.RemoveDuplicates(users, false)

	buf, err := json.Marshal(group)
	if err != nil {
		return err
	}

	if _, err := kv.Put(group.Name, buf); err != nil {
		return err
	}
	return nil
}

func (n *NATSProvider) removeAdminFromGroupMapping(username, groupname string, kv *bucket.KeyValueBucket) error {
	entry, err := kv.Get(groupname)
	if err != nil {
		return util.NewRecordNotFoundError(fmt.Sprintf("group %q does not exist", groupname))
	}

	var group Group
	if err := group.Unmarshal(entry.Value()); err != nil {
		return err
	}

	var admins []string
	for _, a := range group.Admins {
		if a != username {
			admins = append(admins, a)
		}
	}

	group.Admins = util.RemoveDuplicates(admins, false)

	buf, err := json.Marshal(group)
	if err != nil {
		return err
	}

	if _, err := kv.Put(group.Name, buf); err != nil {
		return err
	}
	return nil
}

func (n *NATSProvider) removeGroupFromAdminMapping(groupName, adminName string, kv *bucket.KeyValueBucket) error {
	entry, err := kv.Get(adminName)
	if err != nil {
		return err
	}

	var admin Admin
	if err := admin.Unmarshal(entry.Value()); err != nil {
		return err
	}

	var newGroups []AdminGroupMapping
	for _, g := range admin.Groups {
		if g.Name != groupName {
			newGroups = append(newGroups, g)
		}
	}

	admin.Groups = newGroups

	buf, err := admin.Marshal()
	if err != nil {
		return err
	}

	if _, err := kv.Put(adminName, buf); err != nil {
		return err
	}
	return nil
}

func (n *NATSProvider) addRelationToFolderMapping(folderName string, user *User, group *Group, kv *bucket.KeyValueBucket) error {
	entry, err := kv.Get(folderName)
	if err != nil {
		return util.NewGenericError(fmt.Sprintf("folder %q does not exist", folderName))
	}

	var folder vfs.BaseVirtualFolder
	if err := folder.Unmarshal(entry.Value()); err != nil {
		return err
	}

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

	buf, err := folder.Marshal()
	if err != nil {
		return err
	}

	if _, err := kv.Put(folder.Name, buf); err != nil {
		return err
	}
	return nil
}

func (n *NATSProvider) removeRelationFromFolderMapping(folder vfs.VirtualFolder, username, groupname string, kv *bucket.KeyValueBucket) error {
	entry, err := kv.Get(folder.Name)
	if err != nil {
		return nil
	}

	var baseFolder vfs.BaseVirtualFolder
	if err := baseFolder.Unmarshal(entry.Value()); err != nil {
		return err
	}

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

	buf, err := baseFolder.Marshal()
	if err != nil {
		return err
	}

	if _, err := kv.Put(folder.Name, buf); err != nil {
		return err
	}
	return nil
}

func (n *NATSProvider) updateUserRelations(user *User, oldUser User) error {
	foldersBucket, err := n.getFoldersBucket()
	if err != nil {
		return err
	}

	groupsBucket, err := n.getGroupsBucket()
	if err != nil {
		return err
	}

	rolesBucket, err := n.getRolesBucket()
	if err != nil {
		return err
	}

	for idx := range oldUser.VirtualFolders {
		if err = n.removeRelationFromFolderMapping(oldUser.VirtualFolders[idx], oldUser.Username, "", foldersBucket); err != nil {
			return err
		}
	}

	for idx := range oldUser.Groups {
		if err = n.removeUserFromGroupMapping(user.Username, oldUser.Groups[idx].Name, groupsBucket); err != nil {
			return err
		}
	}

	if err = n.removeUserFromRole(oldUser.Username, oldUser.Role, rolesBucket); err != nil {
		return err
	}

	sort.Slice(user.VirtualFolders, func(i, j int) bool {
		return user.VirtualFolders[i].Name < user.VirtualFolders[j].Name
	})

	for idx := range user.VirtualFolders {
		if err = n.addRelationToFolderMapping(user.VirtualFolders[idx].Name, user, nil, foldersBucket); err != nil {
			return err
		}
	}

	sort.Slice(user.Groups, func(i, j int) bool {
		return user.Groups[i].Name < user.Groups[j].Name
	})

	for idx := range user.Groups {
		if err = n.addUserToGroupMapping(user.Username, user.Groups[idx].Name, groupsBucket); err != nil {
			return err
		}
	}
	return n.addUserToRole(user.Username, user.Role, rolesBucket)
}

func (n *NATSProvider) adminExistsInternal(username string) error {
	kv, err := n.getAdminsBucket()
	if err != nil {
		return err
	}

	entry, err := kv.Get(username)
	if err != nil {
		return util.NewRecordNotFoundError(fmt.Sprintf("admin %v does not exist", username))
	}

	if entry.Value() == nil {
		return err
	}
	return nil
}

func (n *NATSProvider) userExistsInternal(username string) error {
	kv, err := n.getUsersBucket()
	if err != nil {
		return err
	}

	entry, err := kv.Get(username)
	if err != nil {
		return util.NewRecordNotFoundError(fmt.Sprintf("username %q does not exist", username))
	}

	if entry.Value() == nil {
		return err
	}
	return nil
}

func (n *NATSProvider) deleteRelatedShares(username string) error {
	kv, err := n.getSharesBucket()
	if err != nil {
		return err
	}

	var toRemove []string
	entry, err := kv.Get(username)
	if err != nil {
		return err
	}

	var share Share
	if err = share.Unmarshal(entry.Value()); err != nil {
		return err
	}

	if share.Username == username {
		toRemove = append(toRemove, share.ShareID)
	}

	for _, k := range toRemove {
		if err := kv.Delete(k); err != nil {
			return err
		}
	}
	return nil
}

func (n *NATSProvider) deleteRelatedAPIKey(username string, scope APIKeyScope) error {
	kv, err := n.getAPIKeysBucket()
	if err != nil {
		return fmt.Errorf("failed to get API keys bucket: %w", err)
	}

	entry, err := kv.Get(username)
	if err != nil {
		return fmt.Errorf("failed to get API key entry: %w", err)
	}

	var apiKey APIKey
	if err = apiKey.Unmarshal(entry.Value()); err != nil {
		return fmt.Errorf("failed to unmarshal API key: %w", err)
	}

	keyToDelete := n.getKeyIDToDelete(username, scope, apiKey)
	if keyToDelete == "" {
		return nil // No matching key found
	}

	if err := kv.Delete(keyToDelete); err != nil {
		return fmt.Errorf("failed to delete API key %s: %w", keyToDelete, err)
	}
	return nil
}

func (n *NATSProvider) getKeyIDToDelete(username string, scope APIKeyScope, apiKey APIKey) string {
	switch scope {
	case APIKeyScopeUser:
		if apiKey.User == username {
			return apiKey.KeyID
		}
	case APIKeyScopeAdmin:
		if apiKey.Admin == username {
			return apiKey.KeyID
		}
	}
	return ""
}

func (n *NATSProvider) getDefenderHosts(_ int64, _ int) ([]DefenderEntry, error) {
	return nil, ErrNotImplemented
}

func (n *NATSProvider) getDefenderHostByIP(_ string, _ int64) (DefenderEntry, error) {
	return DefenderEntry{}, ErrNotImplemented
}

func (n *NATSProvider) isDefenderHostBanned(_ string) (DefenderEntry, error) {
	return DefenderEntry{}, ErrNotImplemented
}

func (n *NATSProvider) updateDefenderBanTime(_ string, _ int) error {
	return ErrNotImplemented
}

func (n *NATSProvider) deleteDefenderHost(_ string) error {
	return ErrNotImplemented
}

func (n *NATSProvider) addDefenderEvent(_ string, _ int) error {
	return ErrNotImplemented
}

func (n *NATSProvider) setDefenderBanTime(_ string, _ int64) error {
	return ErrNotImplemented
}

func (n *NATSProvider) cleanupDefender(_ int64) error {
	return ErrNotImplemented
}

func (n *NATSProvider) addActiveTransfer(_ ActiveTransfer) error {
	return ErrNotImplemented
}

func (n *NATSProvider) updateActiveTransferSizes(_, _, _ int64, _ string) error {
	return ErrNotImplemented
}

func (n *NATSProvider) removeActiveTransfer(_ int64, _ string) error {
	return ErrNotImplemented
}

func (n *NATSProvider) cleanupActiveTransfers(_ time.Time) error {
	return ErrNotImplemented
}

func (n *NATSProvider) getActiveTransfers(_ time.Time) ([]ActiveTransfer, error) {
	return nil, ErrNotImplemented
}

func (n *NATSProvider) addSharedSession(_ Session) error {
	return ErrNotImplemented
}

func (n *NATSProvider) deleteSharedSession(_ string, _ SessionType) error {
	return ErrNotImplemented
}

func (n *NATSProvider) getSharedSession(_ string, _ SessionType) (Session, error) {
	return Session{}, ErrNotImplemented
}

func (n *NATSProvider) cleanupSharedSessions(_ SessionType, _ int64) error {
	return ErrNotImplemented
}

func (*NATSProvider) getTaskByName(_ string) (Task, error) {
	return Task{}, ErrNotImplemented
}

func (*NATSProvider) addTask(_ string) error {
	return ErrNotImplemented
}

func (*NATSProvider) updateTask(_ string, _ int64) error {
	return ErrNotImplemented
}

func (*NATSProvider) updateTaskTimestamp(_ string) error {
	return ErrNotImplemented
}

func (*NATSProvider) addNode() error {
	return ErrNotImplemented
}

func (*NATSProvider) getNodeByName(_ string) (Node, error) {
	return Node{}, ErrNotImplemented
}

func (*NATSProvider) getNodes() ([]Node, error) {
	return nil, ErrNotImplemented
}

func (*NATSProvider) updateNodeTimestamp() error {
	return ErrNotImplemented
}

func (*NATSProvider) cleanupNodes() error {
	return ErrNotImplemented
}

func (n *NATSProvider) getRecentlyUpdatedIPListEntries(_ int64) ([]IPListEntry, error) {
	return nil, ErrNotImplemented
}

func (n *NATSProvider) initializeDatabase() error {
	return ErrNoInitRequired
}

func (n *NATSProvider) getAdmins(limit, offset int, order string) ([]Admin, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("limit must be positive, got %d", limit)
	}

	if offset < 0 {
		return nil, fmt.Errorf("offset must be non-negative, got %d", offset)
	}

	capacity := min(limit, 10)
	admins := make([]Admin, 0, capacity)

	kv, err := n.getAdminsBucket()
	if err != nil {
		return nil, fmt.Errorf("failed to get admins bucket: %w", err)
	}

	opts := []nats.WatchOpt{nats.UpdatesOnly(), nats.MetaOnly()}
	keys, err := kv.Keys(opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to get admin keys: %w", err)
	}

	// Apply ordering
	if order == "desc" {
		for i, j := 0, len(keys)-1; i < j; i, j = i+1, j-1 {
			keys[i], keys[j] = keys[j], keys[i]
		}
	}

	// Apply pagination
	start := offset
	end := min(start+limit, len(keys))
	if start >= len(keys) {
		return admins, nil
	}

	for _, key := range keys[start:end] {
		entry, err := kv.Get(key)
		if err != nil {
			return nil, fmt.Errorf("failed to get admin data for key %s: %w", key, err)
		}

		var admin Admin
		if err = admin.Unmarshal(entry.Value()); err != nil {
			return nil, fmt.Errorf("failed to unmarshal admin data for key %s: %w", key, err)
		}

		admin.HideConfidentialData()
		admins = append(admins, admin)
	}
	return admins, nil
}

func (n *NATSProvider) dumpAdmins() ([]Admin, error) {
	admins := make([]Admin, 0, 30)

	kv, err := n.getAdminsBucket()
	if err != nil {
		return nil, fmt.Errorf("failed to get admins bucket: %w", err)
	}

	keys, err := kv.Keys()
	if err != nil {
		return nil, fmt.Errorf("failed to list admin keys: %w", err)
	}

	for _, key := range keys {
		entry, err := kv.Get(key)
		if err != nil {
			return nil, fmt.Errorf("failed to get admin data for key %s: %w", key, err)
		}

		var admin Admin
		if err := admin.Unmarshal(entry.Value()); err != nil {
			return nil, fmt.Errorf("failed to unmarshal admin data for key %s: %w", key, err)
		}

		admins = append(admins, admin)
	}
	return admins, nil
}

func (n *NATSProvider) addUser(user *User) error {
	if err := ValidateUser(user); err != nil {
		return err
	}

	// Get all required buckets
	usersBucket, err := n.getUsersBucket()
	if err != nil {
		return fmt.Errorf("failed to get users bucket: %w", err)
	}

	foldersBucket, err := n.getFoldersBucket()
	if err != nil {
		return fmt.Errorf("failed to get folders bucket: %w", err)
	}

	groupsBucket, err := n.getGroupsBucket()
	if err != nil {
		return fmt.Errorf("failed to get groups bucket: %w", err)
	}

	rolesBucket, err := n.getRolesBucket()
	if err != nil {
		return fmt.Errorf("failed to get roles bucket: %w", err)
	}

	// Check if a user already exists
	entry, err := usersBucket.Get(user.Username)
	if err == nil && entry != nil {
		return util.NewI18nError(
			fmt.Errorf("%w: username %v already exists", ErrDuplicatedKey, user.Username),
			util.I18nErrorDuplicatedUsername,
		)
	}

	if err != nil && !errors.Is(err, nats.ErrKeyNotFound) {
		return fmt.Errorf("failed to check existing user: %w", err)
	}

	// Initialize user fields
	now := util.GetTimeAsMsSinceEpoch(time.Now())
	user.LastQuotaUpdate = 0
	user.UsedQuotaSize = 0
	user.UsedQuotaFiles = 0
	user.UsedUploadDataTransfer = 0
	user.UsedDownloadDataTransfer = 0
	user.LastLogin = 0
	user.FirstDownload = 0
	user.FirstUpload = 0
	user.CreatedAt = now
	user.UpdatedAt = now

	// Add a user to a role
	if err := n.addUserToRole(user.Username, user.Role, rolesBucket); err != nil {
		return fmt.Errorf("failed to add user to role: %w", err)
	}

	// Process virtual folders
	sort.Slice(user.VirtualFolders, func(i, j int) bool {
		return user.VirtualFolders[i].Name < user.VirtualFolders[j].Name
	})

	for idx := range user.VirtualFolders {
		if err := n.addRelationToFolderMapping(user.VirtualFolders[idx].Name, user, nil, foldersBucket); err != nil {
			return fmt.Errorf("failed to add folder mapping: %w", err)
		}
	}

	// Process groups
	sort.Slice(user.Groups, func(i, j int) bool {
		return user.Groups[i].Name < user.Groups[j].Name
	})

	for idx := range user.Groups {
		if err := n.addUserToGroupMapping(user.Username, user.Groups[idx].Name, groupsBucket); err != nil {
			return fmt.Errorf("failed to add group mapping: %w", err)
		}
	}

	// Marshal and store user data
	buf, err := json.Marshal(user)
	if err != nil {
		return fmt.Errorf("failed to marshal user data: %w", err)
	}

	// Create the user entry in the NATS KV store
	if _, err = usersBucket.Create(user.Username, buf); err != nil {
		return fmt.Errorf("failed to create user entry: %w", err)
	}
	return nil
}

func (n *NATSProvider) updateUser(user *User) error {
	if err := ValidateUser(user); err != nil {
		return err
	}

	valueBucket, err := n.getUsersBucket()
	if err != nil {
		return err
	}

	// Get existing user
	entry, err := valueBucket.Get(user.Username)
	if err != nil {
		if errors.Is(err, nats.ErrKeyNotFound) {
			return util.NewRecordNotFoundError(fmt.Sprintf("username %q does not exist", user.Username))
		}
		return err
	}

	var oldUser User
	if err := oldUser.Unmarshal(entry.Value()); err != nil {
		return err
	}

	if err := n.updateUserRelations(user, oldUser); err != nil {
		return err
	}

	reflection.MergeZeroFields(user, oldUser)
	user.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())

	buf, err := json.Marshal(user)
	if err != nil {
		return err
	}

	// Use Update with revision for atomic operation
	if _, err = valueBucket.Update(user.Username, buf, entry.Revision()); err == nil {
		setLastUserUpdate()
	}
	return err
}

func (n *NATSProvider) deleteUser(user User, _ bool) error {
	usersBucket, err := n.getUsersBucket()
	if err != nil {
		return fmt.Errorf("failed to get users bucket: %w", err)
	}

	foldersBucket, err := n.getFoldersBucket()
	if err != nil {
		return fmt.Errorf("failed to get folders bucket: %w", err)
	}

	groupsBucket, err := n.getGroupsBucket()
	if err != nil {
		return fmt.Errorf("failed to get groups bucket: %w", err)
	}

	rolesBucket, err := n.getRolesBucket()
	if err != nil {
		return fmt.Errorf("failed to get roles bucket: %w", err)
	}

	entry, err := usersBucket.Get(user.Username)
	if err != nil {
		if errors.Is(err, nats.ErrKeyNotFound) {
			return util.NewRecordNotFoundError(fmt.Sprintf("username %q does not exist", user.Username))
		}
		return fmt.Errorf("failed to get user: %w", err)
	}

	var oldUser User
	if err := oldUser.Unmarshal(entry.Value()); err != nil {
		return fmt.Errorf("failed to unmarshal user data: %w", err)
	}

	if err := n.removeUserFromRole(oldUser.Username, oldUser.Role, rolesBucket); err != nil {
		return fmt.Errorf("failed to remove user from role: %w", err)
	}

	for idx := range oldUser.VirtualFolders {
		if err := n.removeRelationFromFolderMapping(oldUser.VirtualFolders[idx], oldUser.Username, "", foldersBucket); err != nil {
			return fmt.Errorf("failed to remove folder mapping: %w", err)
		}
	}

	for idx := range oldUser.Groups {
		if err := n.removeUserFromGroupMapping(oldUser.Username, oldUser.Groups[idx].Name, groupsBucket); err != nil {
			return fmt.Errorf("failed to remove group mapping: %w", err)
		}
	}

	if err := n.deleteRelatedAPIKey(user.Username, APIKeyScopeUser); err != nil {
		return fmt.Errorf("failed to delete related API keys: %w", err)
	}

	if err := n.deleteRelatedShares(user.Username); err != nil {
		return fmt.Errorf("failed to delete related shares: %w", err)
	}

	if err := usersBucket.Delete(user.Username); err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}
	return nil
}

func (n *NATSProvider) updateUserPassword(username, password string) error {
	usersBucket, err := n.getUsersBucket()
	if err != nil {
		return err
	}

	entry, err := usersBucket.Get(username)
	if err != nil {
		if errors.Is(err, nats.ErrKeyNotFound) {
			return util.NewRecordNotFoundError(fmt.Sprintf("username %q does not exist", username))
		}
		return err
	}

	var user User
	if err := user.Unmarshal(entry.Value()); err != nil {
		return err
	}

	user.Password = password
	user.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())

	buf, err := user.Marshal()
	if err != nil {
		return err
	}

	if _, err := usersBucket.Update(username, buf, entry.Revision()); err != nil {
		return err
	}
	return nil
}

func (n *NATSProvider) dumpUsers() ([]User, error) {
	users := make([]User, 0, 100)

	usersBucket, err := n.getUsersBucket()
	if err != nil {
		return nil, err
	}

	foldersBucket, err := n.getFoldersBucket()
	if err != nil {
		return nil, err
	}

	keys, err := usersBucket.Keys()
	if err != nil {
		return nil, err
	}

	for _, key := range keys {
		entry, err := usersBucket.Get(key)
		if err != nil {
			continue
		}
		user, err := n.joinUserAndFolders(entry.Value(), foldersBucket)
		if err != nil {
			continue
		}
		users = append(users, user)
	}
	return users, nil
}

func (n *NATSProvider) getRecentlyUpdatedUsers(after int64) ([]User, error) {
	if getLastUserUpdate() < after {
		return nil, nil
	}

	users := make([]User, 0, 10)

	usersBucket, err := n.getUsersBucket()
	if err != nil {
		return nil, err
	}

	foldersBucket, err := n.getFoldersBucket()
	if err != nil {
		return nil, err
	}

	groupsBucket, err := n.getGroupsBucket()
	if err != nil {
		return nil, err
	}

	keys, err := usersBucket.Keys()
	if err != nil {
		return nil, err
	}

	for _, key := range keys {
		entry, err := usersBucket.Get(key)
		if err != nil {
			continue
		}

		var user User
		if err := user.Unmarshal(entry.Value()); err != nil {
			continue
		}

		if user.UpdatedAt < after {
			continue
		}

		if len(user.VirtualFolders) > 0 {
			var folders []vfs.VirtualFolder
			for idx := range user.VirtualFolders {
				folder := &user.VirtualFolders[idx]
				baseFolder, err := n.folderExistsInternal(folder.Name, foldersBucket)
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
				group, err := n.groupExistsInternal(user.Groups[idx].Name, groupsBucket)
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
	return users, nil
}

func (n *NATSProvider) getUsersForQuotaCheck(toFetch map[string]bool) ([]User, error) {
	users := make([]User, 0, 10)

	usersBucket, err := n.getUsersBucket()
	if err != nil {
		return nil, err
	}

	foldersBucket, err := n.getFoldersBucket()
	if err != nil {
		return nil, err
	}

	groupsBucket, err := n.getGroupsBucket()
	if err != nil {
		return nil, err
	}

	for username := range toFetch {
		entry, err := usersBucket.Get(username)
		if err != nil {
			continue
		}

		var user User
		if err := user.Unmarshal(entry.Value()); err != nil {
			continue
		}

		needFolders := toFetch[user.Username]
		if needFolders && len(user.VirtualFolders) > 0 {
			var folders []vfs.VirtualFolder
			for idx := range user.VirtualFolders {
				folder := &user.VirtualFolders[idx]
				baseFolder, err := n.folderExistsInternal(folder.Name, foldersBucket)
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
				group, err := n.groupExistsInternal(user.Groups[idx].Name, groupsBucket)
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

func (n *NATSProvider) getUsers(limit int, offset int, order, role string) ([]User, error) {
	if limit <= 0 {
		return []User{}, nil
	}

	usersBucket, err := n.getUsersBucket()
	if err != nil {
		return nil, err
	}

	foldersBucket, err := n.getFoldersBucket()
	if err != nil {
		return nil, err
	}

	keys, err := usersBucket.Keys()
	if err != nil {
		return nil, err
	}

	// Sort keys based on order
	if order == OrderDESC {
		sort.Sort(sort.Reverse(sort.StringSlice(keys)))
	} else {
		sort.Strings(keys)
	}

	users := make([]User, 0, limit)
	itNum := 0

	for _, key := range keys {
		itNum++
		if itNum <= offset {
			continue
		}

		entry, err := usersBucket.Get(key)
		if err != nil {
			continue
		}

		user, err := n.joinUserAndFolders(entry.Value(), foldersBucket)
		if err != nil {
			continue
		}

		if !user.hasRole(role) {
			continue
		}

		user.PrepareForRendering()
		users = append(users, user)

		if len(users) >= limit {
			break
		}
	}
	return users, nil
}

func (n *NATSProvider) dumpFolders() ([]vfs.BaseVirtualFolder, error) {
	folders := make([]vfs.BaseVirtualFolder, 0, 50)

	foldersBucket, err := n.getFoldersBucket()
	if err != nil {
		return nil, err
	}

	keys, err := foldersBucket.Keys()
	if err != nil {
		return nil, err
	}

	for _, key := range keys {
		entry, err := foldersBucket.Get(key)
		if err != nil {
			continue
		}

		var folder vfs.BaseVirtualFolder
		if err := folder.Unmarshal(entry.Value()); err != nil {
			continue
		}

		folders = append(folders, folder)
	}
	return folders, nil
}

func (n *NATSProvider) getFolders(limit, offset int, order string, _ bool) ([]vfs.BaseVirtualFolder, error) {
	if limit <= 0 {
		return []vfs.BaseVirtualFolder{}, nil
	}

	foldersBucket, err := n.getFoldersBucket()
	if err != nil {
		return nil, err
	}

	keys, err := foldersBucket.Keys()
	if err != nil {
		return nil, err
	}

	// Sort keys based on order
	if order == OrderDESC {
		sort.Sort(sort.Reverse(sort.StringSlice(keys)))
	} else {
		sort.Strings(keys)
	}

	folders := make([]vfs.BaseVirtualFolder, 0, limit)
	itNum := 0

	for _, key := range keys {
		itNum++
		if itNum <= offset {
			continue
		}

		entry, err := foldersBucket.Get(key)
		if err != nil {
			continue
		}

		var folder vfs.BaseVirtualFolder
		if err := folder.Unmarshal(entry.Value()); err != nil {
			continue
		}

		folder.PrepareForRendering()
		folders = append(folders, folder)

		if len(folders) >= limit {
			break
		}
	}
	return folders, nil
}

func (n *NATSProvider) getFolderByName(name string) (vfs.BaseVirtualFolder, error) {
	var folder vfs.BaseVirtualFolder

	foldersBucket, err := n.getFoldersBucket()
	if err != nil {
		return folder, err
	}

	entry, err := foldersBucket.Get(name)
	if err != nil {
		if errors.Is(err, nats.ErrKeyNotFound) {
			return folder, util.NewRecordNotFoundError(fmt.Sprintf("folder %v does not exist", name))
		}
		return folder, err
	}

	err = folder.Unmarshal(entry.Value())
	return folder, err
}

func (n *NATSProvider) addFolder(folder *vfs.BaseVirtualFolder) error {
	if err := ValidateFolder(folder); err != nil {
		return err
	}

	foldersBucket, err := n.getFoldersBucket()
	if err != nil {
		return err
	}

	if _, err = foldersBucket.Get(folder.Name); err == nil {
		return util.NewI18nError(
			fmt.Errorf("%w: folder %q already exists", ErrDuplicatedKey, folder.Name),
			util.I18nErrorDuplicatedUsername,
		)
	}

	if !errors.Is(err, nats.ErrKeyNotFound) {
		return err
	}

	folder.Users = nil
	folder.Groups = nil

	buf, err := folder.Marshal()
	if err != nil {
		return err
	}

	_, err = foldersBucket.Create(folder.Name, buf)
	return err
}

func (n *NATSProvider) updateFolder(folder *vfs.BaseVirtualFolder) error {
	if err := ValidateFolder(folder); err != nil {
		return err
	}

	foldersBucket, err := n.getFoldersBucket()
	if err != nil {
		return err
	}

	entry, err := foldersBucket.Get(folder.Name)
	if err != nil {
		if errors.Is(err, nats.ErrKeyNotFound) {
			return util.NewRecordNotFoundError(fmt.Sprintf("folder %v does not exist", folder.Name))
		}
		return err
	}

	var oldFolder vfs.BaseVirtualFolder
	if err := oldFolder.Unmarshal(entry.Value()); err != nil {
		return err
	}

	reflection.MergeZeroFields(folder, oldFolder)

	buf, err := folder.Marshal()
	if err != nil {
		return err
	}

	_, err = foldersBucket.Update(folder.Name, buf, entry.Revision())
	return err
}

func (n *NATSProvider) deleteFolderMappings(folder vfs.BaseVirtualFolder, usersBucket, groupsBucket *bucket.KeyValueBucket) error {
	for _, username := range folder.Users {
		entry, err := usersBucket.Get(username)
		if err != nil {
			if errors.Is(err, nats.ErrKeyNotFound) {
				continue
			}
			return err
		}

		var user User
		if err := user.Unmarshal(entry.Value()); err != nil {
			return err
		}

		var folders []vfs.VirtualFolder
		for _, userFolder := range user.VirtualFolders {
			if folder.Name != userFolder.Name {
				folders = append(folders, userFolder)
			}
		}

		user.VirtualFolders = folders

		buf, err := user.Marshal()
		if err != nil {
			return err
		}

		if _, err = usersBucket.Update(user.Username, buf, entry.Revision()); err != nil {
			return err
		}
	}

	for _, groupname := range folder.Groups {
		entry, err := groupsBucket.Get(groupname)
		if err != nil {
			if errors.Is(err, nats.ErrKeyNotFound) {
				continue
			}
			return err
		}

		var group Group
		if err := group.Unmarshal(entry.Value()); err != nil {
			return err
		}

		var folders []vfs.VirtualFolder
		for _, groupFolder := range group.VirtualFolders {
			if folder.Name != groupFolder.Name {
				folders = append(folders, groupFolder)
			}
		}

		group.VirtualFolders = folders

		buf, err := group.Marshal()
		if err != nil {
			return err
		}

		if _, err = groupsBucket.Update(group.Name, buf, entry.Revision()); err != nil {
			return err
		}
	}
	return nil
}

func (n *NATSProvider) deleteFolder(baseFolder vfs.BaseVirtualFolder) error {
	foldersBucket, err := n.getFoldersBucket()
	if err != nil {
		return err
	}

	usersBucket, err := n.getUsersBucket()
	if err != nil {
		return err
	}

	groupsBucket, err := n.getGroupsBucket()
	if err != nil {
		return err
	}

	entry, err := foldersBucket.Get(baseFolder.Name)
	if err != nil {
		if errors.Is(err, nats.ErrKeyNotFound) {
			return util.NewRecordNotFoundError(fmt.Sprintf("folder %v does not exist", baseFolder.Name))
		}
		return err
	}

	var folder vfs.BaseVirtualFolder
	if err := folder.Unmarshal(entry.Value()); err != nil {
		return err
	}

	if err := n.deleteFolderMappings(folder, usersBucket, groupsBucket); err != nil {
		return err
	}

	return foldersBucket.Delete(folder.Name)
}

func (n *NATSProvider) updateFolderQuota(name string, filesAdd int, sizeAdd int64, reset bool) error {
	foldersBucket, err := n.getFoldersBucket()
	if err != nil {
		return err
	}

	entry, err := foldersBucket.Get(name)
	if err != nil {
		if errors.Is(err, nats.ErrKeyNotFound) {
			return util.NewRecordNotFoundError(fmt.Sprintf("folder %q does not exist, unable to update quota", name))
		}
		return err
	}

	var folder vfs.BaseVirtualFolder
	if err := folder.Unmarshal(entry.Value()); err != nil {
		return err
	}

	if reset {
		folder.UsedQuotaSize = sizeAdd
		folder.UsedQuotaFiles = filesAdd
	} else {
		folder.UsedQuotaSize += sizeAdd
		folder.UsedQuotaFiles += filesAdd
	}

	folder.LastQuotaUpdate = util.GetTimeAsMsSinceEpoch(time.Now())

	buf, err := json.Marshal(folder)
	if err != nil {
		return err
	}

	_, err = foldersBucket.Update(folder.Name, buf, entry.Revision())
	return err
}

func (n *NATSProvider) getGroups(limit int, offset int, order string, _ bool) ([]Group, error) {
	if limit <= 0 {
		return []Group{}, nil
	}

	groupsBucket, err := n.getGroupsBucket()
	if err != nil {
		return nil, err
	}

	foldersBucket, err := n.getFoldersBucket()
	if err != nil {
		return nil, err
	}

	keys, err := groupsBucket.Keys()
	if err != nil {
		return nil, err
	}

	// Sort keys based on order
	if order == OrderDESC {
		sort.Sort(sort.Reverse(sort.StringSlice(keys)))
	} else {
		sort.Strings(keys)
	}

	groups := make([]Group, 0, limit)
	itNum := 0

	for _, key := range keys {
		itNum++
		if itNum <= offset {
			continue
		}

		entry, err := groupsBucket.Get(key)
		if err != nil {
			continue
		}

		group, err := n.joinGroupAndFolders(entry.Value(), foldersBucket)
		if err != nil {
			continue
		}

		group.PrepareForRendering()
		groups = append(groups, group)

		if len(groups) >= limit {
			break
		}
	}
	return groups, nil
}

func (n *NATSProvider) getGroupsWithNames(names []string) ([]Group, error) {
	groupsBucket, err := n.getGroupsBucket()
	if err != nil {
		return nil, err
	}

	foldersBucket, err := n.getFoldersBucket()
	if err != nil {
		return nil, err
	}

	var groups []Group
	for _, name := range names {
		entry, err := groupsBucket.Get(name)
		if err != nil {
			if errors.Is(err, nats.ErrKeyNotFound) {
				continue
			}
			return nil, err
		}

		group, err := n.joinGroupAndFolders(entry.Value(), foldersBucket)
		if err != nil {
			return nil, err
		}
		groups = append(groups, group)
	}
	return groups, nil
}

func (n *NATSProvider) getUsersInGroups(names []string) ([]string, error) {
	groupsBucket, err := n.getGroupsBucket()
	if err != nil {
		return nil, err
	}

	var usernames []string
	for _, name := range names {
		entry, err := groupsBucket.Get(name)
		if err != nil {
			if errors.Is(err, nats.ErrKeyNotFound) {
				continue
			}
			return nil, err
		}

		var group Group
		if err := group.Unmarshal(entry.Value()); err != nil {
			return nil, err
		}
		usernames = append(usernames, group.Users...)
	}
	return usernames, nil
}

func (n *NATSProvider) groupExists(name string) (Group, error) {
	var group Group

	groupsBucket, err := n.getGroupsBucket()
	if err != nil {
		return group, err
	}

	foldersBucket, err := n.getFoldersBucket()
	if err != nil {
		return group, err
	}

	entry, err := groupsBucket.Get(name)
	if err != nil {
		if errors.Is(err, nats.ErrKeyNotFound) {
			return group, util.NewRecordNotFoundError(fmt.Sprintf("group %q does not exist", name))
		}
		return group, err
	}

	return n.joinGroupAndFolders(entry.Value(), foldersBucket)
}

func (n *NATSProvider) addGroup(group *Group) error {
	if err := group.validate(); err != nil {
		return err
	}

	groupsBucket, err := n.getGroupsBucket()
	if err != nil {
		return err
	}

	foldersBucket, err := n.getFoldersBucket()
	if err != nil {
		return err
	}

	// Check if group already exists
	_, err = groupsBucket.Get(group.Name)
	if err == nil {
		return util.NewI18nError(
			fmt.Errorf("%w: group %q already exists", ErrDuplicatedKey, group.Name),
			util.I18nErrorDuplicatedUsername,
		)
	}
	if !errors.Is(err, nats.ErrKeyNotFound) {
		return err
	}

	now := util.GetTimeAsMsSinceEpoch(time.Now())
	group.CreatedAt = now
	group.UpdatedAt = now
	group.Users = nil
	group.Admins = nil

	// Sort virtual folders
	sort.Slice(group.VirtualFolders, func(i, j int) bool {
		return group.VirtualFolders[i].Name < group.VirtualFolders[j].Name
	})

	// Add folder mappings
	for idx := range group.VirtualFolders {
		if err := n.addRelationToFolderMapping(group.VirtualFolders[idx].Name, nil, group, foldersBucket); err != nil {
			return err
		}
	}

	buf, err := json.Marshal(group)
	if err != nil {
		return err
	}

	_, err = groupsBucket.Create(group.Name, buf)
	return err
}

func (n *NATSProvider) updateGroup(group *Group) error {
	if err := group.validate(); err != nil {
		return err
	}

	groupsBucket, err := n.getGroupsBucket()
	if err != nil {
		return err
	}

	foldersBucket, err := n.getFoldersBucket()
	if err != nil {
		return err
	}

	entry, err := groupsBucket.Get(group.Name)
	if err != nil {
		if errors.Is(err, nats.ErrKeyNotFound) {
			return util.NewRecordNotFoundError(fmt.Sprintf("group %q does not exist", group.Name))
		}
		return err
	}

	var oldGroup Group
	if err := json.Unmarshal(entry.Value(), &oldGroup); err != nil {
		return err
	}

	// Remove old folder mappings
	for idx := range oldGroup.VirtualFolders {
		if err := n.removeRelationFromFolderMapping(oldGroup.VirtualFolders[idx], "", oldGroup.Name, foldersBucket); err != nil {
			return err
		}
	}

	// Sort and add new folder mappings
	sort.Slice(group.VirtualFolders, func(i, j int) bool {
		return group.VirtualFolders[i].Name < group.VirtualFolders[j].Name
	})
	for idx := range group.VirtualFolders {
		if err := n.addRelationToFolderMapping(group.VirtualFolders[idx].Name, nil, group, foldersBucket); err != nil {
			return err
		}
	}

	group.ID = oldGroup.ID
	group.CreatedAt = oldGroup.CreatedAt
	group.Users = oldGroup.Users
	group.Admins = oldGroup.Admins
	group.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())

	buf, err := json.Marshal(group)
	if err != nil {
		return err
	}

	_, err = groupsBucket.Update(group.Name, buf, entry.Revision())
	return err
}

func (n *NATSProvider) deleteGroup(group Group) error {
	groupsBucket, err := n.getGroupsBucket()
	if err != nil {
		return err
	}

	entry, err := groupsBucket.Get(group.Name)
	if err != nil {
		if errors.Is(err, nats.ErrKeyNotFound) {
			return util.NewRecordNotFoundError(fmt.Sprintf("group %q does not exist", group.Name))
		}
		return err
	}

	var oldGroup Group
	if err := json.Unmarshal(entry.Value(), &oldGroup); err != nil {
		return err
	}

	if len(oldGroup.Users) > 0 {
		return util.NewValidationError(fmt.Sprintf("the group %q is referenced, it cannot be removed", oldGroup.Name))
	}

	if len(oldGroup.VirtualFolders) > 0 {
		foldersBucket, err := n.getFoldersBucket()
		if err != nil {
			return err
		}
		for idx := range oldGroup.VirtualFolders {
			if err := n.removeRelationFromFolderMapping(oldGroup.VirtualFolders[idx], "", oldGroup.Name, foldersBucket); err != nil {
				return err
			}
		}
	}

	if len(oldGroup.Admins) > 0 {
		adminsBucket, err := n.getAdminsBucket()
		if err != nil {
			return err
		}
		for idx := range oldGroup.Admins {
			if err := n.removeGroupFromAdminMapping(oldGroup.Name, oldGroup.Admins[idx], adminsBucket); err != nil {
				return err
			}
		}
	}

	return groupsBucket.Delete(group.Name)
}

func (n *NATSProvider) dumpGroups() ([]Group, error) {
	groups := make([]Group, 0, 50)

	groupsBucket, err := n.getGroupsBucket()
	if err != nil {
		return nil, err
	}

	foldersBucket, err := n.getFoldersBucket()
	if err != nil {
		return nil, err
	}

	keys, err := groupsBucket.Keys()
	if err != nil {
		return nil, err
	}

	for _, key := range keys {
		entry, err := groupsBucket.Get(key)
		if err != nil {
			continue
		}

		group, err := n.joinGroupAndFolders(entry.Value(), foldersBucket)
		if err != nil {
			return nil, err
		}
		groups = append(groups, group)
	}

	return groups, nil
}

func (n *NATSProvider) apiKeyExists(keyID string) (APIKey, error) {
	var apiKey APIKey

	apiKeysBucket, err := n.getAPIKeysBucket()
	if err != nil {
		return apiKey, err
	}

	entry, err := apiKeysBucket.Get(keyID)
	if err != nil {
		if errors.Is(err, nats.ErrKeyNotFound) {
			return apiKey, util.NewRecordNotFoundError(fmt.Sprintf("API key %v does not exist", keyID))
		}
		return apiKey, err
	}

	err = json.Unmarshal(entry.Value(), &apiKey)
	return apiKey, err
}

func (n *NATSProvider) addAPIKey(apiKey *APIKey) error {
	if err := apiKey.validate(); err != nil {
		return err
	}

	apiKeysBucket, err := n.getAPIKeysBucket()
	if err != nil {
		return err
	}

	// Check if key already exists
	_, err = apiKeysBucket.Get(apiKey.KeyID)
	if err == nil {
		return fmt.Errorf("API key %v already exists", apiKey.KeyID)
	}
	if !errors.Is(err, nats.ErrKeyNotFound) {
		return err
	}

	now := util.GetTimeAsMsSinceEpoch(time.Now())
	apiKey.CreatedAt = now
	apiKey.UpdatedAt = now
	apiKey.LastUseAt = 0

	if apiKey.User != "" {
		if err := n.userExists(apiKey.User); err != nil {
			return fmt.Errorf("%w: related user %q does not exists", ErrForeignKeyViolated, apiKey.User)
		}
	}

	if apiKey.Admin != "" {
		if err := n.adminExists(apiKey.Admin); err != nil {
			return fmt.Errorf("%w: related admin %q does not exists", ErrForeignKeyViolated, apiKey.Admin)
		}
	}

	buf, err := json.Marshal(apiKey)
	if err != nil {
		return err
	}

	_, err = apiKeysBucket.Create(apiKey.KeyID, buf)
	return err
}

//////////////////////////////////

func (n *NATSProvider) updateAPIKey(apiKey *APIKey) error {
	err := apiKey.validate()
	if err != nil {
		return err
	}
	return n.dbHandle.Update(func(tx *bolt.Tx) error {
		bucket, err := n.getAPIKeysBucket()
		if err != nil {
			return err
		}
		var a []byte

		if a = bucket.Get([]byte(apiKey.KeyID)); a == nil {
			return util.NewRecordNotFoundError(fmt.Sprintf("API key %v does not exist", apiKey.KeyID))
		}
		var oldAPIKey APIKey
		err = json.Unmarshal(a, &oldAPIKey)
		if err != nil {
			return err
		}

		apiKey.ID = oldAPIKey.ID
		apiKey.KeyID = oldAPIKey.KeyID
		apiKey.Key = oldAPIKey.Key
		apiKey.CreatedAt = oldAPIKey.CreatedAt
		apiKey.LastUseAt = oldAPIKey.LastUseAt
		apiKey.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
		if apiKey.User != "" {
			if err := n.userExistsInternal(tx, apiKey.User); err != nil {
				return fmt.Errorf("%w: related user %q does not exists", ErrForeignKeyViolated, apiKey.User)
			}
		}
		if apiKey.Admin != "" {
			if err := n.adminExistsInternal(tx, apiKey.Admin); err != nil {
				return fmt.Errorf("%w: related admin %q does not exists", ErrForeignKeyViolated, apiKey.Admin)
			}
		}
		buf, err := json.Marshal(apiKey)
		if err != nil {
			return err
		}
		return kv.Put([]byte(apiKey.KeyID), buf)
	})
}

func (n *NATSProvider) deleteAPIKey(apiKey APIKey) error {
	return n.dbHandle.Update(func(tx *bolt.Tx) error {
		bucket, err := n.getAPIKeysBucket()
		if err != nil {
			return err
		}

		if bucket.Get([]byte(apiKey.KeyID)) == nil {
			return util.NewRecordNotFoundError(fmt.Sprintf("API key %v does not exist", apiKey.KeyID))
		}

		return bucket.Delete([]byte(apiKey.KeyID))
	})
}

func (n *NATSProvider) getAPIKeys(limit int, offset int, order string) ([]APIKey, error) {
	apiKeys := make([]APIKey, 0, limit)

	err := n.dbHandle.View(func(tx *bolt.Tx) error {
		bucket, err := n.getAPIKeysBucket()
		if err != nil {
			return err
		}
		cursor := bucket.Cursor()
		itNum := 0
		if order == OrderASC {
			for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
				itNum++
				if itNum <= offset {
					continue
				}
				var apiKey APIKey
				err = json.Unmarshal(v, &apiKey)
				if err != nil {
					return err
				}
				apiKey.HideConfidentialData()
				apiKeys = append(apiKeys, apiKey)
				if len(apiKeys) >= limit {
					break
				}
			}
			return nil
		}
		for k, v := cursor.Last(); k != nil; k, v = cursor.Prev() {
			itNum++
			if itNum <= offset {
				continue
			}
			var apiKey APIKey
			err = json.Unmarshal(v, &apiKey)
			if err != nil {
				return err
			}
			apiKey.HideConfidentialData()
			apiKeys = append(apiKeys, apiKey)
			if len(apiKeys) >= limit {
				break
			}
		}
		return nil
	})

	return apiKeys, err
}

func (n *NATSProvider) dumpAPIKeys() ([]APIKey, error) {
	apiKeys := make([]APIKey, 0, 30)
	err := n.dbHandle.View(func(tx *bolt.Tx) error {
		bucket, err := n.getAPIKeysBucket()
		if err != nil {
			return err
		}

		cursor := bucket.Cursor()
		for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
			var apiKey APIKey
			err = json.Unmarshal(v, &apiKey)
			if err != nil {
				return err
			}
			apiKeys = append(apiKeys, apiKey)
		}
		return err
	})

	return apiKeys, err
}

func (n *NATSProvider) shareExists(shareID, username string) (Share, error) {
	var share Share
	err := n.dbHandle.View(func(tx *bolt.Tx) error {
		bucket, err := n.getSharesBucket()
		if err != nil {
			return err
		}

		s := bucket.Get([]byte(shareID))
		if s == nil {
			return util.NewRecordNotFoundError(fmt.Sprintf("Share %v does not exist", shareID))
		}
		if err := json.Unmarshal(s, &share); err != nil {
			return err
		}
		if username != "" && share.Username != username {
			return util.NewRecordNotFoundError(fmt.Sprintf("Share %v does not exist", shareID))
		}
		return nil
	})
	return share, err
}

func (n *NATSProvider) addShare(share *Share) error {
	err := share.validate()
	if err != nil {
		return err
	}
	return n.dbHandle.Update(func(tx *bolt.Tx) error {
		bucket, err := n.getSharesBucket()
		if err != nil {
			return err
		}
		if a := bucket.Get([]byte(share.ShareID)); a != nil {
			return fmt.Errorf("share %q already exists", share.ShareID)
		}
		id, err := bucket.NextSequence()
		if err != nil {
			return err
		}
		share.ID = int64(id)
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
		if err := n.userExistsInternal(tx, share.Username); err != nil {
			return util.NewValidationError(fmt.Sprintf("related user %q does not exists", share.Username))
		}
		buf, err := json.Marshal(share)
		if err != nil {
			return err
		}
		return kv.Put([]byte(share.ShareID), buf)
	})
}

func (n *NATSProvider) updateShare(share *Share) error {
	if err := share.validate(); err != nil {
		return err
	}

	return n.dbHandle.Update(func(tx *bolt.Tx) error {
		bucket, err := n.getSharesBucket()
		if err != nil {
			return err
		}
		var s []byte

		if s = bucket.Get([]byte(share.ShareID)); s == nil {
			return util.NewRecordNotFoundError(fmt.Sprintf("Share %v does not exist", share.ShareID))
		}
		var oldObject Share
		if err = json.Unmarshal(s, &oldObject); err != nil {
			return err
		}
		if oldObject.Username != share.Username {
			return util.NewRecordNotFoundError(fmt.Sprintf("Share %v does not exist", share.ShareID))
		}

		share.ID = oldObject.ID
		share.ShareID = oldObject.ShareID
		if !share.IsRestore {
			share.UsedTokens = oldObject.UsedTokens
			share.CreatedAt = oldObject.CreatedAt
			share.LastUseAt = oldObject.LastUseAt
			share.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
		}
		if share.CreatedAt == 0 {
			share.CreatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
		}
		if share.UpdatedAt == 0 {
			share.UpdatedAt = share.CreatedAt
		}
		if err := n.userExistsInternal(tx, share.Username); err != nil {
			return util.NewValidationError(fmt.Sprintf("related user %q does not exists", share.Username))
		}
		buf, err := json.Marshal(share)
		if err != nil {
			return err
		}
		return kv.Put([]byte(share.ShareID), buf)
	})
}

func (n *NATSProvider) deleteShare(share Share) error {
	return n.dbHandle.Update(func(tx *bolt.Tx) error {
		bucket, err := n.getSharesBucket()
		if err != nil {
			return err
		}

		var s []byte

		if s = bucket.Get([]byte(share.ShareID)); s == nil {
			return util.NewRecordNotFoundError(fmt.Sprintf("Share %v does not exist", share.ShareID))
		}
		var oldObject Share
		if err = json.Unmarshal(s, &oldObject); err != nil {
			return err
		}
		if oldObject.Username != share.Username {
			return util.NewRecordNotFoundError(fmt.Sprintf("Share %v does not exist", share.ShareID))
		}

		return bucket.Delete([]byte(share.ShareID))
	})
}

func (n *NATSProvider) getShares(limit int, offset int, order, username string) ([]Share, error) {
	shares := make([]Share, 0, limit)

	err := n.dbHandle.View(func(tx *bolt.Tx) error {
		bucket, err := n.getSharesBucket()
		if err != nil {
			return err
		}
		cursor := bucket.Cursor()
		itNum := 0
		if order == OrderASC {
			for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
				var share Share
				if err := json.Unmarshal(v, &share); err != nil {
					return err
				}
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
			return nil
		}
		for k, v := cursor.Last(); k != nil; k, v = cursor.Prev() {
			var share Share
			err = json.Unmarshal(v, &share)
			if err != nil {
				return err
			}
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
		return nil
	})

	return shares, err
}

func (n *NATSProvider) dumpShares() ([]Share, error) {
	shares := make([]Share, 0, 30)
	err := n.dbHandle.View(func(tx *bolt.Tx) error {
		bucket, err := n.getSharesBucket()
		if err != nil {
			return err
		}

		cursor := bucket.Cursor()
		for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
			var share Share
			err = json.Unmarshal(v, &share)
			if err != nil {
				return err
			}
			shares = append(shares, share)
		}
		return err
	})

	return shares, err
}

func (n *NATSProvider) updateShareLastUse(shareID string, numTokens int) error {
	return n.dbHandle.Update(func(tx *bolt.Tx) error {
		bucket, err := n.getSharesBucket()
		if err != nil {
			return err
		}
		var u []byte
		if u = bucket.Get([]byte(shareID)); u == nil {
			return util.NewRecordNotFoundError(fmt.Sprintf("share %q does not exist, unable to update last use", shareID))
		}
		var share Share
		err = json.Unmarshal(u, &share)
		if err != nil {
			return err
		}
		share.LastUseAt = util.GetTimeAsMsSinceEpoch(time.Now())
		share.UsedTokens += numTokens
		buf, err := json.Marshal(share)
		if err != nil {
			return err
		}
		err = kv.Put([]byte(shareID), buf)
		if err != nil {
			providerLog(logger.LevelWarn, "error updating last use for share %q: %v", shareID, err)
			return err
		}
		providerLog(logger.LevelDebug, "last use updated for share %q", shareID)
		return nil
	})
}

func (n *NATSProvider) getEventActions(limit, offset int, order string, _ bool) ([]BaseEventAction, error) {
	if limit <= 0 {
		return nil, nil
	}
	actions := make([]BaseEventAction, 0, limit)
	err := n.dbHandle.View(func(tx *bolt.Tx) error {
		bucket, err := n.getActionsBucket()
		if err != nil {
			return err
		}
		itNum := 0
		cursor := bucket.Cursor()
		if order == OrderASC {
			for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
				itNum++
				if itNum <= offset {
					continue
				}
				var action BaseEventAction
				err = json.Unmarshal(v, &action)
				if err != nil {
					return err
				}
				action.PrepareForRendering()
				actions = append(actions, action)
				if len(actions) >= limit {
					break
				}
			}
		} else {
			for k, v := cursor.Last(); k != nil; k, v = cursor.Prev() {
				itNum++
				if itNum <= offset {
					continue
				}
				var action BaseEventAction
				err = json.Unmarshal(v, &action)
				if err != nil {
					return err
				}
				action.PrepareForRendering()
				actions = append(actions, action)
				if len(actions) >= limit {
					break
				}
			}
		}
		return nil
	})
	return actions, err
}

func (n *NATSProvider) dumpEventActions() ([]BaseEventAction, error) {
	actions := make([]BaseEventAction, 0, 50)
	err := n.dbHandle.View(func(tx *bolt.Tx) error {
		bucket, err := n.getActionsBucket()
		if err != nil {
			return err
		}
		cursor := bucket.Cursor()
		for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
			var action BaseEventAction
			err = json.Unmarshal(v, &action)
			if err != nil {
				return err
			}
			actions = append(actions, action)
		}
		return nil
	})
	return actions, err
}

func (n *NATSProvider) eventActionExists(name string) (BaseEventAction, error) {
	var action BaseEventAction
	err := n.dbHandle.View(func(tx *bolt.Tx) error {
		bucket, err := n.getActionsBucket()
		if err != nil {
			return err
		}
		k := bucket.Get([]byte(name))
		if k == nil {
			return util.NewRecordNotFoundError(fmt.Sprintf("action %q does not exist", name))
		}
		return json.Unmarshal(k, &action)
	})
	return action, err
}

func (n *NATSProvider) addEventAction(action *BaseEventAction) error {
	err := action.validate()
	if err != nil {
		return err
	}
	return n.dbHandle.Update(func(tx *bolt.Tx) error {
		bucket, err := n.getActionsBucket()
		if err != nil {
			return err
		}
		if a := bucket.Get([]byte(action.Name)); a != nil {
			return util.NewI18nError(
				fmt.Errorf("%w: event action %q already exists", ErrDuplicatedKey, action.Name),
				util.I18nErrorDuplicatedName,
			)
		}
		id, err := bucket.NextSequence()
		if err != nil {
			return err
		}
		action.ID = int64(id)
		action.Rules = nil
		buf, err := json.Marshal(action)
		if err != nil {
			return err
		}
		return kv.Put([]byte(action.Name), buf)
	})
}

func (n *NATSProvider) updateEventAction(action *BaseEventAction) error {
	err := action.validate()
	if err != nil {
		return err
	}
	return n.dbHandle.Update(func(tx *bolt.Tx) error {
		bucket, err := n.getActionsBucket()
		if err != nil {
			return err
		}
		var a []byte

		if a = bucket.Get([]byte(action.Name)); a == nil {
			return util.NewRecordNotFoundError(fmt.Sprintf("event action %s does not exist", action.Name))
		}
		var oldAction BaseEventAction
		err = json.Unmarshal(a, &oldAction)
		if err != nil {
			return err
		}
		action.ID = oldAction.ID
		action.Name = oldAction.Name
		action.Rules = nil
		if len(oldAction.Rules) > 0 {
			rulesBucket, err := n.getRulesBucket()
			if err != nil {
				return err
			}
			var relatedRules []string
			for _, ruleName := range oldAction.Rules {
				r := rulesBucket.Get([]byte(ruleName))
				if r != nil {
					relatedRules = append(relatedRules, ruleName)
					var rule EventRule
					err := json.Unmarshal(r, &rule)
					if err != nil {
						return err
					}
					rule.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
					buf, err := json.Marshal(rule)
					if err != nil {
						return err
					}
					if err = rulesBucket.Put([]byte(rule.Name), buf); err != nil {
						return err
					}
					setLastRuleUpdate()
				}
			}
			action.Rules = relatedRules
		}
		buf, err := json.Marshal(action)
		if err != nil {
			return err
		}
		return kv.Put([]byte(action.Name), buf)
	})
}

func (n *NATSProvider) deleteEventAction(action BaseEventAction) error {
	return n.dbHandle.Update(func(tx *bolt.Tx) error {
		bucket, err := n.getActionsBucket()
		if err != nil {
			return err
		}
		var a []byte

		if a = bucket.Get([]byte(action.Name)); a == nil {
			return util.NewRecordNotFoundError(fmt.Sprintf("action %s does not exist", action.Name))
		}
		var oldAction BaseEventAction
		err = json.Unmarshal(a, &oldAction)
		if err != nil {
			return err
		}
		if len(oldAction.Rules) > 0 {
			return util.NewValidationError(fmt.Sprintf("action %s is referenced, it cannot be removed", oldAction.Name))
		}
		return bucket.Delete([]byte(action.Name))
	})
}

func (n *NATSProvider) getEventRules(limit, offset int, order string) ([]EventRule, error) {
	if limit <= 0 {
		return nil, nil
	}
	rules := make([]EventRule, 0, limit)
	err := n.dbHandle.View(func(tx *bolt.Tx) error {
		bucket, err := n.getRulesBucket()
		if err != nil {
			return err
		}
		actionsBucket, err := n.getActionsBucket()
		if err != nil {
			return err
		}
		itNum := 0
		cursor := bucket.Cursor()
		if order == OrderASC {
			for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
				itNum++
				if itNum <= offset {
					continue
				}
				var rule EventRule
				rule, err = n.joinRuleAndActions(v, actionsBucket)
				if err != nil {
					return err
				}
				rule.PrepareForRendering()
				rules = append(rules, rule)
				if len(rules) >= limit {
					break
				}
			}
		} else {
			for k, v := cursor.Last(); k != nil; k, v = cursor.Prev() {
				itNum++
				if itNum <= offset {
					continue
				}
				var rule EventRule
				rule, err = n.joinRuleAndActions(v, actionsBucket)
				if err != nil {
					return err
				}
				rule.PrepareForRendering()
				rules = append(rules, rule)
				if len(rules) >= limit {
					break
				}
			}
		}
		return err
	})
	return rules, err
}

func (n *NATSProvider) dumpEventRules() ([]EventRule, error) {
	rules := make([]EventRule, 0, 50)
	err := n.dbHandle.View(func(tx *bolt.Tx) error {
		bucket, err := n.getRulesBucket()
		if err != nil {
			return err
		}
		actionsBucket, err := n.getActionsBucket()
		if err != nil {
			return err
		}
		cursor := bucket.Cursor()
		for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
			rule, err := n.joinRuleAndActions(v, actionsBucket)
			if err != nil {
				return err
			}
			rules = append(rules, rule)
		}
		return nil
	})
	return rules, err
}

func (n *NATSProvider) getRecentlyUpdatedRules(after int64) ([]EventRule, error) {
	if getLastRuleUpdate() < after {
		return nil, nil
	}
	rules := make([]EventRule, 0, 10)
	err := n.dbHandle.View(func(tx *bolt.Tx) error {
		bucket, err := n.getRulesBucket()
		if err != nil {
			return err
		}
		actionsBucket, err := n.getActionsBucket()
		if err != nil {
			return err
		}
		cursor := bucket.Cursor()
		for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
			var rule EventRule
			err := json.Unmarshal(v, &rule)
			if err != nil {
				return err
			}
			if rule.UpdatedAt < after {
				continue
			}
			var actions []EventAction
			for idx := range rule.Actions {
				action := &rule.Actions[idx]
				var baseAction BaseEventAction
				k := actionsBucket.Get([]byte(action.Name))
				if k == nil {
					continue
				}
				err = json.Unmarshal(k, &baseAction)
				if err != nil {
					continue
				}
				baseAction.Options.SetEmptySecretsIfNil()
				action.BaseEventAction = baseAction
				actions = append(actions, *action)
			}
			rule.Actions = actions
			rules = append(rules, rule)
		}
		return nil
	})
	return rules, err
}

func (n *NATSProvider) eventRuleExists(name string) (EventRule, error) {
	var rule EventRule
	err := n.dbHandle.View(func(tx *bolt.Tx) error {
		bucket, err := n.getRulesBucket()
		if err != nil {
			return err
		}
		r := bucket.Get([]byte(name))
		if r == nil {
			return util.NewRecordNotFoundError(fmt.Sprintf("event rule %q does not exist", name))
		}
		actionsBucket, err := n.getActionsBucket()
		if err != nil {
			return err
		}
		rule, err = n.joinRuleAndActions(r, actionsBucket)
		return err
	})
	return rule, err
}

func (n *NATSProvider) addEventRule(rule *EventRule) error {
	if err := rule.validate(); err != nil {
		return err
	}
	return n.dbHandle.Update(func(tx *bolt.Tx) error {
		bucket, err := n.getRulesBucket()
		if err != nil {
			return err
		}
		actionsBucket, err := n.getActionsBucket()
		if err != nil {
			return err
		}
		if r := bucket.Get([]byte(rule.Name)); r != nil {
			return util.NewI18nError(
				fmt.Errorf("%w: event rule %q already exists", ErrDuplicatedKey, rule.Name),
				util.I18nErrorDuplicatedName,
			)
		}
		id, err := bucket.NextSequence()
		if err != nil {
			return err
		}
		rule.ID = int64(id)
		rule.CreatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
		rule.UpdatedAt = rule.CreatedAt
		for idx := range rule.Actions {
			if err = n.addRuleToActionMapping(rule.Name, rule.Actions[idx].Name, actionsBucket); err != nil {
				return err
			}
		}
		sort.Slice(rule.Actions, func(i, j int) bool {
			return rule.Actions[i].Order < rule.Actions[j].Order
		})
		buf, err := json.Marshal(rule)
		if err != nil {
			return err
		}
		err = kv.Put([]byte(rule.Name), buf)
		if err == nil {
			setLastRuleUpdate()
		}
		return err
	})
}

func (n *NATSProvider) updateEventRule(rule *EventRule) error {
	if err := rule.validate(); err != nil {
		return err
	}
	return n.dbHandle.Update(func(tx *bolt.Tx) error {
		bucket, err := n.getRulesBucket()
		if err != nil {
			return err
		}
		actionsBucket, err := n.getActionsBucket()
		if err != nil {
			return err
		}
		var r []byte
		if r = bucket.Get([]byte(rule.Name)); r == nil {
			return util.NewRecordNotFoundError(fmt.Sprintf("event rule %q does not exist", rule.Name))
		}
		var oldRule EventRule
		if err = json.Unmarshal(r, &oldRule); err != nil {
			return err
		}
		for idx := range oldRule.Actions {
			if err = n.removeRuleFromActionMapping(rule.Name, oldRule.Actions[idx].Name, actionsBucket); err != nil {
				return err
			}
		}
		for idx := range rule.Actions {
			if err = n.addRuleToActionMapping(rule.Name, rule.Actions[idx].Name, actionsBucket); err != nil {
				return err
			}
		}
		rule.ID = oldRule.ID
		rule.CreatedAt = oldRule.CreatedAt
		rule.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
		buf, err := json.Marshal(rule)
		if err != nil {
			return err
		}
		sort.Slice(rule.Actions, func(i, j int) bool {
			return rule.Actions[i].Order < rule.Actions[j].Order
		})
		err = kv.Put([]byte(rule.Name), buf)
		if err == nil {
			setLastRuleUpdate()
		}
		return err
	})
}

func (n *NATSProvider) deleteEventRule(rule EventRule, _ bool) error {
	return n.dbHandle.Update(func(tx *bolt.Tx) error {
		bucket, err := n.getRulesBucket()
		if err != nil {
			return err
		}
		var r []byte
		if r = bucket.Get([]byte(rule.Name)); r == nil {
			return util.NewRecordNotFoundError(fmt.Sprintf("event rule %q does not exist", rule.Name))
		}
		var oldRule EventRule
		if err = json.Unmarshal(r, &oldRule); err != nil {
			return err
		}
		if len(oldRule.Actions) > 0 {
			actionsBucket, err := n.getActionsBucket()
			if err != nil {
				return err
			}
			for idx := range oldRule.Actions {
				if err = n.removeRuleFromActionMapping(rule.Name, oldRule.Actions[idx].Name, actionsBucket); err != nil {
					return err
				}
			}
		}
		return bucket.Delete([]byte(rule.Name))
	})
}

func (n *NATSProvider) roleExists(name string) (Role, error) {
	var role Role
	err := n.dbHandle.View(func(tx *bolt.Tx) error {
		bucket, err := n.getRolesBucket()
		if err != nil {
			return err
		}
		r := bucket.Get([]byte(name))
		if r == nil {
			return util.NewRecordNotFoundError(fmt.Sprintf("role %q does not exist", name))
		}
		return json.Unmarshal(r, &role)
	})
	return role, err
}

func (n *NATSProvider) addRole(role *Role) error {
	if err := role.validate(); err != nil {
		return err
	}
	return n.dbHandle.Update(func(tx *bolt.Tx) error {
		bucket, err := n.getRolesBucket()
		if err != nil {
			return err
		}
		if r := bucket.Get([]byte(role.Name)); r != nil {
			return util.NewI18nError(
				fmt.Errorf("%w: role %q already exists", ErrDuplicatedKey, role.Name),
				util.I18nErrorDuplicatedName,
			)
		}
		id, err := bucket.NextSequence()
		if err != nil {
			return err
		}
		role.ID = int64(id)
		role.CreatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
		role.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
		role.Users = nil
		role.Admins = nil
		buf, err := json.Marshal(role)
		if err != nil {
			return err
		}
		return kv.Put([]byte(role.Name), buf)
	})
}

func (n *NATSProvider) updateRole(role *Role) error {
	if err := role.validate(); err != nil {
		return err
	}
	return n.dbHandle.Update(func(tx *bolt.Tx) error {
		bucket, err := n.getRolesBucket()
		if err != nil {
			return err
		}
		var r []byte
		if r = bucket.Get([]byte(role.Name)); r == nil {
			return fmt.Errorf("role %q does not exist", role.Name)
		}
		var oldRole Role
		err = json.Unmarshal(r, &oldRole)
		if err != nil {
			return err
		}
		role.ID = oldRole.ID
		role.CreatedAt = oldRole.CreatedAt
		role.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
		role.Users = oldRole.Users
		role.Admins = oldRole.Admins
		buf, err := json.Marshal(role)
		if err != nil {
			return err
		}
		return kv.Put([]byte(role.Name), buf)
	})
}

func (n *NATSProvider) deleteRole(role Role) error {
	return n.dbHandle.Update(func(tx *bolt.Tx) error {
		bucket, err := n.getRolesBucket()
		if err != nil {
			return err
		}
		var r []byte
		if r = bucket.Get([]byte(role.Name)); r == nil {
			return fmt.Errorf("role %q does not exist", role.Name)
		}
		var oldRole Role
		err = json.Unmarshal(r, &oldRole)
		if err != nil {
			return err
		}
		if len(oldRole.Admins) > 0 {
			return util.NewValidationError(fmt.Sprintf("the role %q is referenced, it cannot be removed", oldRole.Name))
		}
		if len(oldRole.Users) > 0 {
			bucket, err := n.getUsersBucket()
			if err != nil {
				return err
			}
			for _, username := range oldRole.Users {
				if err := n.removeRoleFromUser(username, oldRole.Name, bucket); err != nil {
					return err
				}
			}
		}

		return bucket.Delete([]byte(role.Name))
	})
}

func (n *NATSProvider) getRoles(limit int, offset int, order string, _ bool) ([]Role, error) {
	roles := make([]Role, 0, limit)
	if limit <= 0 {
		return roles, nil
	}
	err := n.dbHandle.View(func(tx *bolt.Tx) error {
		bucket, err := n.getRolesBucket()
		if err != nil {
			return err
		}
		cursor := bucket.Cursor()
		itNum := 0
		if order == OrderASC {
			for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
				itNum++
				if itNum <= offset {
					continue
				}
				var role Role
				err = json.Unmarshal(v, &role)
				if err != nil {
					return err
				}
				roles = append(roles, role)
				if len(roles) >= limit {
					break
				}
			}
		} else {
			for k, v := cursor.Last(); k != nil; k, v = cursor.Prev() {
				itNum++
				if itNum <= offset {
					continue
				}
				var role Role
				err = json.Unmarshal(v, &role)
				if err != nil {
					return err
				}
				roles = append(roles, role)
				if len(roles) >= limit {
					break
				}
			}
		}
		return nil
	})
	return roles, err
}

func (n *NATSProvider) dumpRoles() ([]Role, error) {
	roles := make([]Role, 0, 10)
	err := n.dbHandle.View(func(tx *bolt.Tx) error {
		bucket, err := n.getRolesBucket()
		if err != nil {
			return err
		}
		cursor := bucket.Cursor()
		for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
			var role Role
			err = json.Unmarshal(v, &role)
			if err != nil {
				return err
			}
			roles = append(roles, role)
		}
		return err
	})
	return roles, err
}

func (n *NATSProvider) ipListEntryExists(ipOrNet string, listType IPListType) (IPListEntry, error) {
	entry := IPListEntry{
		IPOrNet: ipOrNet,
		Type:    listType,
	}
	err := n.dbHandle.View(func(tx *bolt.Tx) error {
		bucket, err := n.getIPListsBucket()
		if err != nil {
			return err
		}
		e := bucket.Get([]byte(entry.getKey()))
		if e == nil {
			return util.NewRecordNotFoundError(fmt.Sprintf("entry %q does not exist", entry.IPOrNet))
		}
		err = json.Unmarshal(e, &entry)
		if err == nil {
			entry.PrepareForRendering()
		}
		return err
	})
	return entry, err
}

func (n *NATSProvider) addIPListEntry(entry *IPListEntry) error {
	if err := entry.validate(); err != nil {
		return err
	}
	return n.dbHandle.Update(func(tx *bolt.Tx) error {
		bucket, err := n.getIPListsBucket()
		if err != nil {
			return err
		}
		if e := bucket.Get([]byte(entry.getKey())); e != nil {
			return util.NewI18nError(
				fmt.Errorf("%w: entry %q already exists", ErrDuplicatedKey, entry.IPOrNet),
				util.I18nErrorDuplicatedIPNet,
			)
		}
		entry.CreatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
		entry.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
		buf, err := json.Marshal(entry)
		if err != nil {
			return err
		}
		return kv.Put([]byte(entry.getKey()), buf)
	})
}

func (n *NATSProvider) updateIPListEntry(entry *IPListEntry) error {
	if err := entry.validate(); err != nil {
		return err
	}
	return n.dbHandle.Update(func(tx *bolt.Tx) error {
		bucket, err := n.getIPListsBucket()
		if err != nil {
			return err
		}
		var e []byte
		if e = bucket.Get([]byte(entry.getKey())); e == nil {
			return fmt.Errorf("entry %q does not exist", entry.IPOrNet)
		}
		var oldEntry IPListEntry
		err = json.Unmarshal(e, &oldEntry)
		if err != nil {
			return err
		}
		entry.CreatedAt = oldEntry.CreatedAt
		entry.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
		buf, err := json.Marshal(entry)
		if err != nil {
			return err
		}
		return kv.Put([]byte(entry.getKey()), buf)
	})
}

func (n *NATSProvider) deleteIPListEntry(entry IPListEntry, _ bool) error {
	return n.dbHandle.Update(func(tx *bolt.Tx) error {
		bucket, err := n.getIPListsBucket()
		if err != nil {
			return err
		}
		if e := bucket.Get([]byte(entry.getKey())); e == nil {
			return fmt.Errorf("entry %q does not exist", entry.IPOrNet)
		}
		return bucket.Delete([]byte(entry.getKey()))
	})
}

func (n *NATSProvider) getIPListEntries(listType IPListType, filter, from, order string, limit int) ([]IPListEntry, error) {
	entries := make([]IPListEntry, 0, 15)
	err := n.dbHandle.View(func(tx *bolt.Tx) error {
		bucket, err := n.getIPListsBucket()
		if err != nil {
			return err
		}
		prefix := []byte(fmt.Sprintf("%d_", listType))
		acceptKey := func(k []byte) bool {
			return k != nil && bytes.HasPrefix(k, prefix)
		}
		cursor := bucket.Cursor()
		if order == OrderASC {
			for k, v := cursor.Seek(prefix); acceptKey(k); k, v = cursor.Next() {
				var entry IPListEntry
				err = json.Unmarshal(v, &entry)
				if err != nil {
					return err
				}
				if entry.satisfySearchConstraints(filter, from, order) {
					entry.PrepareForRendering()
					entries = append(entries, entry)
					if limit > 0 && len(entries) >= limit {
						break
					}
				}
			}
		} else {
			for k, v := cursor.Last(); acceptKey(k); k, v = cursor.Prev() {
				var entry IPListEntry
				err = json.Unmarshal(v, &entry)
				if err != nil {
					return err
				}
				if entry.satisfySearchConstraints(filter, from, order) {
					entry.PrepareForRendering()
					entries = append(entries, entry)
					if limit > 0 && len(entries) >= limit {
						break
					}
				}
			}
		}
		return nil
	})
	return entries, err
}

func (n *NATSProvider) dumpIPListEntries() ([]IPListEntry, error) {
	entries := make([]IPListEntry, 0, 10)
	err := n.dbHandle.View(func(tx *bolt.Tx) error {
		bucket, err := n.getIPListsBucket()
		if err != nil {
			return err
		}
		if count := bucket.Stats().KeyN; count > ipListMemoryLimit {
			providerLog(logger.LevelInfo, "IP lists excluded from dump, too many entries: %d", count)
			return nil
		}
		cursor := bucket.Cursor()
		for k, v := cursor.First(); k != nil; k, v = cursor.Next() {
			var entry IPListEntry
			err = json.Unmarshal(v, &entry)
			if err != nil {
				return err
			}
			entry.PrepareForRendering()
			entries = append(entries, entry)
		}
		return nil
	})
	return entries, err
}

func (n *NATSProvider) countIPListEntries(listType IPListType) (int64, error) {
	var count int64
	err := n.dbHandle.View(func(tx *bolt.Tx) error {
		bucket, err := n.getIPListsBucket()
		if err != nil {
			return err
		}
		if listType == 0 {
			count = int64(bucket.Stats().KeyN)
			return nil
		}
		prefix := []byte(fmt.Sprintf("%d_", listType))
		cursor := bucket.Cursor()
		for k, _ := cursor.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, _ = cursor.Next() {
			count++
		}
		return nil
	})
	return count, err
}

func (n *NATSProvider) getListEntriesForIP(ip string, listType IPListType) ([]IPListEntry, error) {
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
	err = n.dbHandle.View(func(tx *bolt.Tx) error {
		bucket, err := n.getIPListsBucket()
		if err != nil {
			return err
		}
		prefix := []byte(fmt.Sprintf("%d_", listType))
		cursor := bucket.Cursor()
		for k, v := cursor.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, v = cursor.Next() {
			var entry IPListEntry
			err = json.Unmarshal(v, &entry)
			if err != nil {
				return err
			}
			if entry.IPType == netType && bytes.Compare(ipBytes, entry.First) >= 0 && bytes.Compare(ipBytes, entry.Last) <= 0 {
				entry.PrepareForRendering()
				entries = append(entries, entry)
			}
		}
		return nil
	})
	return entries, err
}

func (n *NATSProvider) getConfigs() (Configs, error) {
	var configs Configs
	err := n.dbHandle.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(configsBucket)
		if bucket == nil {
			return fmt.Errorf("unable to find configs bucket")
		}
		data := bucket.Get(configsKey)
		if data != nil {
			return json.Unmarshal(data, &configs)
		}
		return nil
	})
	return configs, err
}

func (n *NATSProvider) setConfigs(configs *Configs) error {
	if err := configs.validate(); err != nil {
		return err
	}
	return n.dbHandle.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(configsBucket)
		if bucket == nil {
			return fmt.Errorf("unable to find configs bucket")
		}
		buf, err := json.Marshal(configs)
		if err != nil {
			return err
		}
		return kv.Put(configsKey, buf)
	})
}

func (n *NATSProvider) setFirstDownloadTimestamp(username string) error {
	return n.dbHandle.Update(func(tx *bolt.Tx) error {
		bucket, err := n.getUsersBucket()
		if err != nil {
			return err
		}
		var u []byte
		if u = bucket.Get([]byte(username)); u == nil {
			return util.NewRecordNotFoundError(fmt.Sprintf("username %q does not exist, unable to set download timestamp",
				username))
		}
		var user User
		err = json.Unmarshal(u, &user)
		if err != nil {
			return err
		}
		if user.FirstDownload > 0 {
			return util.NewGenericError(fmt.Sprintf("first download already set to %v",
				util.GetTimeFromMsecSinceEpoch(user.FirstDownload)))
		}
		user.FirstDownload = util.GetTimeAsMsSinceEpoch(time.Now())
		buf, err := json.Marshal(user)
		if err != nil {
			return err
		}
		return kv.Put([]byte(username), buf)
	})
}

func (n *NATSProvider) setFirstUploadTimestamp(username string) error {
	return n.dbHandle.Update(func(tx *bolt.Tx) error {
		bucket, err := n.getUsersBucket()
		if err != nil {
			return err
		}
		var u []byte
		if u = bucket.Get([]byte(username)); u == nil {
			return util.NewRecordNotFoundError(fmt.Sprintf("username %q does not exist, unable to set upload timestamp",
				username))
		}
		var user User
		if err = json.Unmarshal(u, &user); err != nil {
			return err
		}
		if user.FirstUpload > 0 {
			return util.NewGenericError(fmt.Sprintf("first upload already set to %v",
				util.GetTimeFromMsecSinceEpoch(user.FirstUpload)))
		}
		user.FirstUpload = util.GetTimeAsMsSinceEpoch(time.Now())
		buf, err := json.Marshal(user)
		if err != nil {
			return err
		}
		return kv.Put([]byte(username), buf)
	})
}

func (n *NATSProvider) close() error {
	return n.dbHandle.Close()
}

func (n *NATSProvider) reloadConfig() error {
	return nil
}

func (n *NATSProvider) migrateDatabase() error {
	dbVersion, err := getBoltDatabaseVersion(n.dbHandle)
	if err != nil {
		return err
	}
	switch version := dbVersion.Version; {
	case version == boltDatabaseVersion:
		providerLog(logger.LevelDebug, "bolt database is up to date, current version: %d", version)
		return ErrNoInitRequired
	case version < 29:
		err = errSchemaVersionTooOld(version)
		providerLog(logger.LevelError, "%v", err)
		logger.ErrorToConsole("%v", err)
		return err
	case version == 29, version == 30, version == 31:
		logger.InfoToConsole("updating database schema version: %d -> 32", version)
		providerLog(logger.LevelInfo, "updating database schema version: %d -> 32", version)
		if err := updateEventActions(); err != nil {
			return err
		}
		return updateBoltDatabaseVersion(n.dbHandle, 32)
	default:
		if version > boltDatabaseVersion {
			providerLog(logger.LevelError, "database schema version %d is newer than the supported one: %d", version,
				boltDatabaseVersion)
			logger.WarnToConsole("database schema version %d is newer than the supported one: %d", version,
				boltDatabaseVersion)
			return nil
		}
		return fmt.Errorf("database schema version not handled: %d", version)
	}
}

func (n *NATSProvider) revertDatabase(targetVersion int) error { //nolint:gocyclo
	dbVersion, err := n.getBoltDatabaseVersion()
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
		return updateBoltDatabaseVersion(n.dbHandle, 29)
	default:
		return fmt.Errorf("database schema version not handled: %v", dbVersion.Version)
	}
}
