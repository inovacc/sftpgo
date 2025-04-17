package dataprovider

////go:build nats

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/drakkan/sftpgo/v2/internal/dataprovider/bucket"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/util"
	"github.com/drakkan/sftpgo/v2/internal/version"
	"github.com/drakkan/sftpgo/v2/internal/vfs"
	"github.com/nats-io/nats.go"
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

	storageNames := []string{
		usersBucketNATS, groupsBucketNATS, foldersBucketNATS, adminsBucketNATS, apiKeysBucketNATS, sharesBucketNATS,
		actionsBucketNATS, rulesBucketNATS, rolesBucketNATS, ipListsBucketNATS, configsBucketNATS, dbVersionBucketNATS,
		dbVersionKeyNATS,
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

	foldersKv, ok := natsBuckets[foldersBucketNATS]
	if ok {
		folderEntry, err := foldersKv.Get(username)
		if err != nil && !errors.Is(err, nats.ErrKeyNotFound) {
			return User{}, fmt.Errorf("failed to get folders from kv: %w", err)
		}

		if err := n.joinUserAndFolders(&user, folderEntry.Value()); err != nil {
			return User{}, fmt.Errorf("failed to join user and folders: %w", err)
		}
	}

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
