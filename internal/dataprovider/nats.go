package dataprovider

////go:build nats

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/util"
	"github.com/drakkan/sftpgo/v2/internal/version"
	"github.com/nats-io/nats.go"
	"os"
	"path/filepath"
	"sort"
	"strconv"
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

var bucketsNATS = []string{
	NatsKvAdmin, NatsKvGroup, NatsKvRole, NatsKvRule, NatsKvUser, NatsKvFolder, NatsKvShare, NatsKvApiKey, NatsKvEventAction,
	NatsKvEventRule, NatsKvNode, NatsKvTask, NatsKvTransfer, NatsKvDefender, NatsKvIplist, NatsKvSession, NatsKvConfig,
	NatsKvActions, NatsKvSchemaVersion, NatsKvBucketVersion, NatsKvDbVersion, usersBucketNATS, groupsBucketNATS, foldersBucketNATS,
	adminsBucketNATS, apiKeysBucketNATS, sharesBucketNATS, actionsBucketNATS, rulesBucketNATS, rolesBucketNATS, ipListsBucketNATS,
	configsBucketNATS, dbVersionBucketNATS, dbVersionKeyNATS, configsKeyNATS}

func init() {
	version.AddFeature("+nats")
}

type NATSProvider struct {
	jsHandle nats.JetStreamContext
	conn     *nats.Conn
	buckets  map[string]nats.KeyValue
}

type Bucket struct {
	Name        string
	Description string
}

func initializeNATSProvider() error {
	var err error

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

	value := make(map[string]nats.KeyValue)

	bucket := Bucket{
		Name:        NatsKvAdmin,
		Description: "key store for Admin data",
	}

	if err := initBucket(js, bucket, value); err != nil {
		return fmt.Errorf("failed to create KV bucket: %w", err)
	}

	bucket = Bucket{
		Name:        NatsKvRole,
		Description: "key store for Admin role data",
	}

	if err := initBucket(js, bucket, value); err != nil {
		return fmt.Errorf("failed to create KV bucket: %w", err)
	}

	providerLog(logger.LevelDebug, "nats key store handle created")

	provider = &NATSProvider{
		jsHandle: js,
		conn:     nc,
		buckets:  value,
	}
	return err
}

func initBucket(js nats.JetStreamContext, bucket Bucket, value map[string]nats.KeyValue) error {
	kv, err := js.CreateKeyValue(&nats.KeyValueConfig{
		Bucket:      bucket.Name,
		Description: bucket.Description,
		Storage:     nats.FileStorage,
		Compression: true,
	})
	if err != nil {
		return err
	}

	value[kv.Bucket()] = kv
	return nil
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

func (n *NATSProvider) checkAvailability() error {
	entry, err := n.buckets[NatsKvDbVersion].Get(dbVersionKeyNATS)
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
	var admin Admin
	entry, err := n.buckets[NatsKvAdmin].Get(username)
	if err != nil {
		return "", err
	}

	if err := admin.Unmarshal(entry.Value()); err != nil {
		return "", err
	}
	return strconv.FormatInt(admin.UpdatedAt, 10), nil
}

func (n *NATSProvider) getUserSignature(username string) (string, error) {
	var user User
	entry, err := n.buckets[NatsKvUser].Get(username)
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

func (n *NATSProvider) adminExists(username string) (Admin, error) {
	var admin Admin

	entry, err := n.buckets[NatsKvAdmin].Get(username)
	if err != nil {
		if errors.Is(err, nats.ErrKeyNotFound) {
			return admin, util.NewRecordNotFoundError(fmt.Sprintf("admin %v does not exist", username))
		}
		return admin, fmt.Errorf("failed to retrieve admin %q from KV store: %w", username, err)
	}

	if err := admin.Unmarshal(entry.Value()); err != nil {
		return admin, fmt.Errorf("failed to unmarshal admin data: %w", err)
	}
	return admin, nil
}

func (n *NATSProvider) addAdmin(admin *Admin) error {
	if err := admin.validate(); err != nil {
		return err
	}

	data, err := admin.Marshal()
	if err != nil {
		return err
	}

	if _, err := n.buckets[NatsKvAdmin].Put(admin.Username, data); err != nil {
		return util.NewI18nError(
			fmt.Errorf("%w: admin %q already exists", ErrDuplicatedKey, admin.Username),
			util.I18nErrorDuplicatedUsername,
		)
	}

	sort.Slice(admin.Groups, func(i, j int) bool {
		return admin.Groups[i].Name < admin.Groups[j].Name
	})

	for _, g := range admin.Groups {
		if err := n.addAdminToGroupMapping(admin.Username, g.Name); err != nil {
			return err
		}
	}

	if err := n.addAdminToRole(admin.Username, admin.Role); err != nil {
		return err
	}

	// Assign ID and metadata
	admin.ID = time.Now().UnixNano() // You may want a better unique ID strategy
	admin.LastLogin = 0
	now := util.GetTimeAsMsSinceEpoch(time.Now())
	admin.CreatedAt = now
	admin.UpdatedAt = now

	data, err = admin.Marshal()
	if err != nil {
		return err
	}

	if _, err = n.buckets[NatsKvAdmin].Put(admin.Username, data); err != nil {
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
	entry, err := n.buckets[NatsKvApiKey].Get(keyID)
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

	if _, err = n.buckets[NatsKvApiKey].Put(keyID, buf); err != nil {
		providerLog(logger.LevelWarn, "error updating last use for key %q: %v", keyID, err)
		return err
	}

	providerLog(logger.LevelDebug, "last use updated for key %q", keyID)
	return nil
}

func (n *NATSProvider) setUpdatedAt(username string) error {
	entry, err := n.buckets[NatsKvUser].Get(username)
	if err != nil {
		if errors.Is(err, nats.ErrKeyNotFound) {
			return util.NewRecordNotFoundError(fmt.Sprintf("username %q does not exist, unable to update updated at", username))
		}
		return fmt.Errorf("failed to fetch user %q: %w", username, err)
	}

	var user User
	if err := user.Unmarshal(entry.Value()); err != nil {
		return fmt.Errorf("failed to unmarshal user %q: %w", username, err)
	}

	user.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
	data, err := user.Marshal()
	if err != nil {
		return fmt.Errorf("failed to marshal updated user %q: %w", username, err)
	}

	if _, err := n.buckets[NatsKvUser].Put(username, data); err != nil {
		providerLog(logger.LevelWarn, "error setting updated_at for user %q: %v", username, err)
		return fmt.Errorf("failed to update user %q: %w", username, err)
	}

	providerLog(logger.LevelDebug, "updated at set for user %q", username)
	setLastUserUpdate()
	return nil
}
