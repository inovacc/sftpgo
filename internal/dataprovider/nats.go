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

//go:build nats

package dataprovider

import (
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/util"
	"github.com/drakkan/sftpgo/v2/internal/version"
	"github.com/drakkan/sftpgo/v2/internal/vfs"
	"github.com/go-sql-driver/mysql"
	"github.com/nats-io/nats.go"
	"strings"
	"time"
)

func init() {
	version.AddFeature("+nats")
}

const (
	usersBucketNats     = "users"
	groupsBucketNats    = "groups"
	foldersBucketNats   = "folders"
	adminsBucketNats    = "admins"
	apiKeysBucketNats   = "api_keys"
	sharesBucketNats    = "shares"
	actionsBucketNats   = "events_actions"
	rulesBucketNats     = "events_rules"
	rolesBucketNats     = "roles"
	ipListsBucketNats   = "ip_lists"
	configsBucketNats   = "configs"
	dbVersionBucketNats = "db_version"
	dbVersionKeyNats    = "version"
	configsKeyNats      = "configs"
)

var natsBuckets = []string{
	usersBucketNats, groupsBucketNats, foldersBucketNats, adminsBucketNats, apiKeysBucketNats,
	sharesBucketNats, actionsBucketNats, rulesBucketNats, rolesBucketNats, ipListsBucketNats,
	configsBucketNats, dbVersionBucketNats,
}

func ensureBuckets(js nats.JetStreamContext) error {
	for _, bucket := range natsBuckets {
		_, err := js.CreateKeyValue(&nats.KeyValueConfig{
			Bucket:      bucket,
			Storage:     nats.FileStorage,
			Compression: true,
		})
		if err != nil && !errors.Is(err, nats.ErrBadBucket) {
			return fmt.Errorf("failed to create bucket %q: %w", bucket, err)
		}
	}
	return nil
}

type NATSProvider struct {
	js nats.JetStreamContext
}

func initializeNatsProvider() error {
	var err error

	connString, err := getNatsConnectionString(false)
	if err != nil {
		providerLog(logger.LevelError, "error creating nats database handler, connection string: %q, error: %v", connString, err)
		return err
	}

	nc, err := nats.Connect(connString)
	if err != nil {
		providerLog(logger.LevelError, "error creating nats database handler, connection string: %q, error: %v", connString, err)
		return err
	}

	js, err := nc.JetStream()
	if err != nil {
		providerLog(logger.LevelError, "error creating nats database handler, connection string: %q, error: %v", connString, err)
		return err
	}

	providerLog(logger.LevelDebug, "nats key store handle created")

	provider = &NATSProvider{js: js}
	return err
}

func getNatsConnectionString(redactedPwd bool) (string, error) {
	var connectionString string
	if config.ConnectionString == "" {
		password := config.Password
		if redactedPwd && password != "" {
			password = "[redacted]"
		}
		sslMode := getSSLMode()
		if sslMode == "custom" && !redactedPwd {
			if err := registerMySQLCustomTLSConfig(); err != nil {
				return "", err
			}
		}
		connectionString = fmt.Sprintf("%s:%s@tcp([%s]:%d)/%s?collation=utf8mb4_unicode_ci&interpolateParams=true&timeout=10s&parseTime=true&clientFoundRows=true&tls=%s&writeTimeout=60s&readTimeout=60s",
			config.Username, password, config.Host, config.Port, config.Name, sslMode)
	} else {
		connectionString = config.ConnectionString
	}
	return connectionString, nil
}

func (p *NATSProvider) checkAvailability() error {
	return sqlCommonCheckAvailability(p.dbHandle)
}

func (p *NATSProvider) validateUserAndPass(username, password, ip, protocol string) (User, error) {
	return sqlCommonValidateUserAndPass(username, password, ip, protocol, p.dbHandle)
}

func (p *NATSProvider) validateUserAndTLSCert(username, protocol string, tlsCert *x509.Certificate) (User, error) {
	return sqlCommonValidateUserAndTLSCertificate(username, protocol, tlsCert, p.dbHandle)
}

func (p *NATSProvider) validateUserAndPubKey(username string, publicKey []byte, isSSHCert bool) (User, string, error) {
	return sqlCommonValidateUserAndPubKey(username, publicKey, isSSHCert, p.dbHandle)
}

func (p *NATSProvider) updateTransferQuota(username string, uploadSize, downloadSize int64, reset bool) error {
	return sqlCommonUpdateTransferQuota(username, uploadSize, downloadSize, reset, p.dbHandle)
}

func (p *NATSProvider) updateQuota(username string, filesAdd int, sizeAdd int64, reset bool) error {
	return sqlCommonUpdateQuota(username, filesAdd, sizeAdd, reset, p.dbHandle)
}

func (p *NATSProvider) getUsedQuota(username string) (int, int64, int64, int64, error) {
	return sqlCommonGetUsedQuota(username, p.dbHandle)
}

func (p *NATSProvider) getAdminSignature(username string) (string, error) {
	return sqlCommonGetAdminSignature(username, p.dbHandle)
}

func (p *NATSProvider) getUserSignature(username string) (string, error) {
	return sqlCommonGetUserSignature(username, p.dbHandle)
}

func (p *NATSProvider) setUpdatedAt(username string) {
	sqlCommonSetUpdatedAt(username, p.dbHandle)
}

func (p *NATSProvider) updateLastLogin(username string) error {
	return sqlCommonUpdateLastLogin(username, p.dbHandle)
}

func (p *NATSProvider) updateAdminLastLogin(username string) error {
	return sqlCommonUpdateAdminLastLogin(username, p.dbHandle)
}

func (p *NATSProvider) userExists(username, role string) (User, error) {
	return sqlCommonGetUserByUsername(username, role, p.dbHandle)
}

func (p *NATSProvider) addUser(user *User) error {
	return p.normalizeError(sqlCommonAddUser(user, p.dbHandle), fieldUsername)
}

func (p *NATSProvider) updateUser(user *User) error {
	return p.normalizeError(sqlCommonUpdateUser(user, p.dbHandle), -1)
}

func (p *NATSProvider) deleteUser(user User, softDelete bool) error {
	return sqlCommonDeleteUser(user, softDelete, p.dbHandle)
}

func (p *NATSProvider) updateUserPassword(username, password string) error {
	return sqlCommonUpdateUserPassword(username, password, p.dbHandle)
}

func (p *NATSProvider) dumpUsers() ([]User, error) {
	return sqlCommonDumpUsers(p.dbHandle)
}

func (p *NATSProvider) getRecentlyUpdatedUsers(after int64) ([]User, error) {
	return sqlCommonGetRecentlyUpdatedUsers(after, p.dbHandle)
}

func (p *NATSProvider) getUsers(limit int, offset int, order, role string) ([]User, error) {
	return sqlCommonGetUsers(limit, offset, order, role, p.dbHandle)
}

func (p *NATSProvider) getUsersForQuotaCheck(toFetch map[string]bool) ([]User, error) {
	return sqlCommonGetUsersForQuotaCheck(toFetch, p.dbHandle)
}

func (p *NATSProvider) dumpFolders() ([]vfs.BaseVirtualFolder, error) {
	return sqlCommonDumpFolders(p.dbHandle)
}

func (p *NATSProvider) getFolders(limit, offset int, order string, minimal bool) ([]vfs.BaseVirtualFolder, error) {
	return sqlCommonGetFolders(limit, offset, order, minimal, p.dbHandle)
}

func (p *NATSProvider) getFolderByName(name string) (vfs.BaseVirtualFolder, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()
	return sqlCommonGetFolderByName(ctx, name, p.dbHandle)
}

func (p *NATSProvider) addFolder(folder *vfs.BaseVirtualFolder) error {
	return p.normalizeError(sqlCommonAddFolder(folder, p.dbHandle), fieldName)
}

func (p *NATSProvider) updateFolder(folder *vfs.BaseVirtualFolder) error {
	return sqlCommonUpdateFolder(folder, p.dbHandle)
}

func (p *NATSProvider) deleteFolder(folder vfs.BaseVirtualFolder) error {
	return sqlCommonDeleteFolder(folder, p.dbHandle)
}

func (p *NATSProvider) updateFolderQuota(name string, filesAdd int, sizeAdd int64, reset bool) error {
	return sqlCommonUpdateFolderQuota(name, filesAdd, sizeAdd, reset, p.dbHandle)
}

func (p *NATSProvider) getUsedFolderQuota(name string) (int, int64, error) {
	return sqlCommonGetFolderUsedQuota(name, p.dbHandle)
}

func (p *NATSProvider) getGroups(limit, offset int, order string, minimal bool) ([]Group, error) {
	return sqlCommonGetGroups(limit, offset, order, minimal, p.dbHandle)
}

func (p *NATSProvider) getGroupsWithNames(names []string) ([]Group, error) {
	return sqlCommonGetGroupsWithNames(names, p.dbHandle)
}

func (p *NATSProvider) getUsersInGroups(names []string) ([]string, error) {
	return sqlCommonGetUsersInGroups(names, p.dbHandle)
}

func (p *NATSProvider) groupExists(name string) (Group, error) {
	return sqlCommonGetGroupByName(name, p.dbHandle)
}

func (p *NATSProvider) addGroup(group *Group) error {
	return p.normalizeError(sqlCommonAddGroup(group, p.dbHandle), fieldName)
}

func (p *NATSProvider) updateGroup(group *Group) error {
	return sqlCommonUpdateGroup(group, p.dbHandle)
}

func (p *NATSProvider) deleteGroup(group Group) error {
	return sqlCommonDeleteGroup(group, p.dbHandle)
}

func (p *NATSProvider) dumpGroups() ([]Group, error) {
	return sqlCommonDumpGroups(p.dbHandle)
}

func (p *NATSProvider) adminExists(username string) (Admin, error) {
	return sqlCommonGetAdminByUsername(username, p.dbHandle)
}

func (p *NATSProvider) addAdmin(admin *Admin) error {
	return p.normalizeError(sqlCommonAddAdmin(admin, p.dbHandle), fieldUsername)
}

func (p *NATSProvider) updateAdmin(admin *Admin) error {
	return p.normalizeError(sqlCommonUpdateAdmin(admin, p.dbHandle), -1)
}

func (p *NATSProvider) deleteAdmin(admin Admin) error {
	return sqlCommonDeleteAdmin(admin, p.dbHandle)
}

func (p *NATSProvider) getAdmins(limit int, offset int, order string) ([]Admin, error) {
	return sqlCommonGetAdmins(limit, offset, order, p.dbHandle)
}

func (p *NATSProvider) dumpAdmins() ([]Admin, error) {
	return sqlCommonDumpAdmins(p.dbHandle)
}

func (p *NATSProvider) validateAdminAndPass(username, password, ip string) (Admin, error) {
	return sqlCommonValidateAdminAndPass(username, password, ip, p.dbHandle)
}

func (p *NATSProvider) apiKeyExists(keyID string) (APIKey, error) {
	return sqlCommonGetAPIKeyByID(keyID, p.dbHandle)
}

func (p *NATSProvider) addAPIKey(apiKey *APIKey) error {
	return p.normalizeError(sqlCommonAddAPIKey(apiKey, p.dbHandle), -1)
}

func (p *NATSProvider) updateAPIKey(apiKey *APIKey) error {
	return p.normalizeError(sqlCommonUpdateAPIKey(apiKey, p.dbHandle), -1)
}

func (p *NATSProvider) deleteAPIKey(apiKey APIKey) error {
	return sqlCommonDeleteAPIKey(apiKey, p.dbHandle)
}

func (p *NATSProvider) getAPIKeys(limit int, offset int, order string) ([]APIKey, error) {
	return sqlCommonGetAPIKeys(limit, offset, order, p.dbHandle)
}

func (p *NATSProvider) dumpAPIKeys() ([]APIKey, error) {
	return sqlCommonDumpAPIKeys(p.dbHandle)
}

func (p *NATSProvider) updateAPIKeyLastUse(keyID string) error {
	return sqlCommonUpdateAPIKeyLastUse(keyID, p.dbHandle)
}

func (p *NATSProvider) shareExists(shareID, username string) (Share, error) {
	return sqlCommonGetShareByID(shareID, username, p.dbHandle)
}

func (p *NATSProvider) addShare(share *Share) error {
	return p.normalizeError(sqlCommonAddShare(share, p.dbHandle), fieldName)
}

func (p *NATSProvider) updateShare(share *Share) error {
	return p.normalizeError(sqlCommonUpdateShare(share, p.dbHandle), -1)
}

func (p *NATSProvider) deleteShare(share Share) error {
	return sqlCommonDeleteShare(share, p.dbHandle)
}

func (p *NATSProvider) getShares(limit int, offset int, order, username string) ([]Share, error) {
	return sqlCommonGetShares(limit, offset, order, username, p.dbHandle)
}

func (p *NATSProvider) dumpShares() ([]Share, error) {
	return sqlCommonDumpShares(p.dbHandle)
}

func (p *NATSProvider) updateShareLastUse(shareID string, numTokens int) error {
	return sqlCommonUpdateShareLastUse(shareID, numTokens, p.dbHandle)
}

func (p *NATSProvider) getDefenderHosts(from int64, limit int) ([]DefenderEntry, error) {
	return sqlCommonGetDefenderHosts(from, limit, p.dbHandle)
}

func (p *NATSProvider) getDefenderHostByIP(ip string, from int64) (DefenderEntry, error) {
	return sqlCommonGetDefenderHostByIP(ip, from, p.dbHandle)
}

func (p *NATSProvider) isDefenderHostBanned(ip string) (DefenderEntry, error) {
	return sqlCommonIsDefenderHostBanned(ip, p.dbHandle)
}

func (p *NATSProvider) updateDefenderBanTime(ip string, minutes int) error {
	return sqlCommonDefenderIncrementBanTime(ip, minutes, p.dbHandle)
}

func (p *NATSProvider) deleteDefenderHost(ip string) error {
	return sqlCommonDeleteDefenderHost(ip, p.dbHandle)
}

func (p *NATSProvider) addDefenderEvent(ip string, score int) error {
	return sqlCommonAddDefenderHostAndEvent(ip, score, p.dbHandle)
}

func (p *NATSProvider) setDefenderBanTime(ip string, banTime int64) error {
	return sqlCommonSetDefenderBanTime(ip, banTime, p.dbHandle)
}

func (p *NATSProvider) cleanupDefender(from int64) error {
	return sqlCommonDefenderCleanup(from, p.dbHandle)
}

func (p *NATSProvider) addActiveTransfer(transfer ActiveTransfer) error {
	return sqlCommonAddActiveTransfer(transfer, p.dbHandle)
}

func (p *NATSProvider) updateActiveTransferSizes(ulSize, dlSize, transferID int64, connectionID string) error {
	return sqlCommonUpdateActiveTransferSizes(ulSize, dlSize, transferID, connectionID, p.dbHandle)
}

func (p *NATSProvider) removeActiveTransfer(transferID int64, connectionID string) error {
	return sqlCommonRemoveActiveTransfer(transferID, connectionID, p.dbHandle)
}

func (p *NATSProvider) cleanupActiveTransfers(before time.Time) error {
	return sqlCommonCleanupActiveTransfers(before, p.dbHandle)
}

func (p *NATSProvider) getActiveTransfers(from time.Time) ([]ActiveTransfer, error) {
	return sqlCommonGetActiveTransfers(from, p.dbHandle)
}

func (p *NATSProvider) addSharedSession(session Session) error {
	return sqlCommonAddSession(session, p.dbHandle)
}

func (p *NATSProvider) deleteSharedSession(key string, sessionType SessionType) error {
	return sqlCommonDeleteSession(key, sessionType, p.dbHandle)
}

func (p *NATSProvider) getSharedSession(key string, sessionType SessionType) (Session, error) {
	return sqlCommonGetSession(key, sessionType, p.dbHandle)
}

func (p *NATSProvider) cleanupSharedSessions(sessionType SessionType, before int64) error {
	return sqlCommonCleanupSessions(sessionType, before, p.dbHandle)
}

func (p *NATSProvider) getEventActions(limit, offset int, order string, minimal bool) ([]BaseEventAction, error) {
	return sqlCommonGetEventActions(limit, offset, order, minimal, p.dbHandle)
}

func (p *NATSProvider) dumpEventActions() ([]BaseEventAction, error) {
	return sqlCommonDumpEventActions(p.dbHandle)
}

func (p *NATSProvider) eventActionExists(name string) (BaseEventAction, error) {
	return sqlCommonGetEventActionByName(name, p.dbHandle)
}

func (p *NATSProvider) addEventAction(action *BaseEventAction) error {
	return p.normalizeError(sqlCommonAddEventAction(action, p.dbHandle), fieldName)
}

func (p *NATSProvider) updateEventAction(action *BaseEventAction) error {
	return sqlCommonUpdateEventAction(action, p.dbHandle)
}

func (p *NATSProvider) deleteEventAction(action BaseEventAction) error {
	return sqlCommonDeleteEventAction(action, p.dbHandle)
}

func (p *NATSProvider) getEventRules(limit, offset int, order string) ([]EventRule, error) {
	return sqlCommonGetEventRules(limit, offset, order, p.dbHandle)
}

func (p *NATSProvider) dumpEventRules() ([]EventRule, error) {
	return sqlCommonDumpEventRules(p.dbHandle)
}

func (p *NATSProvider) getRecentlyUpdatedRules(after int64) ([]EventRule, error) {
	return sqlCommonGetRecentlyUpdatedRules(after, p.dbHandle)
}

func (p *NATSProvider) eventRuleExists(name string) (EventRule, error) {
	return sqlCommonGetEventRuleByName(name, p.dbHandle)
}

func (p *NATSProvider) addEventRule(rule *EventRule) error {
	return p.normalizeError(sqlCommonAddEventRule(rule, p.dbHandle), fieldName)
}

func (p *NATSProvider) updateEventRule(rule *EventRule) error {
	return sqlCommonUpdateEventRule(rule, p.dbHandle)
}

func (p *NATSProvider) deleteEventRule(rule EventRule, softDelete bool) error {
	return sqlCommonDeleteEventRule(rule, softDelete, p.dbHandle)
}

func (p *NATSProvider) getTaskByName(name string) (Task, error) {
	return sqlCommonGetTaskByName(name, p.dbHandle)
}

func (p *NATSProvider) addTask(name string) error {
	return sqlCommonAddTask(name, p.dbHandle)
}

func (p *NATSProvider) updateTask(name string, version int64) error {
	return sqlCommonUpdateTask(name, version, p.dbHandle)
}

func (p *NATSProvider) updateTaskTimestamp(name string) error {
	return sqlCommonUpdateTaskTimestamp(name, p.dbHandle)
}

func (p *NATSProvider) addNode() error {
	return sqlCommonAddNode(p.dbHandle)
}

func (p *NATSProvider) getNodeByName(name string) (Node, error) {
	return sqlCommonGetNodeByName(name, p.dbHandle)
}

func (p *NATSProvider) getNodes() ([]Node, error) {
	return sqlCommonGetNodes(p.dbHandle)
}

func (p *NATSProvider) updateNodeTimestamp() error {
	return sqlCommonUpdateNodeTimestamp(p.dbHandle)
}

func (p *NATSProvider) cleanupNodes() error {
	return sqlCommonCleanupNodes(p.dbHandle)
}

func (p *NATSProvider) roleExists(name string) (Role, error) {
	return sqlCommonGetRoleByName(name, p.dbHandle)
}

func (p *NATSProvider) addRole(role *Role) error {
	return p.normalizeError(sqlCommonAddRole(role, p.dbHandle), fieldName)
}

func (p *NATSProvider) updateRole(role *Role) error {
	return sqlCommonUpdateRole(role, p.dbHandle)
}

func (p *NATSProvider) deleteRole(role Role) error {
	return sqlCommonDeleteRole(role, p.dbHandle)
}

func (p *NATSProvider) getRoles(limit int, offset int, order string, minimal bool) ([]Role, error) {
	return sqlCommonGetRoles(limit, offset, order, minimal, p.dbHandle)
}

func (p *NATSProvider) dumpRoles() ([]Role, error) {
	return sqlCommonDumpRoles(p.dbHandle)
}

func (p *NATSProvider) ipListEntryExists(ipOrNet string, listType IPListType) (IPListEntry, error) {
	return sqlCommonGetIPListEntry(ipOrNet, listType, p.dbHandle)
}

func (p *NATSProvider) addIPListEntry(entry *IPListEntry) error {
	return p.normalizeError(sqlCommonAddIPListEntry(entry, p.dbHandle), fieldIPNet)
}

func (p *NATSProvider) updateIPListEntry(entry *IPListEntry) error {
	return sqlCommonUpdateIPListEntry(entry, p.dbHandle)
}

func (p *NATSProvider) deleteIPListEntry(entry IPListEntry, softDelete bool) error {
	return sqlCommonDeleteIPListEntry(entry, softDelete, p.dbHandle)
}

func (p *NATSProvider) getIPListEntries(listType IPListType, filter, from, order string, limit int) ([]IPListEntry, error) {
	return sqlCommonGetIPListEntries(listType, filter, from, order, limit, p.dbHandle)
}

func (p *NATSProvider) getRecentlyUpdatedIPListEntries(after int64) ([]IPListEntry, error) {
	return sqlCommonGetRecentlyUpdatedIPListEntries(after, p.dbHandle)
}

func (p *NATSProvider) dumpIPListEntries() ([]IPListEntry, error) {
	return sqlCommonDumpIPListEntries(p.dbHandle)
}

func (p *NATSProvider) countIPListEntries(listType IPListType) (int64, error) {
	return sqlCommonCountIPListEntries(listType, p.dbHandle)
}

func (p *NATSProvider) getListEntriesForIP(ip string, listType IPListType) ([]IPListEntry, error) {
	return sqlCommonGetListEntriesForIP(ip, listType, p.dbHandle)
}

func (p *NATSProvider) getConfigs() (Configs, error) {
	return sqlCommonGetConfigs(p.dbHandle)
}

func (p *NATSProvider) setConfigs(configs *Configs) error {
	return sqlCommonSetConfigs(configs, p.dbHandle)
}

func (p *NATSProvider) setFirstDownloadTimestamp(username string) error {
	return sqlCommonSetFirstDownloadTimestamp(username, p.dbHandle)
}

func (p *NATSProvider) setFirstUploadTimestamp(username string) error {
	return sqlCommonSetFirstUploadTimestamp(username, p.dbHandle)
}

func (p *NATSProvider) close() error {
	return p.dbHandle.Close()
}

func (p *NATSProvider) reloadConfig() error {
	return nil
}

// initializeDatabase creates the initial database structure
func (p *NATSProvider) initializeDatabase() error {
	dbVersion, err := sqlCommonGetDatabaseVersion(p.dbHandle, false)
	if err == nil && dbVersion.Version > 0 {
		return ErrNoInitRequired
	}
	if errors.Is(err, sql.ErrNoRows) {
		return errSchemaVersionEmpty
	}
	logger.InfoToConsole("creating initial database schema, version 29")
	providerLog(logger.LevelInfo, "creating initial database schema, version 29")
	initialSQL := sqlReplaceAll(mysqlInitialSQL)

	return sqlCommonExecSQLAndUpdateDBVersion(p.dbHandle, strings.Split(initialSQL, ";"), 29, true)
}

func (p *NATSProvider) migrateDatabase() error {
	dbVersion, err := sqlCommonGetDatabaseVersion(p.dbHandle, true)
	if err != nil {
		return err
	}

	switch version := dbVersion.Version; {
	case version == sqlDatabaseVersion:
		providerLog(logger.LevelDebug, "sql database is up to date, current version: %d", version)
		return ErrNoInitRequired
	case version < 29:
		err = errSchemaVersionTooOld(version)
		providerLog(logger.LevelError, "%v", err)
		logger.ErrorToConsole("%v", err)
		return err
	case version == 29:
		return updateMySQLDatabaseFromV29(p.dbHandle)
	case version == 30:
		return updateMySQLDatabaseFromV30(p.dbHandle)
	case version == 31:
		return updateMySQLDatabaseFromV31(p.dbHandle)
	default:
		if version > sqlDatabaseVersion {
			providerLog(logger.LevelError, "database schema version %d is newer than the supported one: %d", version,
				sqlDatabaseVersion)
			logger.WarnToConsole("database schema version %d is newer than the supported one: %d", version,
				sqlDatabaseVersion)
			return nil
		}
		return fmt.Errorf("database schema version not handled: %d", version)
	}
}

func (p *NATSProvider) revertDatabase(targetVersion int) error {
	dbVersion, err := sqlCommonGetDatabaseVersion(p.dbHandle, true)
	if err != nil {
		return err
	}
	if dbVersion.Version == targetVersion {
		return errors.New("current version match target version, nothing to do")
	}

	switch dbVersion.Version {
	case 30:
		return downgradeMySQLDatabaseFromV30(p.dbHandle)
	case 31:
		return downgradeMySQLDatabaseFromV31(p.dbHandle)
	case 32:
		return downgradeMySQLDatabaseFromV32(p.dbHandle)
	default:
		return fmt.Errorf("database schema version not handled: %d", dbVersion.Version)
	}
}

func (p *NATSProvider) resetDatabase() error {
	sql := sqlReplaceAll(mysqlResetSQL)
	return sqlCommonExecSQLAndUpdateDBVersion(p.dbHandle, strings.Split(sql, ";"), 0, false)
}

func (p *NATSProvider) normalizeError(err error, fieldType int) error {
	if err == nil {
		return nil
	}
	var mysqlErr *mysql.MySQLError
	if errors.As(err, &mysqlErr) {
		switch mysqlErr.Number {
		case 1062:
			var message string
			switch fieldType {
			case fieldUsername:
				message = util.I18nErrorDuplicatedUsername
			case fieldIPNet:
				message = util.I18nErrorDuplicatedIPNet
			default:
				message = util.I18nErrorDuplicatedName
			}
			return util.NewI18nError(
				fmt.Errorf("%w: %s", ErrDuplicatedKey, err.Error()),
				message,
			)
		case 1452:
			return fmt.Errorf("%w: %s", ErrForeignKeyViolated, err.Error())
		}
	}
	return err
}

func updateMySQLDatabaseFromV29(dbHandle *sql.DB) error {
	if err := updateMySQLDatabaseFrom29To30(dbHandle); err != nil {
		return err
	}
	return updateMySQLDatabaseFromV30(dbHandle)
}

func updateMySQLDatabaseFromV30(dbHandle *sql.DB) error {
	if err := updateMySQLDatabaseFrom30To31(dbHandle); err != nil {
		return err
	}
	return updateMySQLDatabaseFromV31(dbHandle)
}

func updateMySQLDatabaseFromV31(dbHandle *sql.DB) error {
	return updateSQLDatabaseFrom31To32(dbHandle)
}

func downgradeMySQLDatabaseFromV30(dbHandle *sql.DB) error {
	return downgradeMySQLDatabaseFrom30To29(dbHandle)
}

func downgradeMySQLDatabaseFromV31(dbHandle *sql.DB) error {
	if err := downgradeMySQLDatabaseFrom31To30(dbHandle); err != nil {
		return err
	}
	return downgradeMySQLDatabaseFromV30(dbHandle)
}

func downgradeMySQLDatabaseFromV32(dbHandle *sql.DB) error {
	if err := downgradeSQLDatabaseFrom32To31(dbHandle); err != nil {
		return err
	}
	return downgradeMySQLDatabaseFromV31(dbHandle)
}

func updateMySQLDatabaseFrom29To30(dbHandle *sql.DB) error {
	logger.InfoToConsole("updating database schema version: 29 -> 30")
	providerLog(logger.LevelInfo, "updating database schema version: 29 -> 30")

	sql := strings.ReplaceAll(mysqlV30SQL, "{{shares}}", sqlTableShares)
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, strings.Split(sql, ";"), 30, true)
}

func downgradeMySQLDatabaseFrom30To29(dbHandle *sql.DB) error {
	logger.InfoToConsole("downgrading database schema version: 30 -> 29")
	providerLog(logger.LevelInfo, "downgrading database schema version: 30 -> 29")

	sql := strings.ReplaceAll(mysqlV30DownSQL, "{{shares}}", sqlTableShares)
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, strings.Split(sql, ";"), 29, false)
}

func updateMySQLDatabaseFrom30To31(dbHandle *sql.DB) error {
	logger.InfoToConsole("updating database schema version: 30 -> 31")
	providerLog(logger.LevelInfo, "updating database schema version: 30 -> 31")

	sql := strings.ReplaceAll(mysqlV31SQL, "{{shared_sessions}}", sqlTableSharedSessions)
	sql = strings.ReplaceAll(sql, "{{prefix}}", config.SQLTablesPrefix)
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, strings.Split(sql, ";"), 31, true)
}

func downgradeMySQLDatabaseFrom31To30(dbHandle *sql.DB) error {
	logger.InfoToConsole("downgrading database schema version: 31 -> 30")
	providerLog(logger.LevelInfo, "downgrading database schema version: 31 -> 30")

	sql := strings.ReplaceAll(mysqlV31DownSQL, "{{shared_sessions}}", sqlTableSharedSessions)
	sql = strings.ReplaceAll(sql, "{{prefix}}", config.SQLTablesPrefix)
	return sqlCommonExecSQLAndUpdateDBVersion(dbHandle, strings.Split(sql, ";"), 30, false)
}
