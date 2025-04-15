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

////go:build nats

package dataprovider

import (
	"crypto/tls"
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
	"os"
	"path/filepath"
	"strings"
	"time"
)

func init() {
	version.AddFeature("+nats")
}

type NATSProvider struct {
	js nats.JetStreamContext
}

func initializeNATSProvider() error {
	var err error

	connString, err := getNATSConnectionString(false)
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

func getNATSConnectionString(redactedPwd bool) (string, error) {
	var connectionString string
	if config.ConnectionString == "" {
		password := config.Password
		if redactedPwd && password != "" {
			password = "[redacted]"
		}
		sslMode := getSSLMode()
		if sslMode == "custom" && !redactedPwd {
			if err := registerNATSCustomTLSConfig(); err != nil {
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

func registerNATSCustomTLSConfig() error {
	tlsConfig := &tls.Config{}
	if config.RootCert != "" {
		rootCAs, err := x509.SystemCertPool()
		if err != nil {
			rootCAs = x509.NewCertPool()
		}
		rootCrt, err := os.ReadFile(config.RootCert)
		if err != nil {
			return fmt.Errorf("unable to load root certificate %q: %v", config.RootCert, err)
		}
		if !rootCAs.AppendCertsFromPEM(rootCrt) {
			return fmt.Errorf("unable to parse root certificate %q", config.RootCert)
		}
		tlsConfig.RootCAs = rootCAs
	}
	if config.ClientCert != "" && config.ClientKey != "" {
		clientCert := make([]tls.Certificate, 0, 1)
		tlsCert, err := tls.LoadX509KeyPair(config.ClientCert, config.ClientKey)
		if err != nil {
			return fmt.Errorf("unable to load key pair %q, %q: %v", config.ClientCert, config.ClientKey, err)
		}
		clientCert = append(clientCert, tlsCert)
		tlsConfig.Certificates = clientCert
	}
	if config.SSLMode == 2 || config.SSLMode == 3 {
		tlsConfig.InsecureSkipVerify = true
	}
	if !filepath.IsAbs(config.Host) && !config.DisableSNI {
		tlsConfig.ServerName = config.Host
	}
	providerLog(logger.LevelInfo, "registering custom TLS config, root cert %q, client cert %q, client key %q, disable SNI? %v",
		config.RootCert, config.ClientCert, config.ClientKey, config.DisableSNI)
	if err := mysql.RegisterTLSConfig("custom", tlsConfig); err != nil {
		return fmt.Errorf("unable to register tls config: %v", err)
	}
	return nil
}

func (n *NATSProvider) checkAvailability() error {
	return sqlCommonCheckAvailability(n.dbHandle)
}

func (n *NATSProvider) validateUserAndPass(username, password, ip, protocol string) (User, error) {
	return sqlCommonValidateUserAndPass(username, password, ip, protocol, n.dbHandle)
}

func (n *NATSProvider) validateUserAndTLSCert(username, protocol string, tlsCert *x509.Certificate) (User, error) {
	return sqlCommonValidateUserAndTLSCertificate(username, protocol, tlsCert, n.dbHandle)
}

func (n *NATSProvider) validateUserAndPubKey(username string, publicKey []byte, isSSHCert bool) (User, string, error) {
	return sqlCommonValidateUserAndPubKey(username, publicKey, isSSHCert, n.dbHandle)
}

func (n *NATSProvider) updateTransferQuota(username string, uploadSize, downloadSize int64, reset bool) error {
	return sqlCommonUpdateTransferQuota(username, uploadSize, downloadSize, reset, n.dbHandle)
}

func (n *NATSProvider) updateQuota(username string, filesAdd int, sizeAdd int64, reset bool) error {
	return sqlCommonUpdateQuota(username, filesAdd, sizeAdd, reset, n.dbHandle)
}

func (n *NATSProvider) getUsedQuota(username string) (int, int64, int64, int64, error) {
	return sqlCommonGetUsedQuota(username, n.dbHandle)
}

func (n *NATSProvider) getAdminSignature(username string) (string, error) {
	return sqlCommonGetAdminSignature(username, n.dbHandle)
}

func (n *NATSProvider) getUserSignature(username string) (string, error) {
	return sqlCommonGetUserSignature(username, n.dbHandle)
}

func (n *NATSProvider) setUpdatedAt(username string) {
	sqlCommonSetUpdatedAt(username, n.dbHandle)
}

func (n *NATSProvider) updateLastLogin(username string) error {
	return sqlCommonUpdateLastLogin(username, n.dbHandle)
}

func (n *NATSProvider) updateAdminLastLogin(username string) error {
	return sqlCommonUpdateAdminLastLogin(username, n.dbHandle)
}

func (n *NATSProvider) userExists(username, role string) (User, error) {
	return sqlCommonGetUserByUsername(username, role, n.dbHandle)
}

func (n *NATSProvider) addUser(user *User) error {
	return n.normalizeError(sqlCommonAddUser(user, n.dbHandle), fieldUsername)
}

func (n *NATSProvider) updateUser(user *User) error {
	return n.normalizeError(sqlCommonUpdateUser(user, n.dbHandle), -1)
}

func (n *NATSProvider) deleteUser(user User, softDelete bool) error {
	return sqlCommonDeleteUser(user, softDelete, n.dbHandle)
}

func (n *NATSProvider) updateUserPassword(username, password string) error {
	return sqlCommonUpdateUserPassword(username, password, n.dbHandle)
}

func (n *NATSProvider) dumpUsers() ([]User, error) {
	return sqlCommonDumpUsers(n.dbHandle)
}

func (n *NATSProvider) getRecentlyUpdatedUsers(after int64) ([]User, error) {
	return sqlCommonGetRecentlyUpdatedUsers(after, n.dbHandle)
}

func (n *NATSProvider) getUsers(limit int, offset int, order, role string) ([]User, error) {
	return sqlCommonGetUsers(limit, offset, order, role, n.dbHandle)
}

func (n *NATSProvider) getUsersForQuotaCheck(toFetch map[string]bool) ([]User, error) {
	return sqlCommonGetUsersForQuotaCheck(toFetch, n.dbHandle)
}

func (n *NATSProvider) dumpFolders() ([]vfs.BaseVirtualFolder, error) {
	return sqlCommonDumpFolders(n.dbHandle)
}

func (n *NATSProvider) getFolders(limit, offset int, order string, minimal bool) ([]vfs.BaseVirtualFolder, error) {
	return sqlCommonGetFolders(limit, offset, order, minimal, n.dbHandle)
}

func (n *NATSProvider) getFolderByName(name string) (vfs.BaseVirtualFolder, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultSQLQueryTimeout)
	defer cancel()
	return sqlCommonGetFolderByName(ctx, name, n.dbHandle)
}

func (n *NATSProvider) addFolder(folder *vfs.BaseVirtualFolder) error {
	return n.normalizeError(sqlCommonAddFolder(folder, n.dbHandle), fieldName)
}

func (n *NATSProvider) updateFolder(folder *vfs.BaseVirtualFolder) error {
	return sqlCommonUpdateFolder(folder, n.dbHandle)
}

func (n *NATSProvider) deleteFolder(folder vfs.BaseVirtualFolder) error {
	return sqlCommonDeleteFolder(folder, n.dbHandle)
}

func (n *NATSProvider) updateFolderQuota(name string, filesAdd int, sizeAdd int64, reset bool) error {
	return sqlCommonUpdateFolderQuota(name, filesAdd, sizeAdd, reset, n.dbHandle)
}

func (n *NATSProvider) getUsedFolderQuota(name string) (int, int64, error) {
	return sqlCommonGetFolderUsedQuota(name, n.dbHandle)
}

func (n *NATSProvider) getGroups(limit, offset int, order string, minimal bool) ([]Group, error) {
	return sqlCommonGetGroups(limit, offset, order, minimal, n.dbHandle)
}

func (n *NATSProvider) getGroupsWithNames(names []string) ([]Group, error) {
	return sqlCommonGetGroupsWithNames(names, n.dbHandle)
}

func (n *NATSProvider) getUsersInGroups(names []string) ([]string, error) {
	return sqlCommonGetUsersInGroups(names, n.dbHandle)
}

func (n *NATSProvider) groupExists(name string) (Group, error) {
	return sqlCommonGetGroupByName(name, n.dbHandle)
}

func (n *NATSProvider) addGroup(group *Group) error {
	return n.normalizeError(sqlCommonAddGroup(group, n.dbHandle), fieldName)
}

func (n *NATSProvider) updateGroup(group *Group) error {
	return sqlCommonUpdateGroup(group, n.dbHandle)
}

func (n *NATSProvider) deleteGroup(group Group) error {
	return sqlCommonDeleteGroup(group, n.dbHandle)
}

func (n *NATSProvider) dumpGroups() ([]Group, error) {
	return sqlCommonDumpGroups(n.dbHandle)
}

func (n *NATSProvider) adminExists(username string) (Admin, error) {
	return sqlCommonGetAdminByUsername(username, n.dbHandle)
}

func (n *NATSProvider) addAdmin(admin *Admin) error {
	return n.normalizeError(sqlCommonAddAdmin(admin, n.dbHandle), fieldUsername)
}

func (n *NATSProvider) updateAdmin(admin *Admin) error {
	return n.normalizeError(sqlCommonUpdateAdmin(admin, n.dbHandle), -1)
}

func (n *NATSProvider) deleteAdmin(admin Admin) error {
	return sqlCommonDeleteAdmin(admin, n.dbHandle)
}

func (n *NATSProvider) getAdmins(limit int, offset int, order string) ([]Admin, error) {
	return sqlCommonGetAdmins(limit, offset, order, n.dbHandle)
}

func (n *NATSProvider) dumpAdmins() ([]Admin, error) {
	return sqlCommonDumpAdmins(n.dbHandle)
}

func (n *NATSProvider) validateAdminAndPass(username, password, ip string) (Admin, error) {
	return sqlCommonValidateAdminAndPass(username, password, ip, n.dbHandle)
}

func (n *NATSProvider) apiKeyExists(keyID string) (APIKey, error) {
	return sqlCommonGetAPIKeyByID(keyID, n.dbHandle)
}

func (n *NATSProvider) addAPIKey(apiKey *APIKey) error {
	return n.normalizeError(sqlCommonAddAPIKey(apiKey, n.dbHandle), -1)
}

func (n *NATSProvider) updateAPIKey(apiKey *APIKey) error {
	return n.normalizeError(sqlCommonUpdateAPIKey(apiKey, n.dbHandle), -1)
}

func (n *NATSProvider) deleteAPIKey(apiKey APIKey) error {
	return sqlCommonDeleteAPIKey(apiKey, n.dbHandle)
}

func (n *NATSProvider) getAPIKeys(limit int, offset int, order string) ([]APIKey, error) {
	return sqlCommonGetAPIKeys(limit, offset, order, n.dbHandle)
}

func (n *NATSProvider) dumpAPIKeys() ([]APIKey, error) {
	return sqlCommonDumpAPIKeys(n.dbHandle)
}

func (n *NATSProvider) updateAPIKeyLastUse(keyID string) error {
	return sqlCommonUpdateAPIKeyLastUse(keyID, n.dbHandle)
}

func (n *NATSProvider) shareExists(shareID, username string) (Share, error) {
	return sqlCommonGetShareByID(shareID, username, n.dbHandle)
}

func (n *NATSProvider) addShare(share *Share) error {
	return n.normalizeError(sqlCommonAddShare(share, n.dbHandle), fieldName)
}

func (n *NATSProvider) updateShare(share *Share) error {
	return n.normalizeError(sqlCommonUpdateShare(share, n.dbHandle), -1)
}

func (n *NATSProvider) deleteShare(share Share) error {
	return sqlCommonDeleteShare(share, n.dbHandle)
}

func (n *NATSProvider) getShares(limit int, offset int, order, username string) ([]Share, error) {
	return sqlCommonGetShares(limit, offset, order, username, n.dbHandle)
}

func (n *NATSProvider) dumpShares() ([]Share, error) {
	return sqlCommonDumpShares(n.dbHandle)
}

func (n *NATSProvider) updateShareLastUse(shareID string, numTokens int) error {
	return sqlCommonUpdateShareLastUse(shareID, numTokens, n.dbHandle)
}

func (n *NATSProvider) getDefenderHosts(from int64, limit int) ([]DefenderEntry, error) {
	return sqlCommonGetDefenderHosts(from, limit, n.dbHandle)
}

func (n *NATSProvider) getDefenderHostByIP(ip string, from int64) (DefenderEntry, error) {
	return sqlCommonGetDefenderHostByIP(ip, from, n.dbHandle)
}

func (n *NATSProvider) isDefenderHostBanned(ip string) (DefenderEntry, error) {
	return sqlCommonIsDefenderHostBanned(ip, n.dbHandle)
}

func (n *NATSProvider) updateDefenderBanTime(ip string, minutes int) error {
	return sqlCommonDefenderIncrementBanTime(ip, minutes, n.dbHandle)
}

func (n *NATSProvider) deleteDefenderHost(ip string) error {
	return sqlCommonDeleteDefenderHost(ip, n.dbHandle)
}

func (n *NATSProvider) addDefenderEvent(ip string, score int) error {
	return sqlCommonAddDefenderHostAndEvent(ip, score, n.dbHandle)
}

func (n *NATSProvider) setDefenderBanTime(ip string, banTime int64) error {
	return sqlCommonSetDefenderBanTime(ip, banTime, n.dbHandle)
}

func (n *NATSProvider) cleanupDefender(from int64) error {
	return sqlCommonDefenderCleanup(from, n.dbHandle)
}

func (n *NATSProvider) addActiveTransfer(transfer ActiveTransfer) error {
	return sqlCommonAddActiveTransfer(transfer, n.dbHandle)
}

func (n *NATSProvider) updateActiveTransferSizes(ulSize, dlSize, transferID int64, connectionID string) error {
	return sqlCommonUpdateActiveTransferSizes(ulSize, dlSize, transferID, connectionID, n.dbHandle)
}

func (n *NATSProvider) removeActiveTransfer(transferID int64, connectionID string) error {
	return sqlCommonRemoveActiveTransfer(transferID, connectionID, n.dbHandle)
}

func (n *NATSProvider) cleanupActiveTransfers(before time.Time) error {
	return sqlCommonCleanupActiveTransfers(before, n.dbHandle)
}

func (n *NATSProvider) getActiveTransfers(from time.Time) ([]ActiveTransfer, error) {
	return sqlCommonGetActiveTransfers(from, n.dbHandle)
}

func (n *NATSProvider) addSharedSession(session Session) error {
	return sqlCommonAddSession(session, n.dbHandle)
}

func (n *NATSProvider) deleteSharedSession(key string, sessionType SessionType) error {
	return sqlCommonDeleteSession(key, sessionType, n.dbHandle)
}

func (n *NATSProvider) getSharedSession(key string, sessionType SessionType) (Session, error) {
	return sqlCommonGetSession(key, sessionType, n.dbHandle)
}

func (n *NATSProvider) cleanupSharedSessions(sessionType SessionType, before int64) error {
	return sqlCommonCleanupSessions(sessionType, before, n.dbHandle)
}

func (n *NATSProvider) getEventActions(limit, offset int, order string, minimal bool) ([]BaseEventAction, error) {
	return sqlCommonGetEventActions(limit, offset, order, minimal, n.dbHandle)
}

func (n *NATSProvider) dumpEventActions() ([]BaseEventAction, error) {
	return sqlCommonDumpEventActions(n.dbHandle)
}

func (n *NATSProvider) eventActionExists(name string) (BaseEventAction, error) {
	return sqlCommonGetEventActionByName(name, n.dbHandle)
}

func (n *NATSProvider) addEventAction(action *BaseEventAction) error {
	return n.normalizeError(sqlCommonAddEventAction(action, n.dbHandle), fieldName)
}

func (n *NATSProvider) updateEventAction(action *BaseEventAction) error {
	return sqlCommonUpdateEventAction(action, n.dbHandle)
}

func (n *NATSProvider) deleteEventAction(action BaseEventAction) error {
	return sqlCommonDeleteEventAction(action, n.dbHandle)
}

func (n *NATSProvider) getEventRules(limit, offset int, order string) ([]EventRule, error) {
	return sqlCommonGetEventRules(limit, offset, order, n.dbHandle)
}

func (n *NATSProvider) dumpEventRules() ([]EventRule, error) {
	return sqlCommonDumpEventRules(n.dbHandle)
}

func (n *NATSProvider) getRecentlyUpdatedRules(after int64) ([]EventRule, error) {
	return sqlCommonGetRecentlyUpdatedRules(after, n.dbHandle)
}

func (n *NATSProvider) eventRuleExists(name string) (EventRule, error) {
	return sqlCommonGetEventRuleByName(name, n.dbHandle)
}

func (n *NATSProvider) addEventRule(rule *EventRule) error {
	return n.normalizeError(sqlCommonAddEventRule(rule, n.dbHandle), fieldName)
}

func (n *NATSProvider) updateEventRule(rule *EventRule) error {
	return sqlCommonUpdateEventRule(rule, n.dbHandle)
}

func (n *NATSProvider) deleteEventRule(rule EventRule, softDelete bool) error {
	return sqlCommonDeleteEventRule(rule, softDelete, n.dbHandle)
}

func (n *NATSProvider) getTaskByName(name string) (Task, error) {
	return sqlCommonGetTaskByName(name, n.dbHandle)
}

func (n *NATSProvider) addTask(name string) error {
	return sqlCommonAddTask(name, n.dbHandle)
}

func (n *NATSProvider) updateTask(name string, version int64) error {
	return sqlCommonUpdateTask(name, version, n.dbHandle)
}

func (n *NATSProvider) updateTaskTimestamp(name string) error {
	return sqlCommonUpdateTaskTimestamp(name, n.dbHandle)
}

func (n *NATSProvider) addNode() error {
	return sqlCommonAddNode(n.dbHandle)
}

func (n *NATSProvider) getNodeByName(name string) (Node, error) {
	return sqlCommonGetNodeByName(name, n.dbHandle)
}

func (n *NATSProvider) getNodes() ([]Node, error) {
	return sqlCommonGetNodes(n.dbHandle)
}

func (n *NATSProvider) updateNodeTimestamp() error {
	return sqlCommonUpdateNodeTimestamp(n.dbHandle)
}

func (n *NATSProvider) cleanupNodes() error {
	return sqlCommonCleanupNodes(n.dbHandle)
}

func (n *NATSProvider) roleExists(name string) (Role, error) {
	return sqlCommonGetRoleByName(name, n.dbHandle)
}

func (n *NATSProvider) addRole(role *Role) error {
	return n.normalizeError(sqlCommonAddRole(role, n.dbHandle), fieldName)
}

func (n *NATSProvider) updateRole(role *Role) error {
	return sqlCommonUpdateRole(role, n.dbHandle)
}

func (n *NATSProvider) deleteRole(role Role) error {
	return sqlCommonDeleteRole(role, n.dbHandle)
}

func (n *NATSProvider) getRoles(limit int, offset int, order string, minimal bool) ([]Role, error) {
	return sqlCommonGetRoles(limit, offset, order, minimal, n.dbHandle)
}

func (n *NATSProvider) dumpRoles() ([]Role, error) {
	return sqlCommonDumpRoles(n.dbHandle)
}

func (n *NATSProvider) ipListEntryExists(ipOrNet string, listType IPListType) (IPListEntry, error) {
	return sqlCommonGetIPListEntry(ipOrNet, listType, n.dbHandle)
}

func (n *NATSProvider) addIPListEntry(entry *IPListEntry) error {
	return n.normalizeError(sqlCommonAddIPListEntry(entry, n.dbHandle), fieldIPNet)
}

func (n *NATSProvider) updateIPListEntry(entry *IPListEntry) error {
	return sqlCommonUpdateIPListEntry(entry, n.dbHandle)
}

func (n *NATSProvider) deleteIPListEntry(entry IPListEntry, softDelete bool) error {
	return sqlCommonDeleteIPListEntry(entry, softDelete, n.dbHandle)
}

func (n *NATSProvider) getIPListEntries(listType IPListType, filter, from, order string, limit int) ([]IPListEntry, error) {
	return sqlCommonGetIPListEntries(listType, filter, from, order, limit, n.dbHandle)
}

func (n *NATSProvider) getRecentlyUpdatedIPListEntries(after int64) ([]IPListEntry, error) {
	return sqlCommonGetRecentlyUpdatedIPListEntries(after, n.dbHandle)
}

func (n *NATSProvider) dumpIPListEntries() ([]IPListEntry, error) {
	return sqlCommonDumpIPListEntries(n.dbHandle)
}

func (n *NATSProvider) countIPListEntries(listType IPListType) (int64, error) {
	return sqlCommonCountIPListEntries(listType, n.dbHandle)
}

func (n *NATSProvider) getListEntriesForIP(ip string, listType IPListType) ([]IPListEntry, error) {
	return sqlCommonGetListEntriesForIP(ip, listType, n.dbHandle)
}

func (n *NATSProvider) getConfigs() (Configs, error) {
	return sqlCommonGetConfigs(n.dbHandle)
}

func (n *NATSProvider) setConfigs(configs *Configs) error {
	return sqlCommonSetConfigs(configs, n.dbHandle)
}

func (n *NATSProvider) setFirstDownloadTimestamp(username string) error {
	return sqlCommonSetFirstDownloadTimestamp(username, n.dbHandle)
}

func (n *NATSProvider) setFirstUploadTimestamp(username string) error {
	return sqlCommonSetFirstUploadTimestamp(username, n.dbHandle)
}

func (n *NATSProvider) close() error {
	return n.dbHandle.Close()
}

func (n *NATSProvider) reloadConfig() error {
	return nil
}

// initializeDatabase creates the initial database structure
func (n *NATSProvider) initializeDatabase() error {
	dbVersion, err := sqlCommonGetDatabaseVersion(n.dbHandle, false)
	if err == nil && dbVersion.Version > 0 {
		return ErrNoInitRequired
	}
	if errors.Is(err, sql.ErrNoRows) {
		return errSchemaVersionEmpty
	}
	logger.InfoToConsole("creating initial database schema, version 29")
	providerLog(logger.LevelInfo, "creating initial database schema, version 29")
	initialSQL := sqlReplaceAll(mysqlInitialSQL)

	return sqlCommonExecSQLAndUpdateDBVersion(n.dbHandle, strings.Split(initialSQL, ";"), 29, true)
}

func (n *NATSProvider) migrateDatabase() error {
	dbVersion, err := sqlCommonGetDatabaseVersion(n.dbHandle, true)
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
		return updateNATSDatabaseFromV29(n.dbHandle)
	case version == 30:
		return updateNATSDatabaseFromV30(n.dbHandle)
	case version == 31:
		return updateNATSDatabaseFromV31(n.dbHandle)
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

func (n *NATSProvider) revertDatabase(targetVersion int) error {
	dbVersion, err := sqlCommonGetDatabaseVersion(n.dbHandle, true)
	if err != nil {
		return err
	}
	if dbVersion.Version == targetVersion {
		return errors.New("current version match target version, nothing to do")
	}

	switch dbVersion.Version {
	case 30:
		return downgradeNATSDatabaseFromV30(n.dbHandle)
	case 31:
		return downgradeNATSDatabaseFromV31(n.dbHandle)
	case 32:
		return downgradeNATSDatabaseFromV32(n.dbHandle)
	default:
		return fmt.Errorf("database schema version not handled: %d", dbVersion.Version)
	}
}

func (n *NATSProvider) resetDatabase() error {
	sql := sqlReplaceAll(natsReset)
	return sqlCommonExecSQLAndUpdateDBVersion(n.dbHandle, strings.Split(sql, ";"), 0, false)
}

func (n *NATSProvider) normalizeError(err error, fieldType int) error {
	if err == nil {
		return nil
	}
	var natsErr *nats.NATSError
	if errors.As(err, &natsErr) {
		switch natsErr.Number {
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
