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
	"time"

	"github.com/drakkan/sftpgo/v2/internal/logger"
	"github.com/drakkan/sftpgo/v2/internal/util"
	"github.com/drakkan/sftpgo/v2/internal/version"
	"github.com/drakkan/sftpgo/v2/internal/vfs"
	"github.com/nats-io/nats.go"
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
	*NatsCore
	ctx    context.Context
	cancel context.CancelFunc
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

	coreNats, err := NewNatsCore(&NatsCoreConfig{
		JS:           js,
		MaxRetries:   10,
		RetryDelay:   50 * time.Millisecond,
		StorageNames: storageNames,
	})

	ctx, cancel := context.WithCancel(context.Background())
	db := &NATSProvider{
		ctx:      ctx,
		cancel:   cancel,
		NatsCore: coreNats,
	}

	go func() {
		defer db.cancel()
		<-ctx.Done()
		cancel()
	}()

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
	keys, err := p.ListItems(actionsBucketNATS)
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
		wAction := newWrapper(BaseEventAction{})
		_, err := p.GetItem(actionsBucketNATS, k, wAction)
		if err != nil && errors.Is(err, ErrKeyNotFound) {
			continue
		}
		action := wAction.Get().(BaseEventAction)
		action.PrepareForRendering()
		actions = append(actions, action)
		if len(actions) >= limit {
			break
		}
	}
	return actions, nil
}

func (p *NATSProvider) updateTransferQuota(username string, uploadSize, downloadSize int64, reset bool) error {
	wUser := newWrapper(User{})
	revision, err := p.GetItem(usersBucketNATS, username, wUser)
	if err != nil && errors.Is(err, ErrKeyNotFound) {
		return util.NewRecordNotFoundError(fmt.Sprintf("username %q does not exist, unable to update transfer quota", username))
	}
	user := wUser.Get().(User)
	if !reset {
		user.UsedUploadDataTransfer += uploadSize
		user.UsedDownloadDataTransfer += downloadSize
	} else {
		user.UsedUploadDataTransfer = uploadSize
		user.UsedDownloadDataTransfer = downloadSize
	}
	user.LastQuotaUpdate = util.GetTimeAsMsSinceEpoch(time.Now())
	wUser.Set(user)
	if revision == 0 {
		_, err := p.PutItem(usersBucketNATS, username, wUser)
		return err
	}
	providerLog(logger.LevelDebug, "transfer quota updated for user %q, ul increment: %v dl increment: %v is reset? %v", username, uploadSize, downloadSize, reset)
	return p.UpdateItem(usersBucketNATS, username, wUser)
}

func (p *NATSProvider) updateQuota(username string, filesAdd int, sizeAdd int64, reset bool) error {
	wUser := newWrapper(User{})
	revision, err := p.GetItem(usersBucketNATS, username, wUser)
	if err != nil && errors.Is(err, ErrKeyNotFound) {
		return util.NewRecordNotFoundError(fmt.Sprintf("username %q does not exist, unable to update quota", username))
	}
	user := wUser.Get().(User)
	if reset {
		user.UsedQuotaSize = sizeAdd
		user.UsedQuotaFiles = filesAdd
	} else {
		user.UsedQuotaSize += sizeAdd
		user.UsedQuotaFiles += filesAdd
	}
	user.LastQuotaUpdate = util.GetTimeAsMsSinceEpoch(time.Now())
	wUser.Set(user)
	if revision == 0 {
		_, err := p.PutItem(usersBucketNATS, username, wUser)
		return err
	}
	providerLog(logger.LevelDebug, "quota updated for user %q, files increment: %v size increment: %v is reset? %v", username, filesAdd, sizeAdd, reset)
	return p.UpdateItem(usersBucketNATS, username, wUser)
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
	wAdmin := newWrapper(Admin{})
	_, err := p.GetItem(adminsBucketNATS, username, wAdmin)
	if err != nil && errors.Is(err, ErrKeyNotFound) {
		return Admin{}, util.NewRecordNotFoundError(fmt.Sprintf("admin %v does not exist", username))
	}
	return wAdmin.Get().(Admin), nil
}

func (p *NATSProvider) addAdmin(admin *Admin) error {
	if err := admin.validate(); err != nil {
		return err
	}
	wAdmin := newWrapper(Admin{})
	revision, err := p.GetItem(adminsBucketNATS, admin.Username, wAdmin)
	if err != nil && !errors.Is(err, ErrKeyNotFound) {
		return util.NewI18nError(fmt.Errorf("%w: admin %q already exists", ErrDuplicatedKey, admin.Username), util.I18nErrorDuplicatedUsername)
	}
	admin.ID = time.Now().UnixNano()
	admin.LastLogin = 0
	admin.CreatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
	admin.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
	sort.Slice(admin.Groups, func(i, j int) bool {
		return admin.Groups[i].Name < admin.Groups[j].Name
	})
	for idx := range admin.Groups {
		if err = p.addAdminToGroupMapping(admin.Username, admin.Groups[idx].Name); err != nil {
			return err
		}
	}
	if err = p.addAdminToRole(admin.Username, admin.Role); err != nil {
		return err
	}
	wAdmin.Set(*admin)
	if revision == 0 {
		_, err := p.PutItem(adminsBucketNATS, admin.Username, wAdmin)
		return err
	}
	return p.UpdateItem(adminsBucketNATS, admin.Username, wAdmin)
}

func (p *NATSProvider) updateAdmin(admin *Admin) error {
	if err := admin.validate(); err != nil {
		return err
	}
	wAdmin := newWrapper(Admin{})
	revision, err := p.GetItem(adminsBucketNATS, admin.Username, wAdmin)
	if err != nil && errors.Is(err, ErrKeyNotFound) {
		return util.NewRecordNotFoundError(fmt.Sprintf("admin %v does not exist", admin.Username))
	}
	oldAdmin := wAdmin.Get().(Admin)
	if err = p.removeAdminFromRole(oldAdmin.Username, oldAdmin.Role); err != nil {
		return err
	}
	for idx := range oldAdmin.Groups {
		if err = p.removeAdminFromGroupMapping(oldAdmin.Username, oldAdmin.Groups[idx].Name); err != nil {
			return err
		}
	}
	if err = p.addAdminToRole(admin.Username, admin.Role); err != nil {
		return err
	}
	sort.Slice(admin.Groups, func(i, j int) bool {
		return admin.Groups[i].Name < admin.Groups[j].Name
	})
	for idx := range admin.Groups {
		if err = p.addAdminToGroupMapping(admin.Username, admin.Groups[idx].Name); err != nil {
			return err
		}
	}
	admin.ID = oldAdmin.ID
	admin.CreatedAt = oldAdmin.CreatedAt
	admin.LastLogin = oldAdmin.LastLogin
	admin.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
	wAdmin.Set(*admin)
	if revision == 0 {
		_, err := p.PutItem(adminsBucketNATS, admin.Username, wAdmin)
		return err
	}
	return p.UpdateItem(adminsBucketNATS, admin.Username, wAdmin)
}

func (p *NATSProvider) deleteAdmin(admin Admin) error {
	wOldAdmin := newWrapper(Admin{})
	_, err := p.GetItem(adminsBucketNATS, admin.Username, wOldAdmin)
	if err != nil && errors.Is(err, ErrKeyNotFound) {
		return util.NewRecordNotFoundError(fmt.Sprintf("admin %v does not exist", admin.Username))
	}
	oldAdmin := wOldAdmin.Get().(Admin)
	if len(oldAdmin.Groups) > 0 {
		for idx := range oldAdmin.Groups {
			if err = p.removeAdminFromGroupMapping(oldAdmin.Username, oldAdmin.Groups[idx].Name); err != nil {
				return err
			}
		}
	}
	if oldAdmin.Role != "" {
		if err = p.removeAdminFromRole(oldAdmin.Username, oldAdmin.Role); err != nil {
			return err
		}
	}
	if err := p.deleteRelatedAPIKey(admin.Username, APIKeyScopeAdmin); err != nil {
		return err
	}
	return p.DeleteItem(adminsBucketNATS, admin.Username)
}

func (p *NATSProvider) getAdmins(limit int, offset int, order string) ([]Admin, error) {
	admins := make([]Admin, 0, limit)
	keys, err := p.ListItems(adminsBucketNATS)
	if err != nil && errors.Is(err, ErrKeyNotFound) {
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
		wAdmin := newWrapper(Admin{})
		_, err := p.GetItem(adminsBucketNATS, key, wAdmin)
		if err != nil && errors.Is(err, ErrKeyNotFound) {
			continue
		}
		admin := wAdmin.Get().(Admin)
		admin.HideConfidentialData()
		admins = append(admins, admin)
	}
	return admins, nil
}

func (p *NATSProvider) dumpAdmins() ([]Admin, error) {
	admins := make([]Admin, 0, 30)
	keys, err := p.ListItems(adminsBucketNATS)
	if err != nil {
		return nil, err
	}
	for _, key := range keys {
		wAdmin := newWrapper(Admin{})
		_, err := p.GetItem(adminsBucketNATS, key, wAdmin)
		if err != nil && errors.Is(err, ErrKeyNotFound) {
			continue
		}
		admins = append(admins, wAdmin.Get().(Admin))
	}
	return admins, nil
}

func (p *NATSProvider) userExists(username, role string) (User, error) {
	wUser := newWrapper(User{})
	_, err := p.GetItem(usersBucketNATS, username, wUser)
	if err != nil && errors.Is(err, ErrKeyNotFound) {
		return User{}, util.NewRecordNotFoundError(fmt.Sprintf("username %q does not exist", username))
	}
	user, err := p.joinUserAndFolders(wUser.Get().(User))
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
	wUser := newWrapper(User{})
	revision, err := p.GetItem(usersBucketNATS, user.Username, wUser)
	if err == nil && errors.Is(err, ErrKeyNotFound) {
		return util.NewI18nError(fmt.Errorf("%w: username %v already exists", ErrDuplicatedKey, user.Username), util.I18nErrorDuplicatedUsername)
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
	if err := p.addUserToRole(user.Username, user.Role); err != nil {
		return err
	}
	sort.Slice(user.VirtualFolders, func(i, j int) bool {
		return user.VirtualFolders[i].Name < user.VirtualFolders[j].Name
	})
	for idx := range user.VirtualFolders {
		if err = p.addRelationToFolderMapping(user.VirtualFolders[idx].Name, user, nil); err != nil {
			return err
		}
	}
	sort.Slice(user.Groups, func(i, j int) bool {
		return user.Groups[i].Name < user.Groups[j].Name
	})
	for idx := range user.Groups {
		if err = p.addUserToGroupMapping(user.Username, user.Groups[idx].Name); err != nil {
			return err
		}
	}
	wUser.Set(*user)
	if revision == 0 {
		_, err := p.PutItem(usersBucketNATS, user.Username, wUser)
		return err
	}
	return p.UpdateItem(usersBucketNATS, user.Username, wUser)
}

func (p *NATSProvider) updateUser(user *User) error {
	if err := ValidateUser(user); err != nil {
		return err
	}
	wOldUser := newWrapper(User{})
	revision, err := p.GetItem(usersBucketNATS, user.Username, wOldUser)
	if err != nil && errors.Is(err, ErrKeyNotFound) {
		return util.NewRecordNotFoundError(fmt.Sprintf("username %q does not exist", user.Username))
	}
	oldUser := wOldUser.Get().(User)
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
	wOldUser.Set(*user)
	setLastUserUpdate()
	if revision == 0 {
		_, err := p.PutItem(usersBucketNATS, user.Username, wOldUser)
		return err
	}
	return p.UpdateItem(usersBucketNATS, user.Username, wOldUser)
}

func (p *NATSProvider) deleteUser(user User, _ bool) error {
	wOldUser := newWrapper(User{})
	_, err := p.GetItem(usersBucketNATS, user.Username, wOldUser)
	if err != nil && errors.Is(err, ErrKeyNotFound) {
		return util.NewRecordNotFoundError(fmt.Sprintf("username %q does not exist", user.Username))
	}
	oldUser := wOldUser.Get().(User)
	if err := p.removeUserFromRole(oldUser.Username, oldUser.Role); err != nil {
		return err
	}
	for idx := range oldUser.VirtualFolders {
		if err = p.removeRelationFromFolderMapping(oldUser.VirtualFolders[idx], oldUser.Username, ""); err != nil {
			return err
		}
	}
	for idx := range oldUser.Groups {
		if err = p.removeUserFromGroupMapping(oldUser.Username, oldUser.Groups[idx].Name); err != nil {
			return err
		}
	}
	if err := p.deleteRelatedAPIKey(user.Username, APIKeyScopeUser); err != nil {
		return err
	}
	if err := p.deleteRelatedShares(user.Username); err != nil {
		return err
	}
	return p.DeleteItem(usersBucketNATS, user.Username)
}

func (p *NATSProvider) updateUserPassword(username, password string) error {
	wUser := newWrapper(User{})
	revision, err := p.GetItem(usersBucketNATS, username, wUser)
	if err != nil && errors.Is(err, ErrKeyNotFound) {
		return util.NewRecordNotFoundError(fmt.Sprintf("username %q does not exist", username))
	}
	user := wUser.Get().(User)
	user.Password = password
	user.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
	wUser.Set(user)
	if revision == 0 {
		_, err := p.PutItem(usersBucketNATS, username, wUser)
		return err
	}
	return p.UpdateItem(usersBucketNATS, username, wUser)
}

func (p *NATSProvider) dumpUsers() ([]User, error) {
	users := make([]User, 0, 100)
	keys, err := p.ListItems(usersBucketNATS)
	if err != nil {
		return nil, err
	}
	for _, key := range keys {
		wUser := newWrapper(User{})
		_, err := p.GetItem(usersBucketNATS, key, wUser)
		if err != nil && errors.Is(err, ErrKeyNotFound) {
			continue
		}
		user, err := p.joinUserAndFolders(wUser.Get().(User))
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	return users, nil
}

func (p *NATSProvider) getRecentlyUpdatedUsers(after int64) ([]User, error) {
	if getLastUserUpdate() < after {
		return nil, nil
	}
	users := make([]User, 0, 10)
	keys, err := p.ListItems(usersBucketNATS)
	if err != nil {
		return nil, err
	}
	for _, key := range keys {
		wUser := newWrapper(User{})
		_, err := p.GetItem(usersBucketNATS, key, wUser)
		if err != nil && errors.Is(err, ErrKeyNotFound) {
			continue
		}
		user := wUser.Get().(User)
		if user.UpdatedAt < after {
			continue
		}
		if len(user.VirtualFolders) > 0 {
			var folders []vfs.VirtualFolder
			for idx := range user.VirtualFolders {
				folder := &user.VirtualFolders[idx]
				baseFolder, err := p.folderExistsInternal(folder.Name)
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
				group, err := p.groupExistsInternal(user.Groups[idx].Name)
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
	for username, needFolders := range toFetch {
		wUser := newWrapper(User{})
		_, err := p.GetItem(usersBucketNATS, username, wUser)
		if err != nil && errors.Is(err, ErrKeyNotFound) {
			continue
		}
		user := wUser.Get().(User)
		if needFolders && len(user.VirtualFolders) > 0 {
			var folders []vfs.VirtualFolder
			for idx := range user.VirtualFolders {
				folder := &user.VirtualFolders[idx]
				baseFolder, err := p.folderExistsInternal(folder.Name)
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
				group, err := p.groupExistsInternal(user.Groups[idx].Name)
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
	keys, err := p.ListItems(usersBucketNATS)
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
		wUser := newWrapper(User{})
		_, err := p.GetItem(usersBucketNATS, key, wUser)
		if err != nil && errors.Is(err, ErrKeyNotFound) {
			continue
		}
		user, err := p.joinUserAndFolders(wUser.Get().(User))
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
	keys, err := p.ListItems(foldersBucketNATS)
	if err != nil {
		return nil, err
	}
	for _, key := range keys {
		wFolder := newWrapper(vfs.BaseVirtualFolder{})
		_, err := p.GetItem(foldersBucketNATS, key, wFolder)
		if err != nil && errors.Is(err, ErrKeyNotFound) {
			continue
		}
		folders = append(folders, wFolder.Get().(vfs.BaseVirtualFolder))
	}
	return folders, nil
}

func (p *NATSProvider) getFolders(limit, offset int, order string, _ bool) ([]vfs.BaseVirtualFolder, error) {
	folders := make([]vfs.BaseVirtualFolder, 0, limit)
	if limit <= 0 {
		return folders, nil
	}
	keys, err := p.ListItems(foldersBucketNATS)
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
		wFolder := newWrapper(vfs.BaseVirtualFolder{})
		_, err := p.GetItem(foldersBucketNATS, key, wFolder)
		if err != nil && errors.Is(err, ErrKeyNotFound) {
			continue
		}
		folder := wFolder.Get().(vfs.BaseVirtualFolder)
		folder.PrepareForRendering()
		folders = append(folders, folder)
	}
	return folders, nil
}

func (p *NATSProvider) getFolderByName(name string) (vfs.BaseVirtualFolder, error) {
	return p.folderExistsInternal(name)
}

func (p *NATSProvider) addFolder(folder *vfs.BaseVirtualFolder) error {
	if err := ValidateFolder(folder); err != nil {
		return err
	}
	wFolder := newWrapper(vfs.BaseVirtualFolder{})
	revision, err := p.GetItem(foldersBucketNATS, folder.Name, wFolder)
	if err != nil && errors.Is(err, ErrKeyNotFound) {
		return util.NewI18nError(fmt.Errorf("%w: folder %q already exists", ErrDuplicatedKey, folder.Name), util.I18nErrorDuplicatedUsername)
	}
	folder.Users = nil
	folder.Groups = nil
	wFolder.Set(*folder)
	if revision == 0 {
		_, err := p.PutItem(foldersBucketNATS, folder.Name, wFolder)
		return err
	}
	return p.UpdateItem(foldersBucketNATS, folder.Name, wFolder)
}

func (p *NATSProvider) updateFolder(folder *vfs.BaseVirtualFolder) error {
	if err := ValidateFolder(folder); err != nil {
		return err
	}
	wOldFolder := newWrapper(vfs.BaseVirtualFolder{})
	revision, err := p.GetItem(foldersBucketNATS, folder.Name, wOldFolder)
	if err != nil && errors.Is(err, ErrKeyNotFound) {
		return util.NewRecordNotFoundError(fmt.Sprintf("folder %v does not exist", folder.Name))
	}
	oldFolder := wOldFolder.Get().(vfs.BaseVirtualFolder)
	folder.ID = oldFolder.ID
	folder.LastQuotaUpdate = oldFolder.LastQuotaUpdate
	folder.UsedQuotaFiles = oldFolder.UsedQuotaFiles
	folder.UsedQuotaSize = oldFolder.UsedQuotaSize
	folder.Users = oldFolder.Users
	folder.Groups = oldFolder.Groups
	wOldFolder.Set(*folder)
	if revision == 0 {
		_, err := p.PutItem(foldersBucketNATS, folder.Name, wOldFolder)
		return err
	}
	return p.UpdateItem(foldersBucketNATS, folder.Name, wOldFolder)
}

func (p *NATSProvider) deleteFolder(baseFolder vfs.BaseVirtualFolder) error {
	wFolder := newWrapper(vfs.BaseVirtualFolder{})
	_, err := p.GetItem(foldersBucketNATS, baseFolder.Name, wFolder)
	if err != nil && errors.Is(err, ErrKeyNotFound) {
		return util.NewRecordNotFoundError(fmt.Sprintf("folder %v does not exist", baseFolder.Name))
	}
	folder := wFolder.Get().(vfs.BaseVirtualFolder)
	if err = p.deleteFolderMappings(folder); err != nil {
		return err
	}
	return p.DeleteItem(foldersBucketNATS, folder.Name)
}

func (p *NATSProvider) updateFolderQuota(name string, filesAdd int, sizeAdd int64, reset bool) error {
	wFolder := newWrapper(vfs.BaseVirtualFolder{})
	_, err := p.GetItem(foldersBucketNATS, name, wFolder)
	if err != nil && errors.Is(err, ErrKeyNotFound) {
		return util.NewRecordNotFoundError(fmt.Sprintf("folder %q does not exist, unable to update quota", name))
	}
	folder := wFolder.Get().(vfs.BaseVirtualFolder)
	if reset {
		folder.UsedQuotaSize = sizeAdd
		folder.UsedQuotaFiles = filesAdd
	} else {
		folder.UsedQuotaSize += sizeAdd
		folder.UsedQuotaFiles += filesAdd
	}
	folder.LastQuotaUpdate = util.GetTimeAsMsSinceEpoch(time.Now())
	wFolder.Set(folder)
	return p.UpdateItem(foldersBucketNATS, folder.Name, wFolder)
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
	keys, err := p.ListItems(rolesBucketNATS)
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
		wGroup := newWrapper(Group{})
		_, err := p.GetItem(rolesBucketNATS, key, wGroup)
		if err != nil {
			continue
		}
		group, err := p.joinGroupAndFolders(wGroup.Get().(Group))
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
	for _, name := range names {
		wGroup := newWrapper(Group{})
		_, err := p.GetItem(rolesBucketNATS, name, wGroup)
		if err != nil {
			continue
		}
		group, err := p.joinGroupAndFolders(wGroup.Get().(Group))
		if err != nil {
			return nil, err
		}
		groups = append(groups, group)
	}
	return groups, nil
}

func (p *NATSProvider) addGroup(group *Group) error {
	if err := group.validate(); err != nil {
		return err
	}
	wGroup := newWrapper(Group{})
	_, err := p.GetItem(rolesBucketNATS, group.Name, wGroup)
	if err == nil && errors.Is(err, ErrKeyNotFound) {
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
	for idx := range group.VirtualFolders {
		if err = p.addRelationToFolderMapping(group.VirtualFolders[idx].Name, nil, group); err != nil {
			return err
		}
	}
	wGroup.Set(*group)
	return p.UpdateItem(rolesBucketNATS, group.Name, wGroup)
}

func (p *NATSProvider) getUsersInGroups(names []string) ([]string, error) {
	var usernames []string
	for _, name := range names {
		wGroup := newWrapper(Group{})
		_, err := p.GetItem(rolesBucketNATS, name, wGroup)
		if err != nil {
			continue
		}
		group := wGroup.Get().(Group)
		usernames = append(usernames, group.Users...)
	}
	return usernames, nil
}

func (p *NATSProvider) groupExists(name string) (Group, error) {
	wGroup := newWrapper(Group{})
	_, err := p.GetItem(rolesBucketNATS, name, wGroup)
	if err != nil {
		if errors.Is(err, ErrKeyNotFound) {
			return Group{}, util.NewRecordNotFoundError(fmt.Sprintf("group %q does not exist", name))
		}
		return Group{}, err
	}
	return p.joinGroupAndFolders(wGroup.Get().(Group))
}

func (p *NATSProvider) updateGroup(group *Group) error {
	if err := group.validate(); err != nil {
		return err
	}
	wOldGroup := newWrapper(Group{})
	_, err := p.GetItem(rolesBucketNATS, group.Name, wOldGroup)
	if err != nil {
		if errors.Is(err, ErrKeyNotFound) {
			return util.NewRecordNotFoundError(fmt.Sprintf("group %q does not exist", group.Name))
		}
		return err
	}
	oldGroup := wOldGroup.Get().(Group)
	for idx := range oldGroup.VirtualFolders {
		if err = p.removeRelationFromFolderMapping(oldGroup.VirtualFolders[idx], "", oldGroup.Name); err != nil {
			return err
		}
	}
	sort.Slice(group.VirtualFolders, func(i, j int) bool {
		return group.VirtualFolders[i].Name < group.VirtualFolders[j].Name
	})
	for idx := range group.VirtualFolders {
		if err = p.addRelationToFolderMapping(group.VirtualFolders[idx].Name, nil, group); err != nil {
			return err
		}
	}
	group.ID = oldGroup.ID
	group.CreatedAt = oldGroup.CreatedAt
	group.Users = oldGroup.Users
	group.Admins = oldGroup.Admins
	group.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
	wOldGroup.Set(*group)
	return p.UpdateItem(rolesBucketNATS, group.Name, wOldGroup)
}

func (p *NATSProvider) deleteGroup(group Group) error {
	wOldGroup := newWrapper(Group{})
	_, err := p.GetItem(rolesBucketNATS, group.Name, wOldGroup)
	if err != nil {
		if errors.Is(err, ErrKeyNotFound) {
			return util.NewRecordNotFoundError(fmt.Sprintf("group %q does not exist", group.Name))
		}
		return err
	}
	oldGroup := wOldGroup.Get().(Group)
	if len(oldGroup.Users) > 0 {
		return util.NewValidationError(fmt.Sprintf("the group %q is referenced, it cannot be removed", oldGroup.Name))
	}
	if len(oldGroup.VirtualFolders) > 0 {
		for idx := range oldGroup.VirtualFolders {
			if err = p.removeRelationFromFolderMapping(oldGroup.VirtualFolders[idx], "", oldGroup.Name); err != nil {
				return err
			}
		}
	}

	if len(oldGroup.Admins) > 0 {
		for idx := range oldGroup.Admins {
			if err = p.removeGroupFromAdminMapping(oldGroup.Name, oldGroup.Admins[idx]); err != nil {
				return err
			}
		}
	}
	return p.DeleteItem(rolesBucketNATS, group.Name)
}

func (p *NATSProvider) dumpGroups() ([]Group, error) {
	groups := make([]Group, 0, 50)
	keys, err := p.ListItems(rolesBucketNATS)
	if err != nil {
		return nil, err
	}
	for _, key := range keys {
		wGroup := newWrapper(Group{})
		_, err := p.GetItem(rolesBucketNATS, key, wGroup)
		if err != nil {
			continue
		}
		group, err := p.joinGroupAndFolders(wGroup.Get().(Group))
		if err != nil {
			return nil, err
		}
		groups = append(groups, group)
	}
	return groups, nil
}

func (p *NATSProvider) apiKeyExists(keyID string) (APIKey, error) {
	wAPIKey := newWrapper(APIKey{})
	_, err := p.GetItem(apiKeysBucketNATS, keyID, wAPIKey)
	if err != nil {
		if errors.Is(err, ErrKeyNotFound) {
			return APIKey{}, util.NewRecordNotFoundError(fmt.Sprintf("API key %v does not exist", keyID))
		}
		return APIKey{}, err
	}
	return wAPIKey.Get().(APIKey), nil
}

func (p *NATSProvider) updateAPIKey(apiKey *APIKey) error {
	if err := apiKey.validate(); err != nil {
		return err
	}
	wOldAPIKey := newWrapper(APIKey{})
	_, err := p.GetItem(apiKeysBucketNATS, apiKey.KeyID, wOldAPIKey)
	if err != nil {
		if errors.Is(err, ErrKeyNotFound) {
			return util.NewRecordNotFoundError(fmt.Sprintf("API key %v does not exist", apiKey.KeyID))
		}
		return err
	}
	oldAPIKey := wOldAPIKey.Get().(APIKey)
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
	wOldAPIKey.Set(*apiKey)
	return p.UpdateItem(apiKeysBucketNATS, apiKey.KeyID, wOldAPIKey)
}

func (p *NATSProvider) deleteAPIKey(apiKey APIKey) error {
	_, err := p.GetItem(apiKeysBucketNATS, apiKey.KeyID, newWrapper(APIKey{}))
	if err != nil {
		if errors.Is(err, ErrKeyNotFound) {
			return util.NewRecordNotFoundError(fmt.Sprintf("API key %v does not exist", apiKey.KeyID))
		}
		return err
	}
	return p.DeleteItem(apiKeysBucketNATS, apiKey.KeyID)
}

func (p *NATSProvider) getAPIKeys(limit int, offset int, order string) ([]APIKey, error) {
	keys, err := p.ListItems(apiKeysBucketNATS)
	if err != nil {
		return nil, err
	}
	if order == OrderDESC {
		sort.Sort(sort.Reverse(sort.StringSlice(keys)))
	} else {
		sort.Strings(keys)
	}
	apiKeys := make([]APIKey, 0, limit)
	if offset >= len(keys) {
		return apiKeys, nil
	}
	end := offset + limit
	if end > len(keys) {
		end = len(keys)
	}
	for _, key := range keys[offset:end] {
		wAPIKey := newWrapper(APIKey{})
		_, err := p.GetItem(apiKeysBucketNATS, key, wAPIKey)
		if err != nil {
			continue
		}
		apiKey := wAPIKey.Get().(APIKey)
		apiKey.HideConfidentialData()
		apiKeys = append(apiKeys, apiKey)
	}
	return apiKeys, nil
}

func (p *NATSProvider) dumpAPIKeys() ([]APIKey, error) {
	apiKeys := make([]APIKey, 0, 30)
	keys, err := p.ListItems(apiKeysBucketNATS)
	if err != nil {
		return nil, err
	}
	for _, key := range keys {
		wAPIKey := newWrapper(APIKey{})
		_, err := p.GetItem(apiKeysBucketNATS, key, wAPIKey)
		if err != nil {
			continue
		}
		apiKeys = append(apiKeys, wAPIKey.Get().(APIKey))
	}
	return apiKeys, nil
}

func (p *NATSProvider) shareExists(shareID, username string) (Share, error) {
	wShare := newWrapper(Share{})
	_, err := p.GetItem(sharesBucketNATS, shareID, wShare)
	if err != nil {
		if errors.Is(err, ErrKeyNotFound) {
			return Share{}, util.NewRecordNotFoundError(fmt.Sprintf("Share %v does not exist", shareID))
		}
		return Share{}, err
	}
	share := wShare.Get().(Share)
	if username != "" && share.Username != username {
		return Share{}, util.NewRecordNotFoundError(fmt.Sprintf("Share %v does not exist", shareID))
	}
	return share, nil
}

func (p *NATSProvider) addShare(share *Share) error {
	if err := share.validate(); err != nil {
		return err
	}
	_, err := p.GetItem(sharesBucketNATS, share.ShareID, newWrapper(Share{}))
	if err == nil {
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
	wShare := newWrapper(Share{})
	wShare.Set(*share)
	_, err = p.CreateItem(sharesBucketNATS, share.ShareID, wShare)
	return err
}

func (p *NATSProvider) addAPIKey(apiKey *APIKey) error {
	if err := apiKey.validate(); err != nil {
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
	wAPIKey := newWrapper(APIKey{})
	wAPIKey.Set(*apiKey)
	_, err := p.GetItem(apiKeysBucketNATS, apiKey.KeyID, wAPIKey)
	if err == nil {
		return p.UpdateItem(apiKeysBucketNATS, apiKey.KeyID, wAPIKey)
	}
	_, err = p.CreateItem(apiKeysBucketNATS, apiKey.KeyID, wAPIKey)
	return err
}

func (p *NATSProvider) getShares(limit int, offset int, order, username string) ([]Share, error) {
	shares := make([]Share, 0, limit)
	keys, err := p.ListItems(sharesBucketNATS)
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
		wShare := newWrapper(Share{})
		_, err := p.GetItem(sharesBucketNATS, key, wShare)
		if err != nil {
			continue
		}
		share := wShare.Get().(Share)
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
	keys, err := p.ListItems(sharesBucketNATS)
	if err != nil {
		return nil, fmt.Errorf("unable to list shares: %w", err)
	}
	for _, key := range keys {
		wShare := newWrapper(Share{})
		_, err := p.GetItem(sharesBucketNATS, key, wShare)
		if err != nil {
			continue
		}
		shares = append(shares, wShare.Get().(Share))
	}
	return shares, nil
}

func (p *NATSProvider) updateShareLastUse(shareID string, numTokens int) error {
	wShare := newWrapper(Share{})
	_, err := p.GetItem(sharesBucketNATS, shareID, wShare)
	if err != nil {
		if errors.Is(err, ErrKeyNotFound) {
			return util.NewRecordNotFoundError(fmt.Sprintf("share %q does not exist, unable to update last use", shareID))
		}
		return fmt.Errorf("unable to get share %v: %w", shareID, err)
	}
	share := wShare.Get().(Share)
	share.LastUseAt = util.GetTimeAsMsSinceEpoch(time.Now())
	share.UsedTokens += numTokens
	wShare.Set(share)
	if err := p.UpdateItem(sharesBucketNATS, shareID, wShare); err != nil {
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
	wOldShare := newWrapper(Share{})
	_, err := p.GetItem(sharesBucketNATS, share.ShareID, wOldShare)
	if err != nil {
		if errors.Is(err, ErrKeyNotFound) {
			return util.NewRecordNotFoundError(fmt.Sprintf("Share %v does not exist", share.ShareID))
		}
		return fmt.Errorf("unable to get share %v: %w", share.ShareID, err)
	}
	oldShare := wOldShare.Get().(Share)
	if oldShare.Username != share.Username {
		return util.NewRecordNotFoundError(fmt.Sprintf("Share %v does not exist for user %v", share.ShareID, share.Username))
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
	wOldShare.Set(*share)
	return p.UpdateItem(sharesBucketNATS, share.ShareID, wOldShare)
}

func (p *NATSProvider) deleteShare(share Share) error {
	wShare := newWrapper(Share{})
	_, err := p.GetItem(sharesBucketNATS, share.ShareID, wShare)
	if err != nil {
		if errors.Is(err, ErrKeyNotFound) {
			return util.NewRecordNotFoundError(fmt.Sprintf("Share %v does not exist", share.ShareID))
		}
		return fmt.Errorf("unable to get share %v: %w", share.ShareID, err)
	}
	oldShare := wShare.Get().(Share)
	if oldShare.Username != share.Username {
		return util.NewRecordNotFoundError(fmt.Sprintf("Share %v does not exist for user %v",
			share.ShareID, share.Username))
	}
	return p.DeleteItem(sharesBucketNATS, share.ShareID)
}

func (p *NATSProvider) dumpEventActions() ([]BaseEventAction, error) {
	actions := make([]BaseEventAction, 0, 50)
	keys, err := p.ListItems(actionsBucketNATS)
	if err != nil && errors.Is(err, ErrKeyNotFound) {
		return nil, err
	}
	for _, key := range keys {
		wAction := newWrapper(BaseEventAction{})
		_, err := p.GetItem(actionsBucketNATS, key, wAction)
		if err != nil {
			continue
		}
		actions = append(actions, wAction.Get().(BaseEventAction))
	}
	return actions, nil
}

func (p *NATSProvider) eventActionExists(name string) (BaseEventAction, error) {
	wAction := newWrapper(BaseEventAction{})
	_, err := p.GetItem(actionsBucketNATS, name, wAction)
	if err != nil && errors.Is(err, ErrKeyNotFound) {
		return BaseEventAction{}, util.NewRecordNotFoundError(fmt.Sprintf("action %q does not exist", name))
	}
	return wAction.Get().(BaseEventAction), nil
}

func (p *NATSProvider) addEventAction(action *BaseEventAction) error {
	if err := action.validate(); err != nil {
		return err
	}
	wAction := newWrapper(BaseEventAction{})
	if _, err := p.GetItem(actionsBucketNATS, action.Name, wAction); err == nil {
		return util.NewI18nError(fmt.Errorf("%w: event action %q already exists", ErrDuplicatedKey, action.Name), util.I18nErrorDuplicatedName)
	}
	action.ID = time.Now().UnixNano()
	action.Rules = nil
	wAction.Set(*action)
	_, err := p.CreateItem(actionsBucketNATS, action.Name, wAction)
	return err
}

func (p *NATSProvider) updateEventAction(action *BaseEventAction) error {
	if err := action.validate(); err != nil {
		return err
	}
	wOldAction := newWrapper(BaseEventAction{})
	_, err := p.GetItem(actionsBucketNATS, action.Name, wOldAction)
	if err != nil && errors.Is(err, ErrKeyNotFound) {
		return util.NewRecordNotFoundError(fmt.Sprintf("event action %s does not exist", action.Name))
	}
	oldAction := wOldAction.Get().(BaseEventAction)
	action.ID = oldAction.ID
	action.Name = oldAction.Name
	action.Rules = nil
	if len(oldAction.Rules) > 0 {
		var relatedRules []string
		for _, ruleName := range oldAction.Rules {
			wRule := newWrapper(EventRule{})
			_, err := p.GetItem(rolesBucketNATS, ruleName, wRule)
			if err == nil {
				relatedRules = append(relatedRules, ruleName)
				rule := wRule.Get().(EventRule)
				rule.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
				wRule.Set(rule)
				if err = p.UpdateItem(rolesBucketNATS, rule.Name, wRule); err != nil {
					return err
				}
				setLastRuleUpdate()
			}
		}
		action.Rules = relatedRules
	}
	wOldAction.Set(*action)
	return p.UpdateItem(actionsBucketNATS, action.Name, wOldAction)
}

func (p *NATSProvider) deleteEventAction(action BaseEventAction) error {
	wOldAction := newWrapper(BaseEventAction{})
	_, err := p.GetItem(actionsBucketNATS, action.Name, wOldAction)
	if err != nil && errors.Is(err, ErrKeyNotFound) {
		return util.NewRecordNotFoundError(fmt.Sprintf("action %s does not exist", action.Name))
	}
	oldAction := wOldAction.Get().(BaseEventAction)
	if len(oldAction.Rules) > 0 {
		return util.NewValidationError(fmt.Sprintf("action %s is referenced, it cannot be removed", oldAction.Name))
	}
	return p.DeleteItem(actionsBucketNATS, action.Name)
}

func (p *NATSProvider) getEventRules(limit, offset int, order string) ([]EventRule, error) {
	if limit <= 0 {
		return nil, nil
	}
	rules := make([]EventRule, 0, limit)
	keys, err := p.ListItems(rolesBucketNATS)
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
		wEvent := newWrapper(EventRule{})
		_, err := p.GetItem(rolesBucketNATS, key, wEvent)
		if err != nil {
			continue
		}

		rule, err := p.joinRuleAndActions(wEvent.Get().(EventRule))
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
	keys, err := p.ListItems(rolesBucketNATS)
	if err != nil {
		return nil, err
	}
	for _, key := range keys {
		wEvent := newWrapper(EventRule{})
		_, err := p.GetItem(rolesBucketNATS, key, wEvent)
		if err != nil {
			continue
		}
		rule, err := p.joinRuleAndActions(wEvent.Get().(EventRule))
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
	keys, err := p.ListItems(rolesBucketNATS)
	if err != nil {
		return nil, err
	}
	for _, key := range keys {
		wRule := newWrapper(EventRule{})
		_, err := p.GetItem(rolesBucketNATS, key, wRule)
		if err != nil {
			continue
		}
		rule := wRule.Get().(EventRule)
		if rule.UpdatedAt < after {
			continue
		}
		var actions []EventAction
		for idx := range rule.Actions {
			action := &rule.Actions[idx]
			wBaseAction := newWrapper(BaseEventAction{})
			_, err := p.GetItem(actionsBucketNATS, action.Name, wBaseAction)
			if err != nil {
				continue
			}
			baseAction := wBaseAction.Get().(BaseEventAction)
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
	wRule := newWrapper(EventRule{})
	_, err := p.GetItem(rolesBucketNATS, name, wRule)
	if err != nil && errors.Is(err, ErrKeyNotFound) {
		return EventRule{}, util.NewRecordNotFoundError(fmt.Sprintf("event rule %q does not exist", name))
	}
	return p.joinRuleAndActions(wRule.Get().(EventRule))
}

func (p *NATSProvider) addEventRule(rule *EventRule) error {
	if err := rule.validate(); err != nil {
		return err
	}
	wRule := newWrapper(EventRule{})
	_, err := p.GetItem(rolesBucketNATS, rule.Name, wRule)
	if err == nil {
		return util.NewI18nError(fmt.Errorf("%w: event rule %q already exists", ErrDuplicatedKey, rule.Name), util.I18nErrorDuplicatedName)
	}
	rule.ID = time.Now().UnixNano()
	rule.CreatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
	rule.UpdatedAt = rule.CreatedAt
	for idx := range rule.Actions {
		if err = p.addRuleToActionMapping(rule.Name, rule.Actions[idx].Name); err != nil {
			return err
		}
	}
	sort.Slice(rule.Actions, func(i, j int) bool {
		return rule.Actions[i].Order < rule.Actions[j].Order
	})
	wRule.Set(*rule)
	if _, err = p.CreateItem(rolesBucketNATS, rule.Name, wRule); err == nil {
		setLastRuleUpdate()
	}
	return err
}

func (p *NATSProvider) updateEventRule(rule *EventRule) error {
	if err := rule.validate(); err != nil {
		return err
	}
	wOldRule := newWrapper(EventRule{})
	_, err := p.GetItem(rolesBucketNATS, rule.Name, wOldRule)
	if err != nil && errors.Is(err, ErrKeyNotFound) {
		return util.NewRecordNotFoundError(fmt.Sprintf("event rule %q does not exist", rule.Name))
	}
	oldRule := wOldRule.Get().(EventRule)
	for idx := range oldRule.Actions {
		if err = p.removeRuleFromActionMapping(rule.Name, oldRule.Actions[idx].Name); err != nil {
			return err
		}
	}
	for idx := range rule.Actions {
		if err = p.addRuleToActionMapping(rule.Name, rule.Actions[idx].Name); err != nil {
			return err
		}
	}
	rule.ID = oldRule.ID
	rule.CreatedAt = oldRule.CreatedAt
	rule.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
	sort.Slice(rule.Actions, func(i, j int) bool {
		return rule.Actions[i].Order < rule.Actions[j].Order
	})
	wOldRule.Set(*rule)
	if err := p.UpdateItem(actionsBucketNATS, rule.Name, wOldRule); err == nil {
		setLastRuleUpdate()
	}
	return err
}

func (p *NATSProvider) deleteEventRule(rule EventRule, _ bool) error {
	wOldRule := newWrapper(EventRule{})
	_, err := p.GetItem(rolesBucketNATS, rule.Name, wOldRule)
	if err != nil && errors.Is(err, ErrKeyNotFound) {
		return util.NewRecordNotFoundError(fmt.Sprintf("event rule %q does not exist", rule.Name))
	}
	oldRule := wOldRule.Get().(EventRule)
	if len(oldRule.Actions) > 0 {
		for idx := range oldRule.Actions {
			if err = p.removeRuleFromActionMapping(rule.Name, oldRule.Actions[idx].Name); err != nil {
				return err
			}
		}
	}
	return p.UpdateItem(rolesBucketNATS, rule.Name, wOldRule)
}

func (p *NATSProvider) roleExists(name string) (Role, error) {
	wRole := newWrapper(Role{})
	_, err := p.GetItem(foldersBucketNATS, name, wRole)
	if err != nil && errors.Is(err, ErrKeyNotFound) {
		return Role{}, util.NewRecordNotFoundError(fmt.Sprintf("role %q does not exist", name))
	}
	return wRole.Get().(Role), nil
}

func (p *NATSProvider) addRole(role *Role) error {
	if err := role.validate(); err != nil {
		return err
	}
	wRole := newWrapper(Role{})
	if _, err := p.GetItem(foldersBucketNATS, role.Name, wRole); err == nil {
		return util.NewI18nError(fmt.Errorf("%w: role %q already exists", ErrDuplicatedKey, role.Name), util.I18nErrorDuplicatedName)
	}
	role.ID = time.Now().UnixNano()
	role.CreatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
	role.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
	role.Users = nil
	role.Admins = nil
	wRole.Set(*role)
	_, err := p.CreateItem(foldersBucketNATS, role.Name, wRole)
	return err
}

func (p *NATSProvider) updateRole(role *Role) error {
	if err := role.validate(); err != nil {
		return err
	}
	wRole := newWrapper(Role{})
	_, err := p.GetItem(foldersBucketNATS, role.Name, wRole)
	if err != nil && errors.Is(err, ErrKeyNotFound) {
		return fmt.Errorf("role %q does not exist", role.Name)
	}
	oldRole := wRole.Get().(Role)
	role.ID = oldRole.ID
	role.CreatedAt = oldRole.CreatedAt
	role.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
	role.Users = oldRole.Users
	role.Admins = oldRole.Admins
	wRole.Set(*role)
	return p.UpdateItem(foldersBucketNATS, role.Name, wRole)
}

func (p *NATSProvider) deleteRole(role Role) error {
	wOldRole := newWrapper(Role{})
	_, err := p.GetItem(foldersBucketNATS, role.Name, wOldRole)
	if err != nil && errors.Is(err, ErrKeyNotFound) {
		return fmt.Errorf("role %q does not exist", role.Name)
	}
	oldRole := wOldRole.Get().(Role)
	if len(oldRole.Admins) > 0 {
		return util.NewValidationError(fmt.Sprintf("the role %q is referenced, it cannot be removed", oldRole.Name))
	}
	if len(oldRole.Users) > 0 {
		for _, username := range oldRole.Users {
			if err := p.removeRoleFromUser(username, oldRole.Name); err != nil {
				return err
			}
		}
	}
	return p.DeleteItem(foldersBucketNATS, role.Name)
}

func (p *NATSProvider) getRoles(limit int, offset int, order string, _ bool) ([]Role, error) {
	roles := make([]Role, 0, limit)
	if limit <= 0 {
		return roles, nil
	}
	keys, err := p.ListItems(foldersBucketNATS)
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
		wRole := newWrapper(Role{})
		_, err := p.GetItem(foldersBucketNATS, key, wRole)
		if err != nil {
			continue
		}
		roles = append(roles, wRole.Get().(Role))
	}
	return roles, nil
}

func (p *NATSProvider) dumpRoles() ([]Role, error) {
	roles := make([]Role, 0, 10)
	keys, err := p.ListItems(foldersBucketNATS)
	if err != nil {
		return nil, err
	}
	for _, key := range keys {
		wRole := newWrapper(Role{})
		_, err := p.GetItem(foldersBucketNATS, key, wRole)
		if err != nil {
			continue
		}
		roles = append(roles, wRole.Get().(Role))
	}
	return roles, nil
}

func (p *NATSProvider) ipListEntryExists(ipOrNet string, listType IPListType) (IPListEntry, error) {
	entry := IPListEntry{
		IPOrNet: ipOrNet,
		Type:    listType,
	}
	wEntry := newWrapper(IPListEntry{})
	_, err := p.GetItem(rolesBucketNATS, entry.getKey(), wEntry)
	if err != nil && errors.Is(err, ErrKeyNotFound) {
		return entry, util.NewRecordNotFoundError(fmt.Sprintf("entry %q does not exist", entry.IPOrNet))
	}
	entry = wEntry.Get().(IPListEntry)
	entry.PrepareForRendering()
	return entry, nil
}

func (p *NATSProvider) addIPListEntry(entry *IPListEntry) error {
	if err := entry.validate(); err != nil {
		return err
	}
	wEntry := newWrapper(IPListEntry{})
	_, err := p.GetItem(rolesBucketNATS, entry.getKey(), wEntry)
	if err == nil {
		return util.NewI18nError(fmt.Errorf("%w: entry %q already exists", ErrDuplicatedKey, entry.IPOrNet), util.I18nErrorDuplicatedIPNet)
	}
	entry.CreatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
	entry.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
	wEntry.Set(*entry)
	_, err = p.CreateItem(rolesBucketNATS, entry.getKey(), wEntry)
	return err
}

func (p *NATSProvider) updateIPListEntry(entry *IPListEntry) error {
	if err := entry.validate(); err != nil {
		return err
	}
	wEntry := newWrapper(IPListEntry{})
	_, err := p.GetItem(rolesBucketNATS, entry.getKey(), wEntry)
	if err != nil && errors.Is(err, ErrKeyNotFound) {
		return fmt.Errorf("entry %q does not exist", entry.IPOrNet)
	}
	entry.CreatedAt = wEntry.Get().(IPListEntry).CreatedAt
	entry.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
	wEntry.Set(*entry)
	return p.UpdateItem(rolesBucketNATS, entry.getKey(), wEntry)
}

func (p *NATSProvider) deleteIPListEntry(entry IPListEntry, _ bool) error {
	wrapperObj := newWrapper(IPListEntry{})
	_, err := p.GetItem(rolesBucketNATS, entry.getKey(), wrapperObj)
	if err != nil && errors.Is(err, ErrKeyNotFound) {
		return fmt.Errorf("entry %q does not exist", entry.IPOrNet)
	}
	return p.UpdateItem(rolesBucketNATS, entry.getKey(), newWrapper(IPListEntry{}))
}

func (p *NATSProvider) getIPListEntries(listType IPListType, filter, from, order string, limit int) ([]IPListEntry, error) {
	entries := make([]IPListEntry, 0, 15)
	keys, err := p.ListItems(rolesBucketNATS)
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
		wEntry := newWrapper(IPListEntry{})
		_, err := p.GetItem(rolesBucketNATS, key, wEntry)
		if err != nil {
			continue
		}
		entry := wEntry.Get().(IPListEntry)
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
	keys, err := p.ListItems(rolesBucketNATS)
	if err != nil {
		return nil, err
	}
	if len(keys) > ipListMemoryLimit {
		providerLog(logger.LevelInfo, "IP lists excluded from dump, too many entries: %d", len(keys))
		return entries, nil
	}
	for _, key := range keys {
		wEntry := newWrapper(IPListEntry{})
		_, err := p.GetItem(rolesBucketNATS, key, wEntry)
		if err != nil {
			continue
		}
		ipEntry := wEntry.Get().(IPListEntry)
		ipEntry.PrepareForRendering()
		entries = append(entries, ipEntry)
	}
	return entries, nil
}

func (p *NATSProvider) countIPListEntries(listType IPListType) (int64, error) {
	keys, err := p.ListItems(rolesBucketNATS)
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
	keys, err := p.ListItems(rolesBucketNATS)
	if err != nil {
		return nil, err
	}
	prefix := fmt.Sprintf("%d_", listType)
	for _, key := range keys {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		wEntry := newWrapper(IPListEntry{})
		_, err := p.GetItem(rolesBucketNATS, key, wEntry)
		if err != nil {
			continue
		}
		ipEntry := wEntry.Get().(IPListEntry)
		if ipEntry.IPType == netType && bytes.Compare(ipBytes, ipEntry.First) >= 0 && bytes.Compare(ipBytes, ipEntry.Last) <= 0 {
			ipEntry.PrepareForRendering()
			entries = append(entries, ipEntry)
		}
	}
	return entries, nil
}

func (p *NATSProvider) getConfigs() (Configs, error) {
	wConfigs := newWrapper(Configs{})
	_, err := p.GetItem(dbMetadataNATS, configsBucketNATS, wConfigs)
	if err != nil && errors.Is(err, ErrKeyNotFound) {
		return Configs{}, nil
	}
	return wConfigs.Get().(Configs), nil
}

func (p *NATSProvider) setConfigs(configs *Configs) error {
	if err := configs.validate(); err != nil {
		return err
	}
	wConfigs := newWrapper(*configs)
	return p.UpdateItem(dbMetadataNATS, string(configsKey), wConfigs)
}

func (p *NATSProvider) setFirstDownloadTimestamp(username string) error {
	wUser := newWrapper(User{})
	_, err := p.GetItem(usersBucketNATS, username, wUser)
	if err != nil && errors.Is(err, ErrKeyNotFound) {
		return util.NewRecordNotFoundError(fmt.Sprintf("username %q does not exist, unable to set download timestamp", username))
	}
	user := wUser.Get().(User)
	if user.FirstDownload > 0 {
		return util.NewGenericError(fmt.Sprintf("first download already set to %v", util.GetTimeFromMsecSinceEpoch(user.FirstDownload)))
	}
	user.FirstDownload = util.GetTimeAsMsSinceEpoch(time.Now())
	wUser.Set(user)
	return p.UpdateItem(usersBucketNATS, username, wUser)
}

func (p *NATSProvider) setFirstUploadTimestamp(username string) error {
	wUser := newWrapper(User{})
	_, err := p.GetItem(usersBucketNATS, username, wUser)
	if err != nil && errors.Is(err, ErrKeyNotFound) {
		return util.NewRecordNotFoundError(fmt.Sprintf("username %q does not exist, unable to set upload timestamp", username))
	}
	user := wUser.Get().(User)
	if user.FirstUpload > 0 {
		return util.NewGenericError(fmt.Sprintf("first upload already set to %v", util.GetTimeFromMsecSinceEpoch(user.FirstUpload)))
	}
	user.FirstUpload = util.GetTimeAsMsSinceEpoch(time.Now())
	wUser.Set(user)
	return p.UpdateItem(usersBucketNATS, username, wUser)
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
		if err := p.PurgeBucket(name); err != nil {
			providerLog(logger.LevelError, "error purging bucket %s", name)
			continue
		}
	}
	return nil
}

func (p *NATSProvider) checkAvailability() error {
	wVersion := newWrapper(schemaVersion{})
	_, err := p.GetItem(dbMetadataNATS, dbVersionKeyNATS, wVersion)
	return err
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
	wAPIKey := newWrapper(APIKey{})
	revision, err := p.GetItem(apiKeysBucketNATS, keyID, wAPIKey)
	if err != nil && errors.Is(err, ErrKeyNotFound) {
		return util.NewRecordNotFoundError(fmt.Sprintf("key %q does not exist, unable to update last use", keyID))
	}
	apiKey := wAPIKey.Get().(APIKey)
	apiKey.LastUseAt = util.GetTimeAsMsSinceEpoch(time.Now())
	wAPIKey.Set(apiKey)
	if revision == 0 {
		_, err := p.PutItem(apiKeysBucketNATS, keyID, wAPIKey)
		return err
	}
	providerLog(logger.LevelDebug, "last use updated for key %q", keyID)
	return p.UpdateItem(apiKeysBucketNATS, keyID, wAPIKey)
}

func (p *NATSProvider) getAdminSignature(username string) (string, error) {
	wAdmin := newWrapper(Admin{})
	_, err := p.GetItem(adminsBucketNATS, username, wAdmin)
	if err != nil && errors.Is(err, ErrKeyNotFound) {
		return "", err
	}
	admin := wAdmin.Get().(Admin)
	return strconv.FormatInt(admin.UpdatedAt, 10), nil
}

func (p *NATSProvider) getUserSignature(username string) (string, error) {
	wUser := newWrapper(User{})
	_, err := p.GetItem(usersBucketNATS, username, wUser)
	if err != nil && errors.Is(err, ErrKeyNotFound) {
		return "", err
	}
	user := wUser.Get().(User)
	return strconv.FormatInt(user.UpdatedAt, 10), nil
}

func (p *NATSProvider) setUpdatedAt(username string) {
	wUser := newWrapper(User{})
	revision, err := p.GetItem(usersBucketNATS, username, wUser)
	if err != nil && errors.Is(err, ErrKeyNotFound) {
		return
	}
	user := wUser.Get().(User)
	user.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
	wUser.Set(user)
	if revision == 0 {
		_, _ = p.PutItem(usersBucketNATS, username, wUser)
	}
	setLastUserUpdate()
	_ = p.UpdateItem(usersBucketNATS, username, wUser)
}

func (p *NATSProvider) updateLastLogin(username string) error {
	wUser := newWrapper(User{})
	revision, err := p.GetItem(usersBucketNATS, username, wUser)
	if err != nil && errors.Is(err, ErrKeyNotFound) {
		return err
	}
	user := wUser.Get().(User)
	user.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
	wUser.Set(user)
	if revision == 0 {
		_, err := p.PutItem(usersBucketNATS, username, wUser)
		return err
	}
	return p.UpdateItem(usersBucketNATS, username, wUser)
}

func (p *NATSProvider) updateAdminLastLogin(username string) error {
	wAdmin := newWrapper(Admin{})
	revision, err := p.GetItem(adminsBucketNATS, username, wAdmin)
	if err != nil && errors.Is(err, ErrKeyNotFound) {
		return err
	}
	admin := wAdmin.Get().(Admin)
	admin.UpdatedAt = util.GetTimeAsMsSinceEpoch(time.Now())
	wAdmin.Set(admin)
	if revision == 0 {
		_, err := p.PutItem(adminsBucketNATS, username, wAdmin)
		return err
	}
	return p.UpdateItem(adminsBucketNATS, username, wAdmin)
}

func (p *NATSProvider) deleteFolderMappings(folder vfs.BaseVirtualFolder) error {
	for _, username := range folder.Users {
		wUser := newWrapper(User{})
		_, err := p.GetItem(usersBucketNATS, username, wUser)
		if err != nil {
			continue
		}
		user := wUser.Get().(User)
		var folders []vfs.VirtualFolder
		for _, userFolder := range user.VirtualFolders {
			if folder.Name != userFolder.Name {
				folders = append(folders, userFolder)
			}
		}
		user.VirtualFolders = folders
		wUser.Set(user)
		if err := p.UpdateItem(usersBucketNATS, user.Username, wUser); err != nil {
			return err
		}
	}
	for _, groupname := range folder.Groups {
		wGroup := newWrapper(Group{})
		_, err := p.GetItem(rolesBucketNATS, groupname, wGroup)
		if err != nil {
			continue
		}
		group := wGroup.Get().(Group)
		var folders []vfs.VirtualFolder
		for _, groupFolder := range group.VirtualFolders {
			if folder.Name != groupFolder.Name {
				folders = append(folders, groupFolder)
			}
		}
		group.VirtualFolders = folders
		wGroup.Set(group)
		if err := p.UpdateItem(rolesBucketNATS, group.Name, wGroup); err != nil {
			return err
		}
	}
	return nil
}

func (p *NATSProvider) folderExistsInternal(name string) (vfs.BaseVirtualFolder, error) {
	wFolder := newWrapper(vfs.BaseVirtualFolder{})
	_, err := p.GetItem(foldersBucketNATS, name, wFolder)
	if err != nil && errors.Is(err, ErrKeyNotFound) {
		return vfs.BaseVirtualFolder{}, util.NewRecordNotFoundError(fmt.Sprintf("folder %q does not exist", name))
	}
	return wFolder.Get().(vfs.BaseVirtualFolder), err
}

func (p *NATSProvider) joinRuleAndActions(rule EventRule) (EventRule, error) {
	var actions []EventAction
	for idx := range rule.Actions {
		action := &rule.Actions[idx]
		wBaseAction := newWrapper(BaseEventAction{})
		_, err := p.GetItem(actionsBucketNATS, action.Name, wBaseAction)
		if err != nil {
			continue
		}
		baseAction := wBaseAction.Get().(BaseEventAction)
		baseAction.Options.SetEmptySecretsIfNil()
		action.BaseEventAction = baseAction
		actions = append(actions, *action)
	}
	rule.Actions = actions
	return rule, nil
}

func (p *NATSProvider) joinGroupAndFolders(group Group) (Group, error) {
	if len(group.VirtualFolders) > 0 {
		var folders []vfs.VirtualFolder
		for idx := range group.VirtualFolders {
			folder := &group.VirtualFolders[idx]
			baseFolder, err := p.folderExistsInternal(folder.Name)
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

func (p *NATSProvider) joinUserAndFolders(user User) (User, error) {
	if len(user.VirtualFolders) > 0 {
		var folders []vfs.VirtualFolder
		for idx := range user.VirtualFolders {
			folder := &user.VirtualFolders[idx]
			baseFolder, err := p.folderExistsInternal(folder.Name)
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

func (p *NATSProvider) groupExistsInternal(name string) (Group, error) {
	wGroup := newWrapper(Group{})
	_, err := p.GetItem(rolesBucketNATS, name, wGroup)
	if err != nil && errors.Is(err, ErrKeyNotFound) {
		return Group{}, util.NewRecordNotFoundError(fmt.Sprintf("group %q does not exist", name))
	}
	return wGroup.Get().(Group), nil
}

func (p *NATSProvider) addFolderInternal(folder vfs.BaseVirtualFolder) error {
	folder.ID = time.Now().UnixNano()
	wFolder := newWrapper(folder)
	_, err := p.CreateItem(foldersBucketNATS, folder.Name, wFolder)
	return err
}

func (p *NATSProvider) removeRoleFromUser(username, role string) error {
	wUser := newWrapper(User{})
	_, err := p.GetItem(usersBucketNATS, username, wUser)
	if err != nil && errors.Is(err, ErrKeyNotFound) {
		providerLog(logger.LevelWarn, "user %q does not exist, cannot remove role %q", username, role)
		return nil
	}
	user := wUser.Get().(User)
	if user.Role == role {
		user.Role = ""
		wUser.Set(user)
		return p.UpdateItem(usersBucketNATS, user.Username, wUser)
	}
	providerLog(logger.LevelError, "user %q does not have the expected role %q, actual %q", username, role, user.Role)
	return nil
}

func (p *NATSProvider) addAdminToRole(username, roleName string) error {
	if roleName == "" {
		return nil
	}
	wRole := newWrapper(Role{})
	_, err := p.GetItem(rolesBucketNATS, roleName, wRole)
	if err != nil && errors.Is(err, ErrKeyNotFound) {
		return fmt.Errorf("%w: role %q does not exist", ErrForeignKeyViolated, roleName)
	}
	role := wRole.Get().(Role)
	if !slices.Contains(role.Admins, username) {
		role.Admins = append(role.Admins, username)
		wRole.Set(role)
		return p.UpdateItem(rolesBucketNATS, role.Name, wRole)
	}
	return nil
}

func (p *NATSProvider) removeAdminFromRole(username, roleName string) error {
	if roleName == "" {
		return nil
	}
	wRole := newWrapper(Role{})
	_, err := p.GetItem(rolesBucketNATS, roleName, wRole)
	if err != nil && errors.Is(err, ErrKeyNotFound) {
		providerLog(logger.LevelWarn, "role %q does not exist, cannot remove admin %q", roleName, username)
		return nil
	}
	role := wRole.Get().(Role)
	if slices.Contains(role.Admins, username) {
		var admins []string
		for _, admin := range role.Admins {
			if admin != username {
				admins = append(admins, admin)
			}
		}
		role.Admins = util.RemoveDuplicates(admins, false)
		wRole.Set(role)
		return p.UpdateItem(rolesBucketNATS, role.Name, wRole)
	}
	return nil
}

func (p *NATSProvider) addUserToRole(username, roleName string) error {
	if roleName == "" {
		return nil
	}
	wRole := newWrapper(Role{})
	_, err := p.GetItem(rolesBucketNATS, roleName, wRole)
	if err != nil && errors.Is(err, ErrKeyNotFound) {
		return fmt.Errorf("%w: role %q does not exist", ErrForeignKeyViolated, roleName)
	}
	role := wRole.Get().(Role)
	if !slices.Contains(role.Users, username) {
		role.Users = append(role.Users, username)
		wRole.Set(role)
		return p.UpdateItem(rolesBucketNATS, role.Name, wRole)
	}
	return nil
}

func (p *NATSProvider) removeUserFromRole(username, roleName string) error {
	if roleName == "" {
		return nil
	}
	wRole := newWrapper(Role{})
	_, err := p.GetItem(rolesBucketNATS, roleName, wRole)
	if err != nil && errors.Is(err, ErrKeyNotFound) {
		providerLog(logger.LevelWarn, "role %q does not exist, cannot remove user %q", roleName, username)
		return nil
	}
	role := wRole.Get().(Role)
	if slices.Contains(role.Users, username) {
		var users []string
		for _, user := range role.Users {
			if user != username {
				users = append(users, user)
			}
		}
		users = util.RemoveDuplicates(users, false)
		role.Users = users
		wRole.Set(role)
		return p.UpdateItem(rolesBucketNATS, role.Name, wRole)
	}
	return nil
}

func (p *NATSProvider) addRuleToActionMapping(ruleName, actionName string) error {
	wAction := newWrapper(BaseEventAction{})
	_, err := p.GetItem(actionsBucketNATS, actionName, wAction)
	if err != nil && errors.Is(err, ErrKeyNotFound) {
		return util.NewGenericError(fmt.Sprintf("action %q does not exist", actionName))
	}
	action := wAction.Get().(BaseEventAction)
	if !slices.Contains(action.Rules, ruleName) {
		action.Rules = append(action.Rules, ruleName)
		wAction.Set(action)
		return p.UpdateItem(actionsBucketNATS, action.Name, wAction)
	}
	return nil
}

func (p *NATSProvider) removeRuleFromActionMapping(ruleName, actionName string) error {
	wAction := newWrapper(BaseEventAction{})
	_, err := p.GetItem(actionsBucketNATS, actionName, wAction)
	if err != nil && errors.Is(err, ErrKeyNotFound) {
		providerLog(logger.LevelWarn, "action %q does not exist, cannot remove from mapping", actionName)
		return nil
	}
	action := wAction.Get().(BaseEventAction)
	if slices.Contains(action.Rules, ruleName) {
		var rules []string
		for _, r := range action.Rules {
			if r != ruleName {
				rules = append(rules, r)
			}
		}
		action.Rules = util.RemoveDuplicates(rules, false)
		wAction.Set(action)
		return p.UpdateItem(actionsBucketNATS, action.Name, wAction)
	}
	return nil
}

func (p *NATSProvider) addUserToGroupMapping(username, groupname string) error {
	wGroup := newWrapper(Group{})
	_, err := p.GetItem(groupsBucketNATS, groupname, wGroup)
	if err != nil && errors.Is(err, ErrKeyNotFound) {
		return util.NewGenericError(fmt.Sprintf("group %q does not exist", groupname))
	}
	group := wGroup.Get().(Group)
	if !slices.Contains(group.Users, username) {
		group.Users = append(group.Users, username)
		wGroup.Set(group)
		return p.UpdateItem(groupsBucketNATS, group.Name, wGroup)
	}
	return nil
}

func (p *NATSProvider) removeUserFromGroupMapping(username, groupname string) error {
	wGroup := newWrapper(Group{})
	_, err := p.GetItem(groupsBucketNATS, groupname, wGroup)
	if err != nil && errors.Is(err, ErrKeyNotFound) {
		return util.NewRecordNotFoundError(fmt.Sprintf("group %q does not exist", groupname))
	}
	group := wGroup.Get().(Group)
	users := make([]string, 0)
	for _, u := range group.Users {
		if u != username {
			users = append(users, u)
		}
	}
	group.Users = util.RemoveDuplicates(users, false)
	return p.UpdateItem(groupsBucketNATS, group.Name, wGroup)
}

func (p *NATSProvider) addAdminToGroupMapping(username, groupname string) error {
	wGroup := newWrapper(Group{})
	_, err := p.GetItem(rolesBucketNATS, groupname, wGroup)
	if err != nil && errors.Is(err, ErrKeyNotFound) {
		return util.NewRecordNotFoundError(fmt.Sprintf("group %q does not exist", groupname))
	}
	group := wGroup.Get().(Group)
	if !slices.Contains(group.Admins, username) {
		group.Admins = append(group.Admins, username)
		wGroup.Set(group)
		return p.UpdateItem(rolesBucketNATS, group.Name, wGroup)
	}
	return nil
}

func (p *NATSProvider) removeAdminFromGroupMapping(username, groupname string) error {
	wGroup := newWrapper(Group{})
	_, err := p.GetItem(rolesBucketNATS, groupname, wGroup)
	if err != nil && errors.Is(err, ErrKeyNotFound) {
		return util.NewRecordNotFoundError(fmt.Sprintf("group %q does not exist", groupname))
	}
	group := wGroup.Get().(Group)
	admins := make([]string, 0)
	for _, a := range group.Admins {
		if a != username {
			admins = append(admins, a)
		}
	}
	group.Admins = util.RemoveDuplicates(admins, false)
	wGroup.Set(group)
	return p.UpdateItem(rolesBucketNATS, group.Name, wGroup)
}

func (p *NATSProvider) removeGroupFromAdminMapping(groupName, adminName string) error {
	wAdmin := newWrapper(Admin{})
	_, err := p.GetItem(adminsBucketNATS, adminName, wAdmin)
	if err != nil && errors.Is(err, ErrKeyNotFound) {
		// the admin does not exist so there is no associated group
		return nil
	}
	admin := wAdmin.Get().(Admin)
	var newGroups []AdminGroupMapping
	for _, g := range admin.Groups {
		if g.Name != groupName {
			newGroups = append(newGroups, g)
		}
	}
	admin.Groups = newGroups
	wAdmin.Set(admin)
	return p.UpdateItem(adminsBucketNATS, adminName, wAdmin)
}

func (p *NATSProvider) addRelationToFolderMapping(folderName string, user *User, group *Group) error {
	wFolder := newWrapper(vfs.BaseVirtualFolder{})
	_, err := p.GetItem(foldersBucketNATS, folderName, wFolder)
	if err != nil && errors.Is(err, ErrKeyNotFound) {
		return util.NewGenericError(fmt.Sprintf("folder %q does not exist", folderName))
	}
	folder := wFolder.Get().(vfs.BaseVirtualFolder)
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
	wFolder.Set(folder)
	return p.UpdateItem(foldersBucketNATS, folder.Name, wFolder)
}

func (p *NATSProvider) removeRelationFromFolderMapping(folder vfs.VirtualFolder, username, groupname string) error {
	wFolder := newWrapper(vfs.BaseVirtualFolder{})
	revision, err := p.GetItem(foldersBucketNATS, folder.Name, wFolder)
	if err != nil && errors.Is(err, ErrKeyNotFound) {
		// the folder does not exist, so there is no associated user/group
		return nil
	}
	baseFolder := wFolder.Get().(vfs.BaseVirtualFolder)
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
	wFolder.Set(baseFolder)
	if revision == 0 {
		_, err := p.PutItem(foldersBucketNATS, folder.Name, wFolder)
		return err
	}
	return p.UpdateItem(foldersBucketNATS, folder.Name, wFolder)
}

func (p *NATSProvider) updateUserRelations(user *User, oldUser User) error {
	for idx := range oldUser.VirtualFolders {
		if err := p.removeRelationFromFolderMapping(oldUser.VirtualFolders[idx], oldUser.Username, ""); err != nil {
			return err
		}
	}
	for idx := range oldUser.Groups {
		if err := p.removeUserFromGroupMapping(user.Username, oldUser.Groups[idx].Name); err != nil {
			return err
		}
	}
	if err := p.removeUserFromRole(oldUser.Username, oldUser.Role); err != nil {
		return err
	}
	sort.Slice(user.VirtualFolders, func(i, j int) bool {
		return user.VirtualFolders[i].Name < user.VirtualFolders[j].Name
	})
	for idx := range user.VirtualFolders {
		if err := p.addRelationToFolderMapping(user.VirtualFolders[idx].Name, user, nil); err != nil {
			return err
		}
	}
	sort.Slice(user.Groups, func(i, j int) bool {
		return user.Groups[i].Name < user.Groups[j].Name
	})
	for idx := range user.Groups {
		if err := p.addUserToGroupMapping(user.Username, user.Groups[idx].Name); err != nil {
			return err
		}
	}
	return p.addUserToRole(user.Username, user.Role)
}

func (p *NATSProvider) adminExistsInternal(username string) error {
	wAdmin := newWrapper(Admin{})
	_, err := p.GetItem(adminsBucketNATS, username, wAdmin)
	if err != nil && errors.Is(err, ErrKeyNotFound) {
		return util.NewRecordNotFoundError(fmt.Sprintf("admin %v does not exist", username))
	}
	return nil
}

func (p *NATSProvider) userExistsInternal(username string) error {
	wUser := newWrapper(User{})
	_, err := p.GetItem(usersBucketNATS, username, wUser)
	if err != nil && errors.Is(err, ErrKeyNotFound) {
		return util.NewRecordNotFoundError(fmt.Sprintf("username %q does not exist", username))
	}
	return nil
}

func (p *NATSProvider) deleteRelatedShares(username string) error {
	keys, err := p.ListItems(sharesBucketNATS)
	if err != nil {
		return err
	}
	for _, k := range keys {
		wShare := newWrapper(Share{})
		_, err := p.GetItem(sharesBucketNATS, k, wShare)
		if err != nil && errors.Is(err, ErrKeyNotFound) {
			continue
		}
		share := wShare.Get().(Share)
		if share.Username == username {
			if err := p.DeleteItem(sharesBucketNATS, share.ShareID); err != nil {
				return err
			}
		}
	}
	return nil
}

func (p *NATSProvider) deleteRelatedAPIKey(username string, scope APIKeyScope) error {
	keys, err := p.ListItems(apiKeysBucketNATS)
	if err != nil {
		return err
	}
	for _, k := range keys {
		wAPIKey := newWrapper(APIKey{})
		_, err := p.GetItem(apiKeysBucketNATS, k, wAPIKey)
		if err != nil && errors.Is(err, ErrKeyNotFound) {
			continue
		}
		apiKey := wAPIKey.Get().(APIKey)
		if (scope == APIKeyScopeUser && apiKey.User == username) || (scope == APIKeyScopeAdmin && apiKey.Admin == username) {
			if err := p.DeleteItem(apiKeysBucketNATS, apiKey.KeyID); err != nil {
				return err
			}
		}
	}
	return nil
}

func (p *NATSProvider) getDatabaseVersion() (schemaVersion, error) {
	wVersion := newWrapper(schemaVersion{})
	_, err := p.GetItem(dbMetadataNATS, dbVersionKeyNATS, wVersion)
	if err != nil {
		if errors.Is(err, ErrKeyNotFound) {
			wVersion.Set(schemaVersion{Version: 29})
			if _, err := p.PutItem(dbMetadataNATS, dbVersionKeyNATS, wVersion); err != nil {
				return wVersion.Get().(schemaVersion), err
			}
			return wVersion.Get().(schemaVersion), nil
		}
		return wVersion.Get().(schemaVersion), err
	}
	return wVersion.Get().(schemaVersion), nil
}

func (p *NATSProvider) updateDatabaseVersion(version int) error {
	wVersion := newWrapper(schemaVersion{})
	_, err := p.GetItem(dbMetadataNATS, dbVersionKeyNATS, wVersion)
	if err != nil {
		if errors.Is(err, ErrKeyNotFound) {
			wVersion.Set(schemaVersion{Version: version})
			if _, err := p.PutItem(dbMetadataNATS, dbVersionKeyNATS, wVersion); err != nil {
				return err
			}
			return nil
		}
	}
	wVersion.Set(schemaVersion{Version: version})
	return p.UpdateItem(dbMetadataNATS, dbVersionKeyNATS, wVersion)
}
