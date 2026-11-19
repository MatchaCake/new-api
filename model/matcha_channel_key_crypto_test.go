package model

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"

	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/schema"
)

func testChannelKeyCrypto(t *testing.T, decryptAll bool) (*channelKeyCrypto, []byte) {
	t.Helper()
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	c, err := newChannelKeyCrypto(key, decryptAll)
	require.NoError(t, err)
	return c, key
}

// useChannelKeyCrypto installs c for the test and restores the previous state.
func useChannelKeyCrypto(t *testing.T, c *channelKeyCrypto) {
	t.Helper()
	prev, prevErr := currentChannelKeyCrypto()
	setChannelKeyCrypto(c)
	t.Cleanup(func() {
		channelKeyCryptoMu.Lock()
		channelKeyCryptoState, channelKeyCryptoErr = prev, prevErr
		channelKeyCryptoMu.Unlock()
	})
}

func TestChannelKeyCipherRoundTrip(t *testing.T) {
	c, _ := testChannelKeyCrypto(t, false)
	for _, plain := range []string{"sk-test-123", "a\nb\nc", `[{"type":"service_account"}]`, "中文密钥", strings.Repeat("x", 10000)} {
		a, err := c.encrypt(plain)
		require.NoError(t, err)
		b, err := c.encrypt(plain)
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(a, "enc:v1:"))
		assert.NotEqual(t, a, b, "every write uses a fresh nonce")
		assert.NotContains(t, a, plain)
		got, err := c.decrypt(a)
		require.NoError(t, err)
		assert.Equal(t, plain, got)
	}
}

func TestChannelKeyDecryptFailsLoudly(t *testing.T) {
	c, _ := testChannelKeyCrypto(t, false)
	other, _ := testChannelKeyCrypto(t, false)
	ct, err := c.encrypt("sk-secret")
	require.NoError(t, err)

	_, err = other.decrypt(ct)
	assert.ErrorIs(t, err, ErrChannelKeyDecrypt, "wrong key")

	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(ct, "enc:v1:"))
	require.NoError(t, err)
	for _, i := range []int{0, 12, len(raw) - 1} { // nonce, ciphertext, tag
		tampered := append([]byte(nil), raw...)
		tampered[i] ^= 0x01
		_, err = c.decrypt("enc:v1:" + base64.RawURLEncoding.EncodeToString(tampered))
		assert.ErrorIs(t, err, ErrChannelKeyDecrypt, "tampered byte %d", i)
	}
	_, err = c.decrypt("enc:v1:" + base64.RawURLEncoding.EncodeToString(raw[:20]))
	assert.ErrorIs(t, err, ErrChannelKeyBadFormat, "truncated")
	_, err = c.decrypt("enc:v1:not base64!!")
	assert.ErrorIs(t, err, ErrChannelKeyBadFormat)

	var disabled *channelKeyCrypto = &channelKeyCrypto{}
	_, err = disabled.decrypt(ct)
	assert.ErrorIs(t, err, ErrChannelKeyNoKey)
}

func TestParseChannelKeyEncryptionKey(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	for _, s := range []string{hex.EncodeToString(key), base64.StdEncoding.EncodeToString(key), base64.RawStdEncoding.EncodeToString(key), base64.URLEncoding.EncodeToString(key), base64.RawURLEncoding.EncodeToString(key)} {
		got, err := parseChannelKeyEncryptionKey(s)
		require.NoError(t, err, s)
		assert.Equal(t, key, got)
	}
	for _, s := range []string{"short", base64.StdEncoding.EncodeToString(key[:16]), hex.EncodeToString(key[:16]), "!!!!"} {
		_, err := parseChannelKeyEncryptionKey(s)
		assert.Error(t, err, s)
	}
}

func TestChannelKeyCryptoFromEnv(t *testing.T) {
	t.Setenv(ChannelKeyEncryptionKeyEnv, "")
	t.Setenv(ChannelKeyEncryptionDecryptAllEnv, "")
	c, err := channelKeyCryptoFromEnv()
	require.NoError(t, err)
	assert.False(t, c.enabled())

	t.Setenv(ChannelKeyEncryptionDecryptAllEnv, "true")
	_, err = channelKeyCryptoFromEnv()
	assert.Error(t, err, "rollback mode without a key")

	t.Setenv(ChannelKeyEncryptionKeyEnv, base64.StdEncoding.EncodeToString(make([]byte, 32)))
	c, err = channelKeyCryptoFromEnv()
	require.NoError(t, err)
	assert.True(t, c.enabled())
	assert.False(t, c.encryptsWrites())

	t.Setenv(ChannelKeyEncryptionDecryptAllEnv, "")
	c, err = channelKeyCryptoFromEnv()
	require.NoError(t, err)
	assert.True(t, c.encryptsWrites())

	t.Setenv(ChannelKeyEncryptionKeyEnv, "not-a-key")
	_, err = channelKeyCryptoFromEnv()
	assert.Error(t, err)
}

func TestChannelKeyStorageHelpers(t *testing.T) {
	c, _ := testChannelKeyCrypto(t, false)
	useChannelKeyCrypto(t, &channelKeyCrypto{})
	got, err := channelKeyForStorage("sk-plain")
	require.NoError(t, err)
	assert.Equal(t, "sk-plain", got, "disabled: stored as-is")
	got, err = channelKeyFromStorage("sk-plain")
	require.NoError(t, err)
	assert.Equal(t, "sk-plain", got)
	got, err = channelKeyFromStorage("enc:v1:looks-like-ciphertext")
	require.NoError(t, err)
	assert.Equal(t, "enc:v1:looks-like-ciphertext", got, "disabled: everything is returned as stored")
	ct, _ := c.encrypt("x")

	setChannelKeyCrypto(c)
	got, err = channelKeyFromStorage("sk-plain")
	require.NoError(t, err)
	assert.Equal(t, "sk-plain", got, "enabled: plaintext still reads")
	got, err = channelKeyForStorage("")
	require.NoError(t, err)
	assert.Equal(t, "", got, "empty key stays empty")
	// Input that looks like ciphertext (even valid ciphertext) is encrypted
	// like any other value and reads back verbatim.
	for _, lookalike := range []string{ct, "enc:v1:garbage"} {
		got, err = channelKeyForStorage(lookalike)
		require.NoError(t, err)
		assert.NotEqual(t, lookalike, got)
		back, err := channelKeyFromStorage(got)
		require.NoError(t, err)
		assert.Equal(t, lookalike, back)
	}
}

// channelKeyTestDB opens a fresh database of the given dialect as DB.
func channelKeyTestDB(t *testing.T, dialect string) *gorm.DB {
	t.Helper()
	var driver gorm.Dialector
	switch dialect {
	case "sqlite":
		driver = sqlite.Open(filepath.Join(t.TempDir(), "channel-key.db"))
	case "mysql":
		dsn := os.Getenv("TEST_MYSQL_DSN")
		if dsn == "" {
			t.Skip("TEST_MYSQL_DSN is not configured")
		}
		driver = mysql.Open(dsn)
	case "postgres":
		dsn := os.Getenv("TEST_POSTGRES_DSN")
		if dsn == "" {
			t.Skip("TEST_POSTGRES_DSN is not configured")
		}
		driver = postgres.Open(dsn)
	}
	prefix := fmt.Sprintf("chkey_%d_", time.Now().UnixNano())
	db, err := gorm.Open(driver, &gorm.Config{NamingStrategy: schema.NamingStrategy{TablePrefix: prefix}})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(4)
	previousDB, previousType, previousMem := DB, common.MainDatabaseType(), common.MemoryCacheEnabled
	DB = db
	common.SetMainDatabaseType(common.DatabaseType(dialect))
	initCol()
	t.Cleanup(func() {
		DB = previousDB
		common.SetMainDatabaseType(previousType)
		common.MemoryCacheEnabled = previousMem
		initCol()
		assert.NoError(t, db.Migrator().DropTable(&Ability{}, &Channel{}))
		assert.NoError(t, sqlDB.Close())
	})
	require.NoError(t, db.AutoMigrate(&Channel{}, &Ability{}))
	RegisterChannelKeyClauseBuilders(db)
	return db
}

func rawChannelKey(t *testing.T, db *gorm.DB, id int) string {
	t.Helper()
	var keys []string
	require.NoError(t, db.Model(&Channel{}).Where("id = ?", id).Pluck("key", &keys).Error)
	require.Len(t, keys, 1)
	return keys[0]
}

func requireStoredEncrypted(t *testing.T, c *channelKeyCrypto, db *gorm.DB, id int, plain string) {
	t.Helper()
	raw := rawChannelKey(t, db, id)
	require.True(t, isEncryptedChannelKey(raw), "channel %d stored as plaintext", id)
	got, err := c.decrypt(raw)
	require.NoError(t, err)
	require.Equal(t, plain, got)
}

func newKeyTestChannel(name, key string) *Channel {
	models, group := "gpt-test", "default"
	return &Channel{Name: name, Key: key, Type: constant.ChannelTypeOpenAI, Status: common.ChannelStatusEnabled, Models: models, Group: group}
}

var channelKeyDialects = []string{"sqlite", "mysql", "postgres"}

func TestChannelKeyDisabledIsUnchanged(t *testing.T) {
	for _, dialect := range channelKeyDialects {
		t.Run(dialect, func(t *testing.T) {
			db := channelKeyTestDB(t, dialect)
			useChannelKeyCrypto(t, &channelKeyCrypto{})
			ch := newKeyTestChannel("plain", "sk-plain-1")
			require.NoError(t, ch.Insert())
			assert.Equal(t, "sk-plain-1", rawChannelKey(t, db, ch.Id))
			require.NoError(t, db.Model(&Channel{}).Where("id = ?", ch.Id).Update("key", "sk-plain-2").Error)
			assert.Equal(t, "sk-plain-2", rawChannelKey(t, db, ch.Id))
			got, err := GetChannelById(ch.Id, true)
			require.NoError(t, err)
			assert.Equal(t, "sk-plain-2", got.Key)
			found, err := SearchChannels("sk-plain-2", "", "", false)
			require.NoError(t, err)
			require.Len(t, found, 1)
			_, err = UpdateChannelLocked(ch.Id, func(c *Channel) error { c.Key = "sk-plain-3"; return nil })
			require.NoError(t, err)
			assert.Equal(t, "sk-plain-3", rawChannelKey(t, db, ch.Id))
			require.NoError(t, InitChannelKeyEncryption())
			assert.Equal(t, "sk-plain-3", rawChannelKey(t, db, ch.Id), "startup leaves plaintext alone")

			// A plaintext key that looks like ciphertext: still starts, still read as stored.
			require.NoError(t, db.Model(&Channel{}).Where("id = ?", ch.Id).Update("key", "enc:v1:odd-but-plain").Error)
			assert.Equal(t, "enc:v1:odd-but-plain", rawChannelKey(t, db, ch.Id))
			require.NoError(t, InitChannelKeyEncryption())
			got, err = GetChannelById(ch.Id, true)
			require.NoError(t, err)
			assert.Equal(t, "enc:v1:odd-but-plain", got.Key)
		})
	}
}

func TestChannelKeyEncryptedReadWritePaths(t *testing.T) {
	for _, dialect := range channelKeyDialects {
		t.Run(dialect, func(t *testing.T) {
			db := channelKeyTestDB(t, dialect)
			c, _ := testChannelKeyCrypto(t, false)
			useChannelKeyCrypto(t, c)

			// Insert (create channel, copy channel)
			ch := newKeyTestChannel("single", "sk-single-1")
			require.NoError(t, ch.Insert())
			assert.Equal(t, "sk-single-1", ch.Key, "caller keeps the plaintext")
			requireStoredEncrypted(t, c, db, ch.Id, "sk-single-1")

			// Batch insert (add channel in batch mode)
			batch := []Channel{*newKeyTestChannel("b1", "sk-b1"), *newKeyTestChannel("b2", "sk-b2")}
			require.NoError(t, BatchInsertChannels(batch))
			var batchRows []Channel
			require.NoError(t, db.Where("name IN ?", []string{"b1", "b2"}).Order("name").Find(&batchRows).Error)
			require.Len(t, batchRows, 2)
			requireStoredEncrypted(t, c, db, batchRows[0].Id, "sk-b1")
			requireStoredEncrypted(t, c, db, batchRows[1].Id, "sk-b2")

			// Multi-key channel: the whole list (newline or JSON) is one ciphertext.
			multi := newKeyTestChannel("multi", "sk-m1\nsk-m2\nsk-m3")
			multi.ChannelInfo = ChannelInfo{IsMultiKey: true, MultiKeySize: 3, MultiKeyMode: constant.MultiKeyModePolling}
			require.NoError(t, multi.Insert())
			requireStoredEncrypted(t, c, db, multi.Id, "sk-m1\nsk-m2\nsk-m3")
			jsonMulti := newKeyTestChannel("vertex", `[{"type":"service_account","private_key":"k1"},{"type":"service_account","private_key":"k2"}]`)
			jsonMulti.ChannelInfo = ChannelInfo{IsMultiKey: true, MultiKeySize: 2}
			require.NoError(t, jsonMulti.Insert())
			gotJSON, err := GetChannelById(jsonMulti.Id, true)
			require.NoError(t, err)
			assert.Len(t, gotJSON.GetKeys(), 2)

			// Read: admin "view key" and test channel load with selectAll.
			got, err := GetChannelById(multi.Id, true)
			require.NoError(t, err)
			assert.Equal(t, []string{"sk-m1", "sk-m2", "sk-m3"}, got.GetKeys())

			// Edit channel (Update omits the key, then reloads it).
			got.Name = "multi-renamed"
			require.NoError(t, got.Update())
			assert.Equal(t, "sk-m1\nsk-m2\nsk-m3", got.Key)
			assert.Equal(t, 3, got.ChannelInfo.MultiKeySize)
			requireStoredEncrypted(t, c, db, multi.Id, "sk-m1\nsk-m2\nsk-m3")

			// Key change through the locked path (edit key, multi-key manage, plugin refresh).
			stored, err := UpdateChannelLocked(ch.Id, func(s *Channel) error {
				assert.Equal(t, "sk-single-1", s.Key)
				s.Key = "sk-single-2"
				return nil
			})
			require.NoError(t, err)
			assert.Equal(t, "sk-single-2", stored.Key)
			requireStoredEncrypted(t, c, db, ch.Id, "sk-single-2")
			// Locked path without a key change: the compare-and-swap must still match.
			_, err = UpdateChannelLocked(ch.Id, func(s *Channel) error { s.Status = common.ChannelStatusManuallyDisabled; return nil })
			require.NoError(t, err)
			requireStoredEncrypted(t, c, db, ch.Id, "sk-single-2")

			// Column writes (Codex credential refresh / usage refresh).
			require.NoError(t, db.Model(&Channel{}).Where("id = ?", ch.Id).Update("key", "sk-single-3").Error)
			requireStoredEncrypted(t, c, db, ch.Id, "sk-single-3")
			require.NoError(t, db.Model(&Channel{}).Where("id = ?", ch.Id).Updates(map[string]any{"key": "sk-single-4", "status": common.ChannelStatusEnabled}).Error)
			requireStoredEncrypted(t, c, db, ch.Id, "sk-single-4")
			require.NoError(t, db.Model(&Channel{Id: ch.Id}).Updates(Channel{Key: "sk-single-4b"}).Error)
			requireStoredEncrypted(t, c, db, ch.Id, "sk-single-4b") // struct update: encrypted once, not twice
			holder := &Channel{Id: ch.Id}
			require.NoError(t, db.Model(holder).Update("key", "sk-single-5").Error)
			assert.Equal(t, "sk-single-5", holder.Key, "the model passed to Update keeps the plaintext")
			requireStoredEncrypted(t, c, db, ch.Id, "sk-single-5")

			// Scheduled plugin result and plugin login write the key with maps too.
			_, err = UpdateScheduledChannelLocked(context.Background(), ch.Id, func(s *Channel) error { s.Key = "sk-single-6"; return nil })
			require.NoError(t, err)
			requireStoredEncrypted(t, c, db, ch.Id, "sk-single-6")
			plugin := newKeyTestChannel("plugin", "cred-1")
			plugin.Type = constant.ChannelTypeTaskPlugin
			require.NoError(t, plugin.Insert())
			require.NoError(t, UpdateTaskPluginChannelLocked(plugin.Id, func(s *Channel, _ []*Channel) error {
				assert.Equal(t, "cred-1", s.Key)
				s.Key = "cred-2"
				return nil
			}))
			requireStoredEncrypted(t, c, db, plugin.Id, "cred-2")

			// Batch edit by tag and status changes never touch the key.
			tag := "t1"
			require.NoError(t, db.Model(&Channel{}).Where("id = ?", ch.Id).Update("tag", tag).Error)
			pr := int64(5)
			require.NoError(t, EditChannelByTag(tag, nil, nil, nil, nil, &pr, nil, nil, nil))
			requireStoredEncrypted(t, c, db, ch.Id, "sk-single-6")
			UpdateChannelStatus(multi.Id, "sk-m2", common.ChannelStatusAutoDisabled, "test")
			requireStoredEncrypted(t, c, db, multi.Id, "sk-m1\nsk-m2\nsk-m3")

			// Search by exact key, list without keys.
			found, err := SearchChannels("sk-single-6", "", "", false)
			require.NoError(t, err)
			require.Len(t, found, 1)
			assert.Equal(t, ch.Id, found[0].Id)
			assert.Empty(t, found[0].Key, "search still omits keys")
			found, err = SearchChannels("sk-nope", "", "", false)
			require.NoError(t, err)
			assert.Empty(t, found)
			found, err = SearchChannels("single", "", "", false)
			require.NoError(t, err)
			assert.Len(t, found, 1, "name search unaffected")
			tags, err := SearchTags("sk-single-6", "", "", false)
			require.NoError(t, err)
			require.Len(t, tags, 1)
			list, err := GetAllChannels(0, 100, false, false)
			require.NoError(t, err)
			for _, l := range list {
				assert.Empty(t, l.Key)
			}

			// Cache: relay selection reads plaintext keys.
			common.MemoryCacheEnabled = true
			InitChannelCache()
			cached, err := CacheGetChannel(ch.Id)
			require.NoError(t, err)
			assert.Equal(t, "sk-single-6", cached.Key)
			cachedMulti, err := CacheGetChannel(multi.Id)
			require.NoError(t, err)
			k, _, apiErr := cachedMulti.GetNextEnabledKey()
			require.Nil(t, apiErr)
			assert.Contains(t, []string{"sk-m1", "sk-m3"}, k, "a plaintext key, and not the disabled one")
			_, err = UpdateChannelLocked(ch.Id, func(s *Channel) error { s.Key = "sk-single-7"; return nil })
			require.NoError(t, err)
			cached, err = CacheGetChannel(ch.Id)
			require.NoError(t, err)
			assert.Equal(t, "sk-single-7", cached.Key, "cache gets the new plaintext")
		})
	}
}

func TestChannelKeyMigrationAndRollback(t *testing.T) {
	for _, dialect := range channelKeyDialects {
		t.Run(dialect, func(t *testing.T) {
			db := channelKeyTestDB(t, dialect)
			useChannelKeyCrypto(t, &channelKeyCrypto{})
			plains := map[string]string{"a": "sk-a", "b": "sk-b1\nsk-b2", "c": `{"json":"cred"}`, "empty": ""}
			ids := map[string]int{}
			for name, key := range plains {
				ch := newKeyTestChannel(name, key)
				require.NoError(t, ch.Insert())
				ids[name] = ch.Id
			}

			c, key := testChannelKeyCrypto(t, false)
			setChannelKeyCrypto(c)
			require.NoError(t, InitChannelKeyEncryption())
			for name, plain := range plains {
				if plain == "" {
					assert.Equal(t, "", rawChannelKey(t, db, ids[name]))
					continue
				}
				requireStoredEncrypted(t, c, db, ids[name], plain)
			}
			before := map[string]string{}
			for name := range plains {
				before[name] = rawChannelKey(t, db, ids[name])
			}
			n, err := EncryptAllChannelKeys(db)
			require.NoError(t, err)
			assert.Equal(t, 0, n, "idempotent")
			for name := range plains {
				assert.Equal(t, before[name], rawChannelKey(t, db, ids[name]), "a rerun rewrites nothing")
			}

			// Wrong key: refuse, change nothing.
			wrong, _ := testChannelKeyCrypto(t, false)
			setChannelKeyCrypto(wrong)
			assert.ErrorIs(t, InitChannelKeyEncryption(), ErrChannelKeyDecrypt)
			for name := range plains {
				assert.Equal(t, before[name], rawChannelKey(t, db, ids[name]))
			}

			// Rollback: same key, decrypt-all mode.
			rollback, err := newChannelKeyCrypto(key, true)
			require.NoError(t, err)
			setChannelKeyCrypto(rollback)
			require.NoError(t, InitChannelKeyEncryption())
			for name, plain := range plains {
				assert.Equal(t, plain, rawChannelKey(t, db, ids[name]))
			}
			n, err = DecryptAllChannelKeys(db)
			require.NoError(t, err)
			assert.Equal(t, 0, n, "idempotent")
			// Rollback mode writes plaintext.
			require.NoError(t, db.Model(&Channel{}).Where("id = ?", ids["a"]).Update("key", "sk-a2").Error)
			assert.Equal(t, "sk-a2", rawChannelKey(t, db, ids["a"]))

			// Then the variables can go away.
			setChannelKeyCrypto(&channelKeyCrypto{})
			require.NoError(t, InitChannelKeyEncryption())
		})
	}
}

func TestChannelKeyMigrationIsAllOrNothing(t *testing.T) {
	for _, dialect := range channelKeyDialects {
		t.Run(dialect, func(t *testing.T) {
			db := channelKeyTestDB(t, dialect)
			c, _ := testChannelKeyCrypto(t, false)
			useChannelKeyCrypto(t, &channelKeyCrypto{})
			first := newKeyTestChannel("first", "sk-first")
			require.NoError(t, first.Insert())
			bad := newKeyTestChannel("bad", "placeholder")
			require.NoError(t, bad.Insert())
			last := newKeyTestChannel("last", "sk-last")
			require.NoError(t, last.Insert())
			ct, _ := c.encrypt("sk-bad")
			tampered := ct[:len(ct)-2] + "AA"
			if tampered == ct {
				tampered = ct[:len(ct)-2] + "BB"
			}
			require.NoError(t, db.Model(&Channel{}).Where("id = ?", bad.Id).Update("key", storedChannelKey(tampered)).Error)

			setChannelKeyCrypto(c)
			_, err := EncryptAllChannelKeys(db)
			require.Error(t, err)
			assert.Equal(t, "sk-first", rawChannelKey(t, db, first.Id), "rolled back")
			assert.Equal(t, "sk-last", rawChannelKey(t, db, last.Id))
			_, err = GetChannelById(bad.Id, true)
			assert.Error(t, err, "a tampered key is an error, not garbage")
			got, err := GetChannelById(first.Id, true)
			require.NoError(t, err)
			assert.Equal(t, "sk-first", got.Key)
		})
	}
}
