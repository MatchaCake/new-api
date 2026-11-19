package model

// Fork-only (抹茶公益站): encrypt channels.key at rest.
//
// With MATCHA_CHANNEL_KEY_ENCRYPTION_KEY unset nothing changes: keys are read
// and written exactly as stored (startup only logs an error if some rows look
// encrypted, i.e. the key was removed after a migration). With it set (32 random bytes, base64 or hex):
//
//   - every write of channels.key stores "enc:v1:" + base64url(nonce|AES-256-GCM
//     ciphertext|tag), with a fresh random 12-byte nonce per write;
//   - every read returns the plaintext; plaintext rows still read as-is;
//   - at startup InitChannelKeyEncryption encrypts every remaining plaintext
//     row in one transaction (idempotent) and refuses to start if any stored
//     ciphertext does not decrypt with the configured key.
//
// MATCHA_CHANNEL_KEY_ENCRYPTION_DECRYPT_ALL=true (with the key still set) is
// the rollback: at startup every row is decrypted back to plaintext in one
// transaction, and new writes stay plaintext. Afterwards both variables can
// be removed.
//
// How the column is covered (see docs/matcha/channel-key-encryption.md):
//   - struct reads/writes (First/Find/Create/Save/Updates(struct)): the GORM
//     serializer on Channel.Key;
//   - map/column writes (Update("key", v), Updates(map{"key": v})): the SET and
//     VALUES clause builders registered by InitChannelKeyEncryption;
//   - the compare-and-swap in UpdateChannelLocked: channelKeyStoredValue;
//   - the exact-key search: channelKeySearchCondition.
// Only the value of channels.key is affected; ChannelInfo holds no secrets.

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql/driver"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"sync"

	"github.com/QuantumNous/new-api/common"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/schema"
)

const (
	ChannelKeyEncryptionKeyEnv        = "MATCHA_CHANNEL_KEY_ENCRYPTION_KEY"
	ChannelKeyEncryptionDecryptAllEnv = "MATCHA_CHANNEL_KEY_ENCRYPTION_DECRYPT_ALL"

	channelKeyCipherPrefix   = "enc:v1:"
	channelKeySerializerName = "matcha_channel_key"
	channelKeyColumn         = "key"
)

// channelKeyAAD binds ciphertexts to this use, so a value encrypted for some
// other purpose with the same key does not decrypt as a channel key.
var channelKeyAAD = []byte("new-api channels.key v1")

var (
	ErrChannelKeyDecrypt   = errors.New("channel key decryption failed: wrong " + ChannelKeyEncryptionKeyEnv + " or corrupted/tampered ciphertext")
	ErrChannelKeyNoKey     = errors.New("channel key is encrypted but " + ChannelKeyEncryptionKeyEnv + " is not set")
	ErrChannelKeyBadFormat = errors.New("channel key ciphertext is malformed")
)

// channelKeyCrypto is the configuration in effect. aead nil means disabled.
type channelKeyCrypto struct {
	aead       cipher.AEAD
	decryptAll bool // rollback mode: decrypt on read, write plaintext
}

var (
	channelKeyCryptoOnce  sync.Once
	channelKeyCryptoMu    sync.RWMutex
	channelKeyCryptoState *channelKeyCrypto
	channelKeyCryptoErr   error
)

func init() {
	schema.RegisterSerializer(channelKeySerializerName, channelKeySerializer{})
}

// currentChannelKeyCrypto loads the configuration from the environment on
// first use, so channel rows read before InitChannelKeyEncryption (e.g. by a
// schema migration) are decrypted too.
func currentChannelKeyCrypto() (*channelKeyCrypto, error) {
	channelKeyCryptoOnce.Do(func() {
		st, err := channelKeyCryptoFromEnv()
		channelKeyCryptoMu.Lock()
		channelKeyCryptoState, channelKeyCryptoErr = st, err
		channelKeyCryptoMu.Unlock()
	})
	channelKeyCryptoMu.RLock()
	defer channelKeyCryptoMu.RUnlock()
	return channelKeyCryptoState, channelKeyCryptoErr
}

// setChannelKeyCrypto replaces the configuration (tests).
func setChannelKeyCrypto(st *channelKeyCrypto) {
	channelKeyCryptoOnce.Do(func() {})
	channelKeyCryptoMu.Lock()
	channelKeyCryptoState, channelKeyCryptoErr = st, nil
	channelKeyCryptoMu.Unlock()
}

func channelKeyCryptoFromEnv() (*channelKeyCrypto, error) {
	raw := strings.TrimSpace(os.Getenv(ChannelKeyEncryptionKeyEnv))
	decryptAll := common.GetEnvOrDefaultBool(ChannelKeyEncryptionDecryptAllEnv, false)
	if raw == "" {
		if decryptAll {
			return nil, fmt.Errorf("%s=true needs %s to decrypt with", ChannelKeyEncryptionDecryptAllEnv, ChannelKeyEncryptionKeyEnv)
		}
		return &channelKeyCrypto{}, nil
	}
	key, err := parseChannelKeyEncryptionKey(raw)
	if err != nil {
		return nil, err
	}
	return newChannelKeyCrypto(key, decryptAll)
}

func newChannelKeyCrypto(key []byte, decryptAll bool) (*channelKeyCrypto, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &channelKeyCrypto{aead: aead, decryptAll: decryptAll}, nil
}

// parseChannelKeyEncryptionKey accepts exactly 32 bytes as 64 hex digits or
// base64 (standard or URL alphabet, padded or not), e.g. `openssl rand -base64 32`.
func parseChannelKeyEncryptionKey(raw string) ([]byte, error) {
	if len(raw) == 64 {
		if b, err := hex.DecodeString(raw); err == nil {
			return b, nil
		}
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(raw); err == nil {
			if len(b) != 32 {
				return nil, fmt.Errorf("%s must decode to 32 bytes, got %d", ChannelKeyEncryptionKeyEnv, len(b))
			}
			return b, nil
		}
	}
	return nil, fmt.Errorf("%s must be 32 random bytes as base64 or 64 hex digits (openssl rand -base64 32)", ChannelKeyEncryptionKeyEnv)
}

func isEncryptedChannelKey(stored string) bool {
	return strings.HasPrefix(stored, channelKeyCipherPrefix)
}

func (c *channelKeyCrypto) enabled() bool { return c != nil && c.aead != nil }

// encryptsWrites reports whether values written now must be encrypted.
func (c *channelKeyCrypto) encryptsWrites() bool { return c.enabled() && !c.decryptAll }

func (c *channelKeyCrypto) encrypt(plain string) (string, error) {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := c.aead.Seal(nonce, nonce, []byte(plain), channelKeyAAD)
	return channelKeyCipherPrefix + base64.RawURLEncoding.EncodeToString(sealed), nil
}

func (c *channelKeyCrypto) decrypt(stored string) (string, error) {
	if !c.enabled() {
		return "", ErrChannelKeyNoKey
	}
	sealed, err := base64.RawURLEncoding.DecodeString(stored[len(channelKeyCipherPrefix):])
	if err != nil || len(sealed) < c.aead.NonceSize()+c.aead.Overhead() {
		return "", ErrChannelKeyBadFormat
	}
	n := c.aead.NonceSize()
	plain, err := c.aead.Open(nil, sealed[:n], sealed[n:], channelKeyAAD)
	if err != nil {
		return "", ErrChannelKeyDecrypt
	}
	return string(plain), nil
}

// channelKeyForStorage converts a plaintext key to the stored form under the
// current configuration. Empty keys stay empty. Everything else is encrypted,
// including input that merely looks like ciphertext: application values are
// always plaintext, so such input reads back verbatim instead of being stored
// raw (where an undecryptable value would stop the next startup). Values
// already in stored form are written only as storedChannelKey.
func channelKeyForStorage(plain string) (string, error) {
	c, err := currentChannelKeyCrypto()
	if err != nil {
		return "", err
	}
	if plain == "" || !c.encryptsWrites() {
		return plain, nil
	}
	return c.encrypt(plain)
}

// channelKeyFromStorage converts a stored value to the plaintext key. With
// encryption not configured every value is returned as stored, as upstream
// does, so a plaintext key that happens to start with the prefix still works.
func channelKeyFromStorage(stored string) (string, error) {
	if !isEncryptedChannelKey(stored) {
		return stored, nil
	}
	c, err := currentChannelKeyCrypto()
	if err != nil {
		return "", err
	}
	if !c.enabled() {
		return stored, nil
	}
	return c.decrypt(stored)
}

// channelKeySerializer is the GORM serializer on Channel.Key.
type channelKeySerializer struct{}

func (channelKeySerializer) Scan(ctx context.Context, field *schema.Field, dst reflect.Value, dbValue any) error {
	var stored string
	switch v := dbValue.(type) {
	case nil:
	case string:
		stored = v
	case []byte:
		stored = string(v)
	default:
		return fmt.Errorf("channel key: unexpected database type %T", dbValue)
	}
	plain, err := channelKeyFromStorage(stored)
	if err != nil {
		return err
	}
	field.ReflectValueOf(ctx, dst).SetString(plain)
	return nil
}

func (channelKeySerializer) Value(_ context.Context, _ *schema.Field, _ reflect.Value, fieldValue any) (any, error) {
	plain, _ := fieldValue.(string)
	return channelKeyForStorage(plain)
}

// storedChannelKey is a value already in stored form; the clause builders
// pass it through unchanged (used by the bulk encrypt/decrypt).
type storedChannelKey string

func (s storedChannelKey) Value() (driver.Value, error) { return string(s), nil }

func isChannelStatement(stmt *gorm.Statement) bool {
	if stmt.Schema != nil {
		return stmt.Schema.ModelType == reflect.TypeOf(Channel{})
	}
	return stmt.Table != "" && stmt.Table == stmt.DB.NamingStrategy.TableName("Channel")
}

// encryptAssignedKey converts a plaintext string written to channels.key.
// Values that are not plain strings (serializer output, storedChannelKey,
// expressions) are left alone.
func encryptAssignedKey(stmt *gorm.Statement, v any) any {
	plain, ok := v.(string)
	if !ok {
		return v
	}
	stored, err := channelKeyForStorage(plain)
	if err != nil {
		_ = stmt.AddError(err)
		return v
	}
	return stored
}

var channelKeyBuildersRegistered sync.Map // *gorm.Config -> true

// RegisterChannelKeyClauseBuilders makes UPDATE ... SET and INSERT ... VALUES
// on channels store channels.key encrypted when it is given as a plain string
// (Update("key", v), Updates(map), Create(map)). Struct writes are already
// covered by the serializer. Safe to call more than once.
func RegisterChannelKeyClauseBuilders(db *gorm.DB) {
	if db == nil {
		return
	}
	if db.ClauseBuilders == nil {
		db.ClauseBuilders = map[string]clause.ClauseBuilder{}
	}
	if _, done := channelKeyBuildersRegistered.LoadOrStore(db.Config, true); done {
		return
	}
	wrap := func(name string, rewrite func(*gorm.Statement, clause.Expression) clause.Expression) {
		prev := db.ClauseBuilders[name]
		db.ClauseBuilders[name] = func(c clause.Clause, builder clause.Builder) {
			if stmt, ok := builder.(*gorm.Statement); ok && c.Expression != nil && isChannelStatement(stmt) {
				c.Expression = rewrite(stmt, c.Expression)
			}
			if prev != nil {
				prev(c, builder)
			} else {
				c.Build(builder)
			}
		}
	}
	wrap("SET", func(stmt *gorm.Statement, expr clause.Expression) clause.Expression {
		set, ok := expr.(clause.Set)
		if !ok {
			return expr
		}
		out := make(clause.Set, len(set))
		copy(out, set)
		for i := range out {
			if out[i].Column.Name == channelKeyColumn {
				out[i].Value = encryptAssignedKey(stmt, out[i].Value)
			}
		}
		return out
	})
	wrap("VALUES", func(stmt *gorm.Statement, expr clause.Expression) clause.Expression {
		values, ok := expr.(clause.Values)
		if !ok {
			return expr
		}
		col := -1
		for i, c := range values.Columns {
			if c.Name == channelKeyColumn {
				col = i
			}
		}
		if col < 0 {
			return expr
		}
		rows := make([][]any, len(values.Values))
		for i, row := range values.Values {
			rows[i] = append([]any(nil), row...)
			if col < len(rows[i]) {
				rows[i][col] = encryptAssignedKey(stmt, rows[i][col])
			}
		}
		values.Values = rows
		return values
	})
}

// channelKeyStoredValue returns the value channels.key holds for a channel
// read with key plain, for compare-and-swap conditions. Without encryption it
// is plain itself; with it, the stored ciphertext is read back raw.
func channelKeyStoredValue(channelID int, plain string) string {
	c, err := currentChannelKeyCrypto()
	if err != nil || !c.enabled() {
		return plain
	}
	var stored []string
	if err := DB.Model(&Channel{}).Where("id = ?", channelID).Pluck(channelKeyColumn, &stored).Error; err != nil || len(stored) != 1 {
		return plain
	}
	return stored[0]
}

// channelKeySearchCondition returns the SQL condition and argument the channel
// search uses for "the key equals keyword". Encrypted keys cannot be compared
// in SQL, so with encryption on the matching channel ids are found in Go.
func channelKeySearchCondition(keyword string) (string, any) {
	c, err := currentChannelKeyCrypto()
	if err != nil || !c.enabled() {
		return commonKeyCol + " = ?", keyword
	}
	ids := []int{}
	if keyword != "" {
		var channels []Channel
		if err := DB.Select("id", channelKeyColumn).Find(&channels).Error; err == nil {
			for _, ch := range channels {
				if ch.Key == keyword {
					ids = append(ids, ch.Id)
				}
			}
		}
	}
	if len(ids) == 0 {
		ids = append(ids, -1) // ids are positive: matches nothing
	}
	return "id IN (?)", ids
}

type rawChannelKeyRow struct {
	Id  int
	Key string
}

func readRawChannelKeys(tx *gorm.DB) ([]rawChannelKeyRow, error) {
	var rows []rawChannelKeyRow
	err := tx.Model(&Channel{}).Select("id", channelKeyColumn).Order("id").Find(&rows).Error
	return rows, err
}

// rewriteChannelKeys rewrites every row's stored key with convert in one
// transaction, each write conditioned on the value read, and checks every
// rewritten row decrypts back to the original plaintext. Any error rolls back
// everything. It returns the number of rows rewritten.
func rewriteChannelKeys(db *gorm.DB, c *channelKeyCrypto, convert func(stored string) (string, bool, error)) (int, error) {
	changed := 0
	err := db.Transaction(func(tx *gorm.DB) error {
		rows, err := readRawChannelKeys(tx)
		if err != nil {
			return err
		}
		for _, row := range rows {
			next, write, err := convert(row.Key)
			if err != nil {
				return fmt.Errorf("channel %d: %w", row.Id, err)
			}
			if !write {
				continue
			}
			result := tx.Model(&Channel{}).
				Where("id = ?", row.Id).
				Where(clause.Eq{Column: clause.Column{Name: channelKeyColumn}, Value: row.Key}).
				Update(channelKeyColumn, storedChannelKey(next))
			if result.Error != nil {
				return fmt.Errorf("channel %d: %w", row.Id, result.Error)
			}
			if result.RowsAffected != 1 {
				return fmt.Errorf("channel %d: key changed during the rewrite", row.Id)
			}
			changed++
		}
		after, err := readRawChannelKeys(tx)
		if err != nil {
			return err
		}
		if len(after) != len(rows) {
			return errors.New("channel count changed during the rewrite")
		}
		for i := range rows {
			before, err := plainChannelKey(c, rows[i].Key)
			if err != nil {
				return fmt.Errorf("channel %d: %w", rows[i].Id, err)
			}
			now, err := plainChannelKey(c, after[i].Key)
			if err != nil {
				return fmt.Errorf("channel %d: %w", after[i].Id, err)
			}
			if after[i].Id != rows[i].Id || now != before {
				return fmt.Errorf("channel %d: key does not round-trip", rows[i].Id)
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return changed, nil
}

func plainChannelKey(c *channelKeyCrypto, stored string) (string, error) {
	if !isEncryptedChannelKey(stored) {
		return stored, nil
	}
	return c.decrypt(stored)
}

// EncryptAllChannelKeys encrypts every plaintext channel key (idempotent).
func EncryptAllChannelKeys(db *gorm.DB) (int, error) {
	c, err := currentChannelKeyCrypto()
	if err != nil {
		return 0, err
	}
	if !c.enabled() {
		return 0, errors.New(ChannelKeyEncryptionKeyEnv + " is not set")
	}
	return rewriteChannelKeys(db, c, func(stored string) (string, bool, error) {
		if stored == "" {
			return stored, false, nil
		}
		if isEncryptedChannelKey(stored) {
			_, err := c.decrypt(stored)
			return stored, false, err
		}
		next, err := c.encrypt(stored)
		return next, err == nil, err
	})
}

// DecryptAllChannelKeys stores every channel key as plaintext again (idempotent).
func DecryptAllChannelKeys(db *gorm.DB) (int, error) {
	c, err := currentChannelKeyCrypto()
	if err != nil {
		return 0, err
	}
	return rewriteChannelKeys(db, c, func(stored string) (string, bool, error) {
		if !isEncryptedChannelKey(stored) {
			return stored, false, nil
		}
		plain, err := c.decrypt(stored)
		return plain, err == nil, err
	})
}

func countEncryptedChannelKeys(db *gorm.DB) (int64, error) {
	var n int64
	err := db.Model(&Channel{}).Where(commonKeyCol+" LIKE ?", channelKeyCipherPrefix+"%").Count(&n).Error
	return n, err
}

// InitChannelKeyEncryption runs once at startup, after InitDB and before the
// channel cache is built. See the file comment for what each setting does.
func InitChannelKeyEncryption() error {
	c, err := currentChannelKeyCrypto()
	if err != nil {
		return err
	}
	RegisterChannelKeyClauseBuilders(DB)
	switch {
	case !c.enabled():
		n, err := countEncryptedChannelKeys(DB)
		if err != nil {
			return err
		}
		if n > 0 {
			// Not fatal: without the key the stored values are used as-is,
			// exactly as upstream would. Requests on these channels will fail.
			common.SysError(fmt.Sprintf("channel key encryption: %d channel keys look encrypted but %s is not set; those channels will not work until it is set (or a plaintext backup is restored)", n, ChannelKeyEncryptionKeyEnv))
		}
		return nil
	case c.decryptAll:
		n, err := DecryptAllChannelKeys(DB)
		if err != nil {
			return fmt.Errorf("decrypting channel keys: %w", err)
		}
		common.SysLog(fmt.Sprintf("channel key encryption: rollback mode, %d keys decrypted to plaintext; new keys are stored as plaintext", n))
		return nil
	default:
		n, err := EncryptAllChannelKeys(DB)
		if err != nil {
			return fmt.Errorf("encrypting channel keys: %w", err)
		}
		total, _ := countEncryptedChannelKeys(DB)
		common.SysLog(fmt.Sprintf("channel key encryption: enabled, %d keys encrypted now, %d stored encrypted in total", n, total))
		return nil
	}
}
