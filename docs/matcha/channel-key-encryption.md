# Channel key encryption at rest (fork-only)

Upstream new-api stores `channels.key` in plaintext and (as of 2026-11) has no
built-in option to encrypt it; the only upstream attempt, PR #5178, was closed
unmerged. This fork adds it, off by default.

## What it does

| Setting | Behaviour |
|---|---|
| `MATCHA_CHANNEL_KEY_ENCRYPTION_KEY` unset | Exactly as upstream: keys are read and written as stored. At startup the server only logs an error if some rows look encrypted (the key was removed after a migration); those channels then fail until the key is set again. |
| `MATCHA_CHANNEL_KEY_ENCRYPTION_KEY` set | Every write of `channels.key` stores ciphertext; every read returns the plaintext; plaintext rows still work. At startup all remaining plaintext rows are encrypted in one transaction, and the server refuses to start if any stored ciphertext does not decrypt (wrong key, corrupted row). |
| key set **and** `MATCHA_CHANNEL_KEY_ENCRYPTION_DECRYPT_ALL=true` | Rollback: at startup every row is decrypted back to plaintext in one transaction; new writes are plaintext. Afterwards both variables can be removed. |

Nothing else changes: the admin API still takes and returns plaintext keys
(viewing a key still needs the same permission and verification), relaying uses
the decrypted key, the in-memory channel cache holds plaintext as before, and
API clients (e.g. a script that manages channels through `/api/channel`) need no
change.

Format: `enc:v1:` + base64url(12-byte random nonce ‖ AES-256-GCM ciphertext ‖
16-byte tag), additional data `new-api channels.key v1`. A multi-key channel's
whole key list (newline-separated or JSON array) is one ciphertext.
`channel_info` holds only key indexes and statuses, no secrets, and is not
encrypted. With encryption on, every value the application writes is
encrypted, so even a key that itself starts with `enc:v1:` reads back verbatim.
With encryption off every value is used as stored. The one unsupported case: a
plaintext key starting with `enc:v1:` written while encryption is off (or in
rollback mode) makes the next encrypting startup stop with a decryption error,
because it cannot be told apart from a tampered ciphertext; real provider keys
never look like that.

Size: ciphertext is about 4/3 × plaintext + 45 bytes. The column is `text` on
SQLite and PostgreSQL and `longtext` on MySQL (GORM's type for an unsized
string), so no schema change is needed; the serializer does not change the
column type.

## Key

Generate 32 random bytes and keep them in an env file readable only by the
service owner (do **not** put the value in `docker-compose.yml`):

```sh
umask 077
printf 'MATCHA_CHANNEL_KEY_ENCRYPTION_KEY=%s\n' "$(openssl rand -base64 32)" > channel-key.env
```

```yaml
services:
  new-api:
    env_file:
      - ./channel-key.env
```

Accepted formats: 64 hex digits, or base64 (standard or URL alphabet, padded or
not) of exactly 32 bytes. This key is separate from `SESSION_SECRET` and
`CRYPTO_SECRET` (those sign sessions and HMAC cache keys; changing them only
logs users out).

**If the key is lost, the encrypted channel keys cannot be recovered.** Every
channel's key has to be entered again (or a plaintext database backup from
before the migration restored). Back the key file up separately from the
database backups, or at least alongside them in an encrypted backup.

## Migrate

1. Back up the database.
2. Add the env file, restart. The log shows
   `channel key encryption: enabled, N keys encrypted now, M stored encrypted in total`.
   Running it again is a no-op (`0 keys encrypted now`).

Multi-node: every node needs the same key; start one node first.

## Roll back

1. Add `MATCHA_CHANNEL_KEY_ENCRYPTION_DECRYPT_ALL=true` (keep the key), restart.
   Log: `rollback mode, N keys decrypted to plaintext`.
2. Remove both variables, restart.

Rotating the key is the same: roll back with the old key, then migrate with the
new one. Database backups taken while encryption was on need the key that was
in use at the time.

## What it protects against

A leaked database file, dump or backup no longer contains usable upstream
keys. It does **not** protect against anyone who can read the key file or the
server process's environment/memory, i.e. anyone with access to the host
running new-api, and old plaintext backups stay plaintext.

## Every place that touches `channels.key`

Mechanisms (all in `model/matcha_channel_key_crypto.go`):

- **S** – GORM serializer on `Channel.Key` (`serializer:matcha_channel_key`):
  any struct read or write — `First/Find/Create/CreateInBatches/Save/Updates(struct)`.
- **B** – `SET`/`VALUES` clause builders registered at startup: any write of a
  plain string to the `key` column of `channels` through `Update("key", v)`,
  `Updates(map)` or `Create(map)`, including future upstream code.
- **C** – `channelKeyStoredValue`: compare-and-swap against the stored value.
- **Q** – `channelKeySearchCondition`: exact-key search done in Go.

| Path | Code | Covered by |
|---|---|---|
| Create channel (single / batch / multi-to-single), copy channel | `Channel.Insert`, `BatchInsertChannels` (`controller/channel.go` AddChannel, CopyChannel) | S |
| Edit channel (non-key fields) | `Channel.Update` (`Omit("key")`, then reloads) | S (reload) |
| Edit key / multi-key manage (add, delete, enable, disable keys) | `UpdateChannelLocked` (`controller/channel.go`) | B, C (SQLite) |
| Provider plugin credential refresh, OAuth login, scheduled result | `UpdateChannelLocked`, `UpdateTaskPluginChannelLocked`, `UpdateScheduledChannelLocked` (`service/provider_plugin*.go`) | B, C |
| Codex credential refresh and usage refresh | `Update("key", …)` in `service/codex_credential_refresh.go`, `controller/codex_usage.go` | B |
| Codex refresh task listing | `Select("id","name","key",…).Find(&[]*Channel)` | S |
| Other-info / setting / models / status / priority / tag updates | map updates without `key` | not affected |
| Batch edit by tag, enable/disable by tag | `EditChannelByTag` (`Updates(struct)`, key empty so skipped), `Update("status")` | not affected |
| Auto-disable / re-enable, multi-key key status, polling index | `UpdateChannelStatus`, `SaveChannelInfo` (`channel_info` only) | not affected |
| View key (admin, with verification) | `GetChannelById(id, true)` in `controller/channel.go` GetChannelKey | S |
| Channel list / search results | `Omit("key")` | not affected |
| Search by exact key | `SearchChannels`, `SearchTags` | Q |
| Test channel, balance query, model list fetch, upstream model update | `GetChannelById(id, true)` / cached channel | S |
| Relay channel selection, multi-key rotation | channel cache built by `InitChannelCache` (`DB.Find`), `GetNextEnabledKey` | S |
| Cache refresh after key change | `CacheUpdateChannelKey` (plaintext from the caller) | in memory |
| Multi-node cache sync | `SyncTopicChannels` → `InitChannelCache` | S |
| Delete channel / delete disabled | no key read | not affected |
| Midjourney / task polling / responses websocket | cached channel `.Key` | S |
| Bulk migrate / roll back | `EncryptAllChannelKeys`, `DecryptAllChannelKeys` (raw read, conditional write, round-trip check, one transaction) | — |

The inventory was made with a `go/types` scan for every use of the
`model.Channel.Key` field (316 uses, all in-memory on structs loaded through
GORM) plus a search for every query on the channels table and every raw
`key` column reference. No raw SQL reads or writes `channels.key`.

Known difference with encryption on: a database-level unique index on
`channels.key` would no longer detect duplicates (ciphertexts never repeat).
new-api does not create such an index; one upstream controller test adds one
temporarily, so `TestAddChannelRollbackDoesNotReturnIDs` fails only when the
test suite itself is run with the variable set.

Tests: `model/matcha_channel_key_crypto_test.go` (set `TEST_MYSQL_DSN` and
`TEST_POSTGRES_DSN` to include MySQL and PostgreSQL).
