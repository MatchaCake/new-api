package controller

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/setting/operation_setting"
	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// matchaBalanceCase describes the account and the single API key that a
// GET /v1/balance request is made with.
type matchaBalanceCase struct {
	userQuota     int
	userUsedQuota int
	token         model.Token
	quotaPerUnit  float64 // defaults to 500000
	price         float64 // top-up price in CNY per USD; 0 means not configured
}

// requestMatchaBalance seeds one user owning one API key and calls the endpoint
// through the real token middleware, so authentication is exercised as deployed.
func requestMatchaBalance(t *testing.T, tc matchaBalanceCase, authorization string) *httptest.ResponseRecorder {
	t.Helper()

	gin.SetMode(gin.TestMode)
	common.SetDatabaseTypes(common.DatabaseTypeSQLite, common.DatabaseTypeSQLite)
	common.RedisEnabled = false
	dsn := fmt.Sprintf("file:%s?mode=memory&cache=shared", strings.NewReplacer("/", "_", " ", "_").Replace(t.Name()))
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	model.DB = db
	t.Cleanup(func() {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	})
	// Initialize production column quoting for the token key lookup.
	t.Setenv("LOG_SQL_DSN", "")
	require.NoError(t, model.InitLogDB())
	require.NoError(t, db.AutoMigrate(&model.User{}, &model.Token{}))

	previousQuotaPerUnit, previousPrice := common.QuotaPerUnit, operation_setting.Price
	t.Cleanup(func() {
		common.QuotaPerUnit, operation_setting.Price = previousQuotaPerUnit, previousPrice
	})
	common.QuotaPerUnit = 500000
	if tc.quotaPerUnit != 0 {
		common.QuotaPerUnit = tc.quotaPerUnit
	}
	operation_setting.Price = tc.price

	user := &model.User{Username: "balance-owner", Password: "placeholder", Role: common.RoleCommonUser, Status: common.UserStatusEnabled, Group: "default", AuthVersion: 1, AffCode: "balance-owner"}
	require.NoError(t, db.Create(user).Error)
	// Written separately so that zero and negative amounts are stored as given.
	require.NoError(t, db.Model(user).Updates(map[string]any{"quota": tc.userQuota, "used_quota": tc.userUsedQuota}).Error)

	token := tc.token
	token.UserId = user.Id
	token.Key = "balancekey1234"
	require.NoError(t, db.Create(&token).Error)
	require.NoError(t, db.Model(&token).Updates(map[string]any{
		"status":                 tc.token.Status,
		"expired_time":           tc.token.ExpiredTime,
		"remain_quota":           tc.token.RemainQuota,
		"unlimited_quota":        tc.token.UnlimitedQuota,
		"allow_user_quota_query": tc.token.AllowUserQuotaQuery,
	}).Error)

	router := gin.New()
	router.GET("/v1/balance", middleware.TokenAuth(), GetMatchaBalance)
	request := httptest.NewRequest(http.MethodGet, "/v1/balance", nil)
	if authorization != "" {
		request.Header.Set("Authorization", authorization)
	}
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	return recorder
}

func TestMatchaBalanceReportsWhatTheKeyCanSpend(t *testing.T) {
	// 6172800 quota is $12.3456 and 2839450 quota is $5.6789 at 500000 quota per dollar.
	accountFigures := []string{"6172800", "12.3456", "2839450", "5.6789"}

	for _, tc := range []struct {
		name string
		matchaBalanceCase
		want        string
		mustNotLeak []string
	}{
		{
			name: "unlimited key that may query the account shows the account balance",
			matchaBalanceCase: matchaBalanceCase{
				userQuota: 6172800, userUsedQuota: 2839450, price: 7,
				token: model.Token{Name: "抹茶画室", Status: common.TokenStatusEnabled, ExpiredTime: -1, UnlimitedQuota: true, AllowUserQuotaQuery: true, UsedQuota: 617250},
			},
			want: `{
				"object": "balance", "currency": "USD",
				"balance": 12.3456, "balance_quota": 6172800,
				"user": {"balance": 12.3456, "used": 5.6789, "balance_quota": 6172800, "used_quota": 2839450, "group": "default"},
				"token": {"name": "抹茶画室", "unlimited": true, "remaining": null, "remaining_quota": null, "used": 1.2345, "used_quota": 617250, "expires_at": null},
				"quota_per_unit": 500000, "cny_per_usd": 7
			}`,
		},
		{
			name: "limited key below the account balance shows only its own remaining amount",
			matchaBalanceCase: matchaBalanceCase{
				userQuota: 6172800, userUsedQuota: 2839450, price: 7,
				token: model.Token{Name: "shared", Status: common.TokenStatusEnabled, ExpiredTime: 1893456000, RemainQuota: 100000, AllowUserQuotaQuery: true, UsedQuota: 25000},
			},
			want: `{
				"object": "balance", "currency": "USD",
				"balance": 0.2, "balance_quota": 100000,
				"user_hidden_reason": "limited_token",
				"token": {"name": "shared", "unlimited": false, "remaining": 0.2, "remaining_quota": 100000, "used": 0.05, "used_quota": 25000, "expires_at": 1893456000},
				"quota_per_unit": 500000, "cny_per_usd": 7
			}`,
			mustNotLeak: accountFigures,
		},
		{
			name: "limited key above the account balance is capped by the account without the account block",
			matchaBalanceCase: matchaBalanceCase{
				userQuota: 6172800, userUsedQuota: 2839450,
				token: model.Token{Name: "shared", Status: common.TokenStatusEnabled, ExpiredTime: -1, RemainQuota: 10000000, AllowUserQuotaQuery: true},
			},
			want: `{
				"object": "balance", "currency": "USD",
				"balance": 12.3456, "balance_quota": 6172800,
				"user_hidden_reason": "limited_token",
				"token": {"name": "shared", "unlimited": false, "remaining": 20, "remaining_quota": 10000000, "used": 0, "used_quota": 0, "expires_at": null},
				"quota_per_unit": 500000
			}`,
			mustNotLeak: []string{"2839450", "5.6789", `"user"`},
		},
		{
			name: "unlimited key with the user quota switch off reveals nothing about the account",
			matchaBalanceCase: matchaBalanceCase{
				userQuota: 6172800, userUsedQuota: 2839450, price: 7,
				token: model.Token{Name: "legacy", Status: common.TokenStatusEnabled, ExpiredTime: -1, UnlimitedQuota: true, UsedQuota: 617250},
			},
			want: `{
				"object": "balance", "currency": "USD",
				"balance": null, "balance_quota": null,
				"user_hidden_reason": "user_quota_query_disabled",
				"token": {"name": "legacy", "unlimited": true, "remaining": null, "remaining_quota": null, "used": 1.2345, "used_quota": 617250, "expires_at": null},
				"quota_per_unit": 500000, "cny_per_usd": 7
			}`,
			mustNotLeak: accountFigures,
		},
		{
			name: "empty account reports zero rather than hiding the balance",
			matchaBalanceCase: matchaBalanceCase{
				token: model.Token{Name: "new", Status: common.TokenStatusEnabled, ExpiredTime: -1, UnlimitedQuota: true, AllowUserQuotaQuery: true},
			},
			want: `{
				"object": "balance", "currency": "USD",
				"balance": 0, "balance_quota": 0,
				"user": {"balance": 0, "used": 0, "balance_quota": 0, "used_quota": 0, "group": "default"},
				"token": {"name": "new", "unlimited": true, "remaining": null, "remaining_quota": null, "used": 0, "used_quota": 0, "expires_at": null},
				"quota_per_unit": 500000
			}`,
		},
		{
			name: "limited key on an empty account can spend nothing",
			matchaBalanceCase: matchaBalanceCase{
				token: model.Token{Name: "shared", Status: common.TokenStatusEnabled, ExpiredTime: -1, RemainQuota: 100000},
			},
			want: `{
				"object": "balance", "currency": "USD",
				"balance": 0, "balance_quota": 0,
				"user_hidden_reason": "limited_token",
				"token": {"name": "shared", "unlimited": false, "remaining": 0.2, "remaining_quota": 100000, "used": 0, "used_quota": 0, "expires_at": null},
				"quota_per_unit": 500000
			}`,
		},
		{
			name: "overdrawn account is not spendable but keeps its real figure",
			matchaBalanceCase: matchaBalanceCase{
				userQuota: -500, userUsedQuota: 1000500,
				token: model.Token{Name: "main", Status: common.TokenStatusEnabled, ExpiredTime: -1, UnlimitedQuota: true, AllowUserQuotaQuery: true},
			},
			want: `{
				"object": "balance", "currency": "USD",
				"balance": 0, "balance_quota": 0,
				"user": {"balance": -0.001, "used": 2.001, "balance_quota": -500, "used_quota": 1000500, "group": "default"},
				"token": {"name": "main", "unlimited": true, "remaining": null, "remaining_quota": null, "used": 0, "used_quota": 0, "expires_at": null},
				"quota_per_unit": 500000
			}`,
		},
		{
			name: "amounts are rounded to six decimals of a dollar",
			matchaBalanceCase: matchaBalanceCase{
				userQuota: 100000, userUsedQuota: 200000, quotaPerUnit: 300000, price: 7.3,
				token: model.Token{Name: "main", Status: common.TokenStatusEnabled, ExpiredTime: -1, UnlimitedQuota: true, AllowUserQuotaQuery: true, UsedQuota: 1},
			},
			want: `{
				"object": "balance", "currency": "USD",
				"balance": 0.333333, "balance_quota": 100000,
				"user": {"balance": 0.333333, "used": 0.666667, "balance_quota": 100000, "used_quota": 200000, "group": "default"},
				"token": {"name": "main", "unlimited": true, "remaining": null, "remaining_quota": null, "used": 0.000003, "used_quota": 1, "expires_at": null},
				"quota_per_unit": 300000, "cny_per_usd": 7.3
			}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recorder := requestMatchaBalance(t, tc.matchaBalanceCase, "Bearer sk-balancekey1234")

			require.Equal(t, http.StatusOK, recorder.Code, recorder.Body.String())
			assert.Equal(t, "no-store", recorder.Header().Get("Cache-Control"))
			assert.JSONEq(t, tc.want, recorder.Body.String())
			for _, secret := range tc.mustNotLeak {
				assert.NotContains(t, recorder.Body.String(), secret)
			}
		})
	}
}

func TestMatchaBalanceRejectsKeysThatCannotCallModels(t *testing.T) {
	usable := model.Token{Name: "main", Status: common.TokenStatusEnabled, ExpiredTime: -1, UnlimitedQuota: true, AllowUserQuotaQuery: true}

	for _, tc := range []struct {
		name          string
		token         model.Token
		authorization string
	}{
		{name: "missing authorization header", token: usable},
		{name: "unknown key", token: usable, authorization: "Bearer sk-doesnotexist"},
		{name: "disabled key", token: model.Token{Name: "off", Status: common.TokenStatusDisabled, ExpiredTime: -1, UnlimitedQuota: true, AllowUserQuotaQuery: true}, authorization: "Bearer sk-balancekey1234"},
		{name: "key past its expiry time", token: model.Token{Name: "old", Status: common.TokenStatusEnabled, ExpiredTime: 1, UnlimitedQuota: true, AllowUserQuotaQuery: true}, authorization: "Bearer sk-balancekey1234"},
		{name: "limited key with nothing left", token: model.Token{Name: "spent", Status: common.TokenStatusEnabled, ExpiredTime: -1, RemainQuota: 0, AllowUserQuotaQuery: true}, authorization: "Bearer sk-balancekey1234"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recorder := requestMatchaBalance(t, matchaBalanceCase{userQuota: 6172800, userUsedQuota: 2839450, token: tc.token}, tc.authorization)

			require.Equal(t, http.StatusUnauthorized, recorder.Code, recorder.Body.String())
			assert.Contains(t, recorder.Body.String(), `"error"`)
			for _, secret := range []string{"balance", "6172800", "2839450"} {
				assert.NotContains(t, recorder.Body.String(), secret)
			}
		})
	}
}
