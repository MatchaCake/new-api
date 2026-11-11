package controller

import (
	"errors"
	"math"
	"net/http"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/i18n"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/relaykit/types"
	"github.com/QuantumNous/new-api/setting/operation_setting"
	"github.com/gin-gonic/gin"
)

// Fork-only (抹茶公益站): GET /v1/balance tells an API key how much it can
// still spend. Documented in docs/matcha/balance-api.md.

// Reasons why a response carries no account figures.
const (
	matchaBalanceHiddenLimitedToken  = "limited_token"
	matchaBalanceHiddenQueryDisabled = "user_quota_query_disabled"
)

type matchaBalanceResponse struct {
	Object   string `json:"object"`
	Currency string `json:"currency"`
	// Balance is what this key can spend right now; null when the key has no
	// limit of its own and may not learn the account balance.
	Balance          *float64           `json:"balance"`
	BalanceQuota     *int               `json:"balance_quota"`
	User             *matchaBalanceUser `json:"user,omitempty"`
	UserHiddenReason string             `json:"user_hidden_reason,omitempty"`
	Token            matchaBalanceToken `json:"token"`
	QuotaPerUnit     float64            `json:"quota_per_unit"`
	CNYPerUSD        *float64           `json:"cny_per_usd,omitempty"`
}

type matchaBalanceUser struct {
	Balance      float64 `json:"balance"`
	Used         float64 `json:"used"`
	BalanceQuota int     `json:"balance_quota"`
	UsedQuota    int     `json:"used_quota"`
	Group        string  `json:"group"`
}

type matchaBalanceToken struct {
	Name           string   `json:"name"`
	Unlimited      bool     `json:"unlimited"`
	Remaining      *float64 `json:"remaining"`
	RemainingQuota *int     `json:"remaining_quota"`
	Used           float64  `json:"used"`
	UsedQuota      int      `json:"used_quota"`
	ExpiresAt      *int64   `json:"expires_at"`
}

// matchaQuotaToUSD converts a quota amount to US dollars for display, rounded
// to six decimals: one quota unit is $0.000002 at the default 500000 per dollar.
func matchaQuotaToUSD(quota int) float64 {
	return math.Round(float64(quota)/common.QuotaPerUnit*1e6) / 1e6
}

func writeMatchaBalanceError(c *gin.Context, err error) {
	common.SysError(common.LogText("failed to query balance for user %d: %s", c.GetInt("id"), err.Error()))
	c.JSON(http.StatusInternalServerError, gin.H{
		"error": types.OpenAIError{
			Message: common.TranslateMessage(c, i18n.MsgDatabaseError),
			Type:    "new_api_error",
			Code:    "query_balance_failed",
		},
	})
}

// GetMatchaBalance must run behind middleware.TokenAuth, which authenticates
// the key and loads its owner's quota and group into the request context.
func GetMatchaBalance(c *gin.Context) {
	c.Header("Cache-Control", "no-store")

	// The key cache is the same source the relay charges against.
	token, err := model.GetTokenByKey(c.GetString("token_key"), false)
	if err != nil {
		writeMatchaBalanceError(c, err)
		return
	}
	userQuota, ok := common.GetContextKeyType[int](c, constant.ContextKeyUserQuota)
	if !ok {
		// Reporting a zero balance here would be a wrong answer, not a safe default.
		writeMatchaBalanceError(c, errors.New("user quota is missing from the request context"))
		return
	}

	response := matchaBalanceResponse{
		Object:   "balance",
		Currency: "USD",
		Token: matchaBalanceToken{
			Name:      token.Name,
			Unlimited: token.UnlimitedQuota,
			Used:      matchaQuotaToUSD(token.UsedQuota),
			UsedQuota: token.UsedQuota,
		},
		QuotaPerUnit: common.QuotaPerUnit,
	}
	if token.ExpiredTime > 0 {
		response.Token.ExpiresAt = &token.ExpiredTime
	}
	if price := operation_setting.Price; price > 0 {
		response.CNYPerUSD = &price
	}

	// A limited key is often handed to someone else, and every key has an
	// "allow querying user quota" switch: account figures need both to agree.
	var spendable int
	switch {
	case !token.UnlimitedQuota:
		remaining := matchaQuotaToUSD(token.RemainQuota)
		response.Token.Remaining, response.Token.RemainingQuota = &remaining, &token.RemainQuota
		response.UserHiddenReason = matchaBalanceHiddenLimitedToken
		spendable = min(userQuota, token.RemainQuota)
	case !token.AllowUserQuotaQuery:
		response.UserHiddenReason = matchaBalanceHiddenQueryDisabled
		c.JSON(http.StatusOK, response)
		return
	default:
		userUsedQuota, err := model.GetUserUsedQuota(token.UserId)
		if err != nil {
			writeMatchaBalanceError(c, err)
			return
		}
		response.User = &matchaBalanceUser{
			Balance:      matchaQuotaToUSD(userQuota),
			Used:         matchaQuotaToUSD(userUsedQuota),
			BalanceQuota: userQuota,
			UsedQuota:    userUsedQuota,
			Group:        common.GetContextKeyString(c, constant.ContextKeyUserGroup),
		}
		spendable = userQuota
	}
	// An overdrawn account or key cannot spend anything.
	spendable = max(spendable, 0)
	balance := matchaQuotaToUSD(spendable)
	response.Balance, response.BalanceQuota = &balance, &spendable
	c.JSON(http.StatusOK, response)
}
