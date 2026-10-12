package model

import (
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func setAffRebateTestGlobals(t *testing.T, percent float64) {
	t.Helper()
	oldQuotaPerUnit := common.QuotaPerUnit
	oldPercent := common.AffTopUpRebatePercent
	common.QuotaPerUnit = 500000
	common.AffTopUpRebatePercent = percent
	t.Cleanup(func() {
		common.QuotaPerUnit = oldQuotaPerUnit
		common.AffTopUpRebatePercent = oldPercent
	})
}

func insertAffRebateTestUser(t *testing.T, id int, username string, inviterId int) {
	t.Helper()
	require.NoError(t, DB.Create(&User{
		Id:        id,
		Username:  username,
		Status:    common.UserStatusEnabled,
		InviterId: inviterId,
		AffCode:   username,
	}).Error)
}

func getAffRebateTestUser(t *testing.T, id int) User {
	t.Helper()
	var user User
	require.NoError(t, DB.Select("id", "quota", "aff_quota", "aff_history").Where("id = ?", id).First(&user).Error)
	return user
}

func countAffRebateLogs(t *testing.T, userId int) int64 {
	t.Helper()
	var count int64
	require.NoError(t, LOG_DB.Model(&Log{}).
		Where("user_id = ? AND type = ? AND content LIKE ?", userId, LogTypeSystem, "Invitation rebate %").
		Count(&count).Error)
	return count
}

func TestEpayTopUpRebatesDirectInviterOnceAndOnlyOneLevel(t *testing.T) {
	truncateTables(t)
	setAffRebateTestGlobals(t, 10)

	insertAffRebateTestUser(t, 601, "aff_a", 0)
	insertAffRebateTestUser(t, 602, "aff_b", 601)
	insertAffRebateTestUser(t, 603, "aff_c", 602)

	// B (invited by A) pays $2 -> 1,000,000 quota; A earns 10% as invitation quota.
	order := createEpayTestOrder(t, 602, "AFFREBATE-B-1", PaymentProviderEpay, common.TopUpStatusPending)
	alreadyDone, err := RechargeEpay(order.TradeNo, "alipay", "127.0.0.1")
	require.NoError(t, err)
	assert.False(t, alreadyDone)

	a := getAffRebateTestUser(t, 601)
	assert.Equal(t, 0, a.Quota, "rebate must not go to the wallet balance directly")
	assert.Equal(t, 100000, a.AffQuota)
	assert.Equal(t, 100000, a.AffHistoryQuota)
	assert.Equal(t, 1000000, getAffRebateTestUser(t, 602).Quota)
	assert.Equal(t, int64(1), countAffRebateLogs(t, 601))

	// Duplicate callback for the same order: no second rebate.
	alreadyDone, err = RechargeEpay(order.TradeNo, "alipay", "127.0.0.1")
	require.NoError(t, err)
	assert.True(t, alreadyDone)
	assert.Equal(t, 100000, getAffRebateTestUser(t, 601).AffQuota)
	assert.Equal(t, int64(1), countAffRebateLogs(t, 601))

	// Every top-up earns a rebate, not only the first.
	order2 := createEpayTestOrder(t, 602, "AFFREBATE-B-2", PaymentProviderEpay, common.TopUpStatusPending)
	_, err = RechargeEpay(order2.TradeNo, "wxpay", "127.0.0.1")
	require.NoError(t, err)
	assert.Equal(t, 200000, getAffRebateTestUser(t, 601).AffQuota)
	assert.Equal(t, 200000, getAffRebateTestUser(t, 601).AffHistoryQuota)

	// C (invited by B) pays: B earns, A does not.
	order3 := createEpayTestOrder(t, 603, "AFFREBATE-C-1", PaymentProviderEpay, common.TopUpStatusPending)
	_, err = RechargeEpay(order3.TradeNo, "alipay", "127.0.0.1")
	require.NoError(t, err)
	assert.Equal(t, 100000, getAffRebateTestUser(t, 602).AffQuota)
	assert.Equal(t, 200000, getAffRebateTestUser(t, 601).AffQuota)
	assert.Equal(t, int64(2), countAffRebateLogs(t, 601))
	assert.Equal(t, int64(1), countAffRebateLogs(t, 602))

	// A has no inviter, so A's own top-up rebates nobody.
	order4 := createEpayTestOrder(t, 601, "AFFREBATE-A-1", PaymentProviderEpay, common.TopUpStatusPending)
	_, err = RechargeEpay(order4.TradeNo, "alipay", "127.0.0.1")
	require.NoError(t, err)
	assert.Equal(t, 200000, getAffRebateTestUser(t, 601).AffQuota)
	assert.Equal(t, 1000000, getAffRebateTestUser(t, 601).Quota)

	// Rebated invitation quota uses the existing transfer flow (minimum 1 unit).
	inviter := &User{Id: 601}
	require.Error(t, inviter.TransferAffQuotaToQuota(200000))
	order5 := createEpayTestOrder(t, 602, "AFFREBATE-B-3", PaymentProviderEpay, common.TopUpStatusPending)
	order5.Amount = 30
	require.NoError(t, DB.Save(&order5).Error)
	_, err = RechargeEpay(order5.TradeNo, "alipay", "127.0.0.1")
	require.NoError(t, err)
	assert.Equal(t, 1700000, getAffRebateTestUser(t, 601).AffQuota)
	require.NoError(t, (&User{Id: 601}).TransferAffQuotaToQuota(500000))
	afterTransfer := getAffRebateTestUser(t, 601)
	assert.Equal(t, 1200000, afterTransfer.AffQuota)
	assert.Equal(t, 1500000, afterTransfer.Quota)
	assert.Equal(t, 1700000, afterTransfer.AffHistoryQuota)
}

func TestTopUpRebateDisabledAtZeroPercent(t *testing.T) {
	truncateTables(t)
	setAffRebateTestGlobals(t, 0)

	insertAffRebateTestUser(t, 611, "aff_zero_a", 0)
	insertAffRebateTestUser(t, 612, "aff_zero_b", 611)
	order := createEpayTestOrder(t, 612, "AFFREBATE-ZERO", PaymentProviderEpay, common.TopUpStatusPending)
	_, err := RechargeEpay(order.TradeNo, "alipay", "127.0.0.1")
	require.NoError(t, err)
	assert.Equal(t, 0, getAffRebateTestUser(t, 611).AffQuota)
	assert.Equal(t, int64(0), countAffRebateLogs(t, 611))
}

func TestManualCompleteTopUpRebatesOnce(t *testing.T) {
	truncateTables(t)
	setAffRebateTestGlobals(t, 10)

	insertAffRebateTestUser(t, 621, "aff_manual_a", 0)
	insertAffRebateTestUser(t, 622, "aff_manual_b", 621)
	order := createEpayTestOrder(t, 622, "AFFREBATE-MANUAL", PaymentProviderEpay, common.TopUpStatusPending)
	require.NoError(t, ManualCompleteTopUp(order.TradeNo, "127.0.0.1"))
	require.NoError(t, ManualCompleteTopUp(order.TradeNo, "127.0.0.1"))
	assert.Equal(t, 100000, getAffRebateTestUser(t, 621).AffQuota)
	assert.Equal(t, int64(1), countAffRebateLogs(t, 621))

	// A late gateway callback after the manual completion is also a no-op.
	alreadyDone, err := RechargeEpay(order.TradeNo, "alipay", "127.0.0.1")
	require.NoError(t, err)
	assert.True(t, alreadyDone)
	assert.Equal(t, 100000, getAffRebateTestUser(t, 621).AffQuota)
}

func TestRedemptionCodeEarnsNoInviterRebate(t *testing.T) {
	truncateTables(t)
	setAffRebateTestGlobals(t, 10)
	require.NoError(t, DB.AutoMigrate(&Redemption{}))
	t.Cleanup(func() {
		DB.Session(&gorm.Session{AllowGlobalUpdate: true}).Unscoped().Delete(&Redemption{})
	})

	insertAffRebateTestUser(t, 631, "aff_redeem_a", 0)
	insertAffRebateTestUser(t, 632, "aff_redeem_b", 631)
	require.NoError(t, DB.Create(&Redemption{
		Id:     9631,
		Name:   "aff-rebate",
		Key:    "0000000000000000000000000000a631",
		Status: common.RedemptionCodeStatusEnabled,
		Quota:  1000000,
	}).Error)
	quota, err := Redeem("0000000000000000000000000000a631", 632)
	require.NoError(t, err)
	assert.Equal(t, 1000000, quota)
	assert.Equal(t, 0, getAffRebateTestUser(t, 631).AffQuota)
	assert.Equal(t, int64(0), countAffRebateLogs(t, 631))
}

func TestComputeAffTopUpRebate(t *testing.T) {
	assert.Equal(t, 100000, computeAffTopUpRebate(1000000, 10))
	assert.Equal(t, 0, computeAffTopUpRebate(9, 10))
	assert.Equal(t, 1, computeAffTopUpRebate(19, 10))
	assert.Equal(t, 25000, computeAffTopUpRebate(1000000, 2.5))
	assert.Equal(t, 0, computeAffTopUpRebate(1000000, 0))
	assert.Equal(t, 1000000, computeAffTopUpRebate(1000000, 150))
}

func TestAffTopUpRebatePercentOption(t *testing.T) {
	old := common.AffTopUpRebatePercent
	originalMap := common.OptionMap
	common.OptionMap = map[string]string{}
	t.Cleanup(func() {
		common.AffTopUpRebatePercent = old
		common.OptionMap = originalMap
	})

	require.NoError(t, updateOptionMap("AffTopUpRebatePercent", "12.5"))
	assert.Equal(t, 12.5, common.AffTopUpRebatePercent)
	require.NoError(t, updateOptionMap("AffTopUpRebatePercent", "-1"))
	assert.Equal(t, 12.5, common.AffTopUpRebatePercent, "invalid values are ignored")
	require.NoError(t, updateOptionMap("AffTopUpRebatePercent", "0"))
	assert.Equal(t, 0.0, common.AffTopUpRebatePercent)
}
