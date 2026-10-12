package controller

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"testing"

	"github.com/Calcium-Ion/go-epay/epay"
	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/pkg/epayv2"
	"github.com/QuantumNous/new-api/setting/operation_setting"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Fork tests for the Epay RSA path (controller/topup_epay_v2.go). The signing
// string and signatures are computed here with crypto/rsa directly, not with
// pkg/epayv2, so they check the wire format instead of the client against itself.

const matchaEpayTestMerchantID = "1001"

type matchaEpayRSATestKeys struct {
	merchant, platform *rsa.PrivateKey
}

// matchaEpaySignContent is the gateway's documented signing string: non-empty
// parameters except sign and sign_type, sorted by name, joined as k=v with &.
func matchaEpaySignContent(params map[string]string) string {
	keys := make([]string, 0, len(params))
	for key, value := range params {
		if key == "sign" || key == "sign_type" || value == "" {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	pairs := make([]string, 0, len(keys))
	for _, key := range keys {
		pairs = append(pairs, key+"="+params[key])
	}
	return strings.Join(pairs, "&")
}

func matchaEpaySign(t *testing.T, key *rsa.PrivateKey, params map[string]string) string {
	t.Helper()
	digest := sha256.Sum256([]byte(matchaEpaySignContent(params)))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(signature)
}

// setupMatchaEpayRSATest selects RSA in upstream's payment settings with fresh
// keys stored as single-line Base64, the format merchant consoles show.
func setupMatchaEpayRSATest(t *testing.T) matchaEpayRSATestKeys {
	t.Helper()
	confirmPaymentComplianceForTest(t)
	paymentSetting := operation_setting.GetPaymentSetting()
	originalSetting := *paymentSetting
	originalPayAddress, originalEpayID, originalEpayKey := operation_setting.PayAddress, operation_setting.EpayId, operation_setting.EpayKey
	originalPayMethods := operation_setting.PayMethods
	t.Cleanup(func() {
		paymentSetting.EpaySignType = originalSetting.EpaySignType
		paymentSetting.EpayMerchantPrivateKey = originalSetting.EpayMerchantPrivateKey
		paymentSetting.EpayPlatformPublicKey = originalSetting.EpayPlatformPublicKey
		operation_setting.PayAddress, operation_setting.EpayId, operation_setting.EpayKey = originalPayAddress, originalEpayID, originalEpayKey
		operation_setting.PayMethods = originalPayMethods
	})

	merchantKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	platformKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	merchantPrivateDER, err := x509.MarshalPKCS8PrivateKey(merchantKey)
	require.NoError(t, err)
	platformPublicDER, err := x509.MarshalPKIXPublicKey(&platformKey.PublicKey)
	require.NoError(t, err)

	operation_setting.PayAddress = "https://pay.example.com"
	operation_setting.EpayId = matchaEpayTestMerchantID
	operation_setting.EpayKey = ""
	operation_setting.PayMethods = []map[string]string{{"type": "alipay"}}
	paymentSetting.EpaySignType = operation_setting.EpaySignTypeRSA
	paymentSetting.EpayMerchantPrivateKey = base64.StdEncoding.EncodeToString(merchantPrivateDER)
	paymentSetting.EpayPlatformPublicKey = base64.StdEncoding.EncodeToString(platformPublicDER)
	return matchaEpayRSATestKeys{merchant: merchantKey, platform: platformKey}
}

func TestMatchaEpayServiceFollowsUpstreamSignType(t *testing.T) {
	setupMatchaEpayRSATest(t)
	paymentSetting := operation_setting.GetPaymentSetting()

	_, isRSAClient := getEpayService().(*epayv2.Client)
	require.True(t, isRSAClient, "RSA mode signs and verifies with pkg/epayv2")
	require.True(t, isEpayWebhookEnabled(), "RSA mode does not need the MD5 key")

	platformPublicKey := paymentSetting.EpayPlatformPublicKey
	paymentSetting.EpayPlatformPublicKey = ""
	require.Nil(t, getEpayService(), "RSA mode needs both keys")
	require.False(t, isEpayWebhookEnabled())
	paymentSetting.EpayPlatformPublicKey = "not a key"
	require.Nil(t, getEpayService(), "an unparsable key disables Epay instead of panicking")
	paymentSetting.EpayPlatformPublicKey = platformPublicKey

	paymentSetting.EpaySignType = operation_setting.EpaySignTypeMD5
	require.Nil(t, getEpayService(), "MD5 mode ignores the RSA keys and needs the MD5 key")
	operation_setting.EpayKey = "md5-key"
	_, isMD5Client := getEpayService().(*epay.Client)
	require.True(t, isMD5Client, "MD5 mode keeps upstream's client")
}

func TestMatchaEpayRSAOrderFormat(t *testing.T) {
	keys := setupMatchaEpayRSATest(t)
	notifyURL, err := url.Parse("https://dashboard.example.com/api/user/epay/notify")
	require.NoError(t, err)
	returnURL, err := url.Parse("https://dashboard.example.com/usage-logs")
	require.NoError(t, err)

	submitURL, params, err := getEpayService().Purchase(&epay.PurchaseArgs{
		Type: "alipay", ServiceTradeNo: "USR1NOabc", Name: "TUC10", Money: "73.00",
		Device: epay.PC, NotifyUrl: notifyURL, ReturnUrl: returnURL,
	})
	require.NoError(t, err)
	assert.Equal(t, "https://pay.example.com/api/pay/submit", submitURL)

	names := make([]string, 0, len(params))
	for name := range params {
		names = append(names, name)
	}
	sort.Strings(names)
	// The exact form posted to the gateway. Notably no "device" field.
	assert.Equal(t, []string{"money", "name", "notify_url", "out_trade_no", "pid", "return_url", "sign", "sign_type", "timestamp", "type"}, names)
	assert.Equal(t, matchaEpayTestMerchantID, params["pid"])
	assert.Equal(t, "RSA", params["sign_type"])
	assert.Equal(t, "73.00", params["money"])
	assert.Equal(t, notifyURL.String(), params["notify_url"])

	// The gateway verifies with the merchant public key.
	signature, err := base64.StdEncoding.DecodeString(params["sign"])
	require.NoError(t, err)
	digest := sha256.Sum256([]byte(matchaEpaySignContent(params)))
	require.NoError(t, rsa.VerifyPKCS1v15(&keys.merchant.PublicKey, crypto.SHA256, digest[:], signature))
}

func TestMatchaEpayRSANotifySettlesOnlyOwnMatchingCallbacks(t *testing.T) {
	keys := setupMatchaEpayRSATest(t)
	const tradeNo = "USR1NOv2"

	db := setupModelListControllerTestDB(t)
	require.NoError(t, db.AutoMigrate(&model.User{}, &model.TopUp{}, &model.Log{}))
	require.NoError(t, db.Create(&model.User{Id: 1, Username: "alice", Quota: 0}).Error)
	require.NoError(t, db.Create(&model.TopUp{UserId: 1, Amount: 10, Money: 73, TradeNo: tradeNo, PaymentMethod: "alipay",
		PaymentProvider: model.PaymentProviderEpay, Status: common.TopUpStatusPending}).Error)

	router := gin.New()
	router.Any("/api/user/epay/notify", EpayNotify)
	// callback sends a notify signed by signer; edit changes fields before
	// signing, tamper changes them after.
	callback := func(method string, signer *rsa.PrivateKey, edit func(map[string]string), tamper func(url.Values)) string {
		// The fork has never enforced a timestamp window on callbacks, so a
		// fixed old timestamp is accepted.
		params := map[string]string{"pid": matchaEpayTestMerchantID, "trade_no": "P1", "out_trade_no": tradeNo, "type": "alipay",
			"trade_status": epay.StatusTradeSuccess, "name": "TUC10", "money": "73.00", "timestamp": "1721206072"}
		if edit != nil {
			edit(params)
		}
		values := url.Values{"sign": {matchaEpaySign(t, signer, params)}, "sign_type": {"RSA"}}
		for key, value := range params {
			values.Set(key, value)
		}
		if tamper != nil {
			tamper(values)
		}
		request := httptest.NewRequest(http.MethodGet, "/api/user/epay/notify?"+values.Encode(), nil)
		if method == http.MethodPost {
			request = httptest.NewRequest(http.MethodPost, "/api/user/epay/notify", strings.NewReader(values.Encode()))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, request)
		return recorder.Body.String()
	}
	status := func() string { return model.GetTopUpByTradeNo(tradeNo).Status }
	quota := func() int {
		var user model.User
		require.NoError(t, db.First(&user, 1).Error)
		return user.Quota
	}

	rejected := []struct {
		name   string
		signer *rsa.PrivateKey
		edit   func(map[string]string)
		tamper func(url.Values)
	}{
		{"amount changed after signing", keys.platform, nil, func(v url.Values) { v.Set("money", "0.01") }},
		{"validly signed but underpaid", keys.platform, func(p map[string]string) { p["money"] = "0.01" }, nil},
		// Every merchant of a gateway shares the platform key: another merchant
		// can get a genuine callback for an order number of its choosing.
		{"validly signed for another merchant", keys.platform, func(p map[string]string) { p["pid"] = "9999" }, nil},
		{"merchant id removed", keys.platform, func(p map[string]string) { delete(p, "pid") }, nil},
		{"signed with the merchant key", keys.merchant, nil, nil},
		{"signature removed", keys.platform, nil, func(v url.Values) { v.Del("sign") }},
		{"declared as MD5", keys.platform, nil, func(v url.Values) { v.Set("sign_type", "MD5") }},
	}
	for _, tc := range rejected {
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			assert.Equal(t, "fail", callback(method, tc.signer, tc.edit, tc.tamper), "%s (%s)", tc.name, method)
		}
	}
	assert.Equal(t, common.TopUpStatusPending, status())
	assert.Zero(t, quota())

	assert.Equal(t, "success", callback(http.MethodGet, keys.platform, nil, nil))
	assert.Equal(t, common.TopUpStatusSuccess, status())
	credited := quota()
	assert.Positive(t, credited)
	assert.Equal(t, "success", callback(http.MethodPost, keys.platform, nil, nil), "duplicate callback is acknowledged")
	assert.Equal(t, credited, quota(), "duplicate callback does not credit twice")
}
