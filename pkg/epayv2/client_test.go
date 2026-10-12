package epayv2

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"maps"
	"net/url"
	"testing"
	"time"

	"github.com/Calcium-Ion/go-epay/epay"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testKeys struct {
	merchant, platform *rsa.PrivateKey
}

func newTestKeys(t *testing.T) testKeys {
	t.Helper()
	merchant, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	platform, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return testKeys{merchant: merchant, platform: platform}
}

// pkcs8Base64 mirrors how the gateway console displays keys: base64 DER with no PEM armor.
func pkcs8Base64(t *testing.T, key *rsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(der)
}

func pkixBase64(t *testing.T, key *rsa.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(key)
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(der)
}

// newMerchantAndGateway returns the merchant-side client under test and a
// client that signs like the gateway (platform private key).
func newMerchantAndGateway(t *testing.T, keys testKeys) (*Client, *Client) {
	t.Helper()
	merchant, err := NewClient("7071", "https://pay.example.com/", pkcs8Base64(t, keys.merchant), pkixBase64(t, &keys.platform.PublicKey))
	require.NoError(t, err)
	gateway, err := NewClient("7071", "https://pay.example.com/", pkcs8Base64(t, keys.platform), pkixBase64(t, &keys.merchant.PublicKey))
	require.NoError(t, err)
	return merchant, gateway
}

func signedCallback(t *testing.T, gateway *Client, params map[string]string) map[string]string {
	t.Helper()
	sign, err := gateway.Sign(params)
	require.NoError(t, err)
	signed := maps.Clone(params)
	signed["sign"] = sign
	signed["sign_type"] = SignType
	return signed
}

func TestPurchaseSignsSubmitFormWithMerchantKey(t *testing.T) {
	keys := newTestKeys(t)
	merchant, gateway := newMerchantAndGateway(t, keys)
	merchant.now = func() time.Time { return time.Unix(1721206072, 0) }
	notifyURL, _ := url.Parse("https://api.example.com/api/user/epay/notify")
	returnURL, _ := url.Parse("https://api.example.com/console/log")

	submitURL, params, err := merchant.Purchase(&epay.PurchaseArgs{
		Type: "alipay", ServiceTradeNo: "USR1NOabc", Name: "TUC10", Money: "10.00",
		Device: epay.PC, NotifyUrl: notifyURL, ReturnUrl: returnURL,
	})
	require.NoError(t, err)
	assert.Equal(t, "https://pay.example.com/api/pay/submit", submitURL)
	assert.Equal(t, map[string]string{
		"pid": "7071", "type": "alipay", "out_trade_no": "USR1NOabc", "name": "TUC10", "money": "10.00",
		"notify_url": notifyURL.String(), "return_url": returnURL.String(),
		"timestamp": "1721206072", "sign_type": "RSA", "sign": params["sign"],
	}, params)

	// The gateway verifies with the merchant public key over the documented string.
	content := "money=10.00&name=TUC10&notify_url=https://api.example.com/api/user/epay/notify&out_trade_no=USR1NOabc&pid=7071&return_url=https://api.example.com/console/log&timestamp=1721206072&type=alipay"
	sig, err := base64.StdEncoding.DecodeString(params["sign"])
	require.NoError(t, err)
	digest := sha256.Sum256([]byte(content))
	require.NoError(t, rsa.VerifyPKCS1v15(&keys.merchant.PublicKey, crypto.SHA256, digest[:], sig))
	ok, err := gateway.VerifySignature(params)
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestPurchaseRejectsAmbiguousParameters(t *testing.T) {
	merchant, _ := newMerchantAndGateway(t, newTestKeys(t))
	notifyURL, _ := url.Parse("https://api.example.com/api/user/epay/notify")
	returnURL, _ := url.Parse("https://api.example.com/console/log?a=1&b=2")
	_, params, err := merchant.Purchase(&epay.PurchaseArgs{
		Type: "alipay", ServiceTradeNo: "USR1NOabc", Name: "TUC10", Money: "10.00",
		NotifyUrl: notifyURL, ReturnUrl: returnURL,
	})
	assert.ErrorIs(t, err, epay.ErrInvalidParams)
	assert.Nil(t, params)
}

func TestVerifyCallback(t *testing.T) {
	keys := newTestKeys(t)
	merchant, gateway := newMerchantAndGateway(t, keys)
	base := map[string]string{
		"pid": "7071", "trade_no": "2024072320222180092", "out_trade_no": "USR1NOabc",
		"api_trade_no": "4200002345", "type": "alipay", "trade_status": epay.StatusTradeSuccess,
		"addtime": "2024-07-01 16:47:32", "endtime": "2024-07-01 16:49:24",
		"name": "TUC10", "money": "10.00", "param": "", "buyer": "o9uAcc", "timestamp": "1721206072",
		// Gateways may add fields; they are part of the signed content.
		"new_ext_field": "x",
	}
	valid := signedCallback(t, gateway, base)

	res, err := merchant.Verify(valid)
	require.NoError(t, err)
	assert.Equal(t, epay.VerifyRes{
		Type: "alipay", TradeNo: "2024072320222180092", ServiceTradeNo: "USR1NOabc",
		Name: "TUC10", Money: "10.00", TradeStatus: epay.StatusTradeSuccess, VerifyStatus: true,
	}, *res)

	foreignGateway, err := NewClient("7071", "https://pay.example.com", pkcs8Base64(t, keys.merchant), pkixBase64(t, &keys.platform.PublicKey))
	require.NoError(t, err)
	otherPID := maps.Clone(base)
	otherPID["pid"] = "9999"

	rejected := map[string]map[string]string{
		"tampered money":         with(valid, "money", "0.01"),
		"tampered order":         with(valid, "out_trade_no", "USR2NOxyz"),
		"tampered extension":     with(valid, "new_ext_field", "y"),
		"missing sign":           with(valid, "sign", ""),
		"garbage sign":           with(valid, "sign", "not-base64!"),
		"md5 sign type":          with(valid, "sign_type", "MD5"),
		"signed by merchant key": signedCallback(t, foreignGateway, base),
		"other merchant pid":     signedCallback(t, gateway, otherPID),
	}
	for name, params := range rejected {
		t.Run(name, func(t *testing.T) {
			res, err := merchant.Verify(params)
			require.NoError(t, err)
			assert.False(t, res.VerifyStatus)
		})
	}

	_, err = merchant.Verify(with(valid, "name", "a&out_trade_no=b"))
	assert.ErrorIs(t, err, epay.ErrInvalidParams)
}

func with(params map[string]string, key, value string) map[string]string {
	out := maps.Clone(params)
	out[key] = value
	return out
}

func TestNewClientAcceptsKeyEncodings(t *testing.T) {
	keys := newTestKeys(t)
	pkcs1PEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(keys.merchant)}))
	pkixPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: must(x509.MarshalPKIXPublicKey(&keys.platform.PublicKey))}))
	wrapped := pkcs8Base64(t, keys.merchant)
	wrapped = wrapped[:64] + "\n" + wrapped[64:] + "\n"

	for name, pair := range map[string][2]string{
		"bare base64":         {pkcs8Base64(t, keys.merchant), pkixBase64(t, &keys.platform.PublicKey)},
		"pem":                 {pkcs1PEM, pkixPEM},
		"wrapped bare base64": {wrapped, pkixBase64(t, &keys.platform.PublicKey)},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := NewClient("7071", "https://pay.example.com", pair[0], pair[1])
			assert.NoError(t, err)
		})
	}

	_, err := NewClient("7071", "https://pay.example.com", "not a key", pkixBase64(t, &keys.platform.PublicKey))
	assert.ErrorContains(t, err, "merchant private key")
	_, err = NewClient("7071", "https://pay.example.com", pkcs8Base64(t, keys.merchant), pkcs8Base64(t, keys.platform))
	assert.ErrorContains(t, err, "platform public key")
}

func must(b []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return b
}

func TestAmountMatches(t *testing.T) {
	cases := []struct {
		expected float64
		money    string
		want     bool
	}{
		{10, "10.00", true},
		{10, "10", true},
		{7.3, "7.30", true},
		{0.1 + 0.2, "0.30", true},
		{10, "9.99", false},
		{10, "0.01", false},
		{10, "", false},
		{10, "ten", false},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, AmountMatches(tc.expected, tc.money), "%v vs %q", tc.expected, tc.money)
	}
}
