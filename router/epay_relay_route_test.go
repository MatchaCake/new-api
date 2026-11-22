package router

import (
	"compress/gzip"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Calcium-Ion/go-epay/epay"
	"github.com/QuantumNous/new-api/pkg/epayv2"
	"github.com/QuantumNous/new-api/setting/operation_setting"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Fork: the Epay relay page through the real API router (gzip, body limit,
// rate limit, DisableCache): security headers survive and GET/POST both work.
func TestEpayRelayRouteThroughTheAPIRouter(t *testing.T) {
	setupRelayRouterTestDB(t)
	paymentSetting := operation_setting.GetPaymentSetting()
	saved := *paymentSetting
	savedAddr, savedID := operation_setting.PayAddress, operation_setting.EpayId
	t.Cleanup(func() {
		paymentSetting.EpaySignType = saved.EpaySignType
		paymentSetting.EpayMerchantPrivateKey = saved.EpayMerchantPrivateKey
		paymentSetting.EpayPlatformPublicKey = saved.EpayPlatformPublicKey
		operation_setting.PayAddress, operation_setting.EpayId = savedAddr, savedID
	})
	merchant, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	platform, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	privDER, err := x509.MarshalPKCS8PrivateKey(merchant)
	require.NoError(t, err)
	pubDER, err := x509.MarshalPKIXPublicKey(&platform.PublicKey)
	require.NoError(t, err)
	operation_setting.PayAddress = "https://pay.example.com"
	operation_setting.EpayId = "1001"
	paymentSetting.EpaySignType = operation_setting.EpaySignTypeRSA
	paymentSetting.EpayMerchantPrivateKey = base64.StdEncoding.EncodeToString(privDER)
	paymentSetting.EpayPlatformPublicKey = base64.StdEncoding.EncodeToString(pubDER)

	client, err := epayv2.NewClient("1001", "https://pay.example.com", paymentSetting.EpayMerchantPrivateKey, paymentSetting.EpayPlatformPublicKey)
	require.NoError(t, err)
	notifyURL, _ := url.Parse("https://router.example.com/api/user/epay/notify")
	returnURL, _ := url.Parse("https://router.example.com/usage-logs")
	_, params, err := client.Purchase(&epay.PurchaseArgs{Type: "alipay", ServiceTradeNo: "USR1NOroute", Name: "抹茶公益站赞助", Money: "7.00",
		NotifyUrl: notifyURL, ReturnUrl: returnURL})
	require.NoError(t, err)
	form := url.Values{}
	for k, v := range params {
		form.Set(k, v)
	}

	engine := gin.New()
	SetApiRouter(engine)
	serve := func(req *http.Request) (*httptest.ResponseRecorder, string) {
		req.Header.Set("Accept-Encoding", "gzip")
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)
		var body io.Reader = w.Body
		if w.Header().Get("Content-Encoding") == "gzip" {
			zr, err := gzip.NewReader(w.Body)
			require.NoError(t, err)
			body = zr
		}
		b, err := io.ReadAll(body)
		require.NoError(t, err)
		return w, string(b)
	}
	post := httptest.NewRequest(http.MethodPost, "/api/user/epay/relay", strings.NewReader(form.Encode()))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for name, req := range map[string]*http.Request{
		"GET":  httptest.NewRequest(http.MethodGet, "/api/user/epay/relay?"+form.Encode(), nil),
		"POST": post,
	} {
		w, body := serve(req)
		require.Equal(t, http.StatusOK, w.Code, name)
		assert.Contains(t, body, `action="https://pay.example.com/api/pay/submit"`, name)
		assert.Contains(t, body, `<button type="submit">继续支付</button>`, name)
		h := w.Header()
		assert.Equal(t, "text/html; charset=utf-8", h.Get("Content-Type"), name)
		assert.Contains(t, h.Get("Cache-Control"), "no-store", name)
		assert.Equal(t, "DENY", h.Get("X-Frame-Options"), name)
		assert.Equal(t, "nosniff", h.Get("X-Content-Type-Options"), name)
		assert.Contains(t, h.Get("Content-Security-Policy"), "frame-ancestors 'none'", name)
	}

	form.Set("money", "0.01")
	w, body := serve(httptest.NewRequest(http.MethodGet, "/api/user/epay/relay?"+form.Encode(), nil))
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.NotContains(t, body, "<form")
}
