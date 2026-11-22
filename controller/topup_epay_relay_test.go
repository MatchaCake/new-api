package controller

import (
	"bytes"
	"encoding/json"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/Calcium-Ion/go-epay/epay"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/setting/operation_setting"
	"github.com/QuantumNous/new-api/setting/system_setting"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Fork tests for the tearoom Epay relay page (topup_epay_relay.go).

const epayRelayTestSubmit = "https://pay.example.com/api/pay/submit"

func setupEpayRelayTest(t *testing.T) matchaEpayRSATestKeys {
	t.Helper()
	keys := setupMatchaEpayRSATest(t)
	originalServer, originalCallback := system_setting.ServerAddress, operation_setting.CustomCallbackAddress
	t.Cleanup(func() {
		system_setting.ServerAddress, operation_setting.CustomCallbackAddress = originalServer, originalCallback
	})
	system_setting.ServerAddress = "https://router.example.com"
	operation_setting.CustomCallbackAddress = "https://router.example.com"
	t.Setenv(epayRelayEdgeOneURLEnv, "https://cn.example.com")
	return keys
}

// signedEpayOrder is an order form exactly as epayv2.Client.Purchase builds it.
func signedEpayOrder(t *testing.T, edit func(map[string]string)) map[string]string {
	t.Helper()
	notifyURL, _ := url.Parse("https://router.example.com/api/user/epay/notify")
	returnURL, _ := url.Parse("https://router.example.com/usage-logs")
	args := &epay.PurchaseArgs{Type: "alipay", ServiceTradeNo: "USR1NOrelay1700000000", Name: "抹茶公益站赞助", Money: "7.00",
		Device: epay.PC, NotifyUrl: notifyURL, ReturnUrl: returnURL}
	if edit != nil {
		// Purchase signs whatever it is given; edit the args through a map.
		m := map[string]string{"name": args.Name, "money": args.Money}
		edit(m)
		args.Name, args.Money = m["name"], m["money"]
	}
	_, params, err := getEpayService().Purchase(args)
	require.NoError(t, err)
	return params
}

func epayRelayRouter() *gin.Engine {
	r := gin.New()
	r.Any(epayRelayPath, EpayRelay)
	return r
}

func relayGET(r *gin.Engine, query string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, epayRelayPath+"?"+query, nil))
	return w
}

func relayPOST(r *gin.Engine, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, epayRelayPath, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func formValues(params map[string]string) url.Values {
	v := url.Values{}
	for k, val := range params {
		v.Set(k, val)
	}
	return v
}

var (
	relayFormRe  = regexp.MustCompile(`<form[^>]*>`)
	relayActRe   = regexp.MustCompile(`action="([^"]*)"`)
	relayInputRe = regexp.MustCompile(`<input type="hidden" name="([^"]*)" value="([^"]*)">`)
)

type relayForm struct {
	forms  int
	action string
	fields map[string]string
}

func parseRelayForm(t *testing.T, body string) relayForm {
	t.Helper()
	f := relayForm{fields: map[string]string{}}
	forms := relayFormRe.FindAllString(body, -1)
	f.forms = len(forms)
	if f.forms == 1 {
		assert.Contains(t, forms[0], `method="post"`)
		if m := relayActRe.FindStringSubmatch(forms[0]); m != nil {
			f.action = html.UnescapeString(m[1])
		}
	}
	for _, m := range relayInputRe.FindAllStringSubmatch(body, -1) {
		name := html.UnescapeString(m[1])
		_, dup := f.fields[name]
		assert.False(t, dup, "field %s rendered twice", name)
		f.fields[name] = html.UnescapeString(m[2])
	}
	return f
}

func assertRelaySecurityHeaders(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	h := w.Header()
	assert.Equal(t, "text/html; charset=utf-8", h.Get("Content-Type"))
	assert.Contains(t, h.Get("Cache-Control"), "no-store")
	assert.Equal(t, "DENY", h.Get("X-Frame-Options"))
	assert.Equal(t, "nosniff", h.Get("X-Content-Type-Options"))
	assert.Equal(t, "strict-origin-when-cross-origin", h.Get("Referrer-Policy"))
	csp := h.Get("Content-Security-Policy")
	assert.Contains(t, csp, "default-src 'none'")
	assert.Contains(t, csp, "frame-ancestors 'none'")
	assert.NotContains(t, csp, "unsafe-inline")
}

func TestEpayRelayGETAndPOSTRepostTheSignedOrderUnchanged(t *testing.T) {
	setupEpayRelayTest(t)
	r := epayRelayRouter()
	params := signedEpayOrder(t, nil)

	for name, w := range map[string]*httptest.ResponseRecorder{
		// What released tearoom builds do: Uri.replace(queryParameters:), space as '+'.
		"GET":          relayGET(r, formValues(params).Encode()),
		"GET with %20": relayGET(r, strings.ReplaceAll(formValues(params).Encode(), "+", "%20")),
		// What the web console's form does.
		"POST": relayPOST(r, formValues(params).Encode()),
	} {
		require.Equal(t, http.StatusOK, w.Code, name)
		assertRelaySecurityHeaders(t, w)
		f := parseRelayForm(t, w.Body.String())
		assert.Equal(t, 1, f.forms, name)
		assert.Equal(t, epayRelayTestSubmit, f.action, name)
		assert.Equal(t, params, f.fields, "%s: every value is forwarded byte for byte, nothing added", name)
		body := w.Body.String()
		assert.Contains(t, body, `<button type="submit">继续支付</button>`, "usable without JavaScript")
		assert.NotContains(t, body, "<script src", "no external scripts")
		// The CSP allows exactly the one inline script on the page.
		assert.Contains(t, body, "<script>"+epayRelayScript+"</script>")
		assert.Contains(t, w.Header().Get("Content-Security-Policy"), cspHash(epayRelayScript))
		assert.Contains(t, body, "<style>"+epayRelayStyle+"</style>")
	}
}

func TestEpayRelayForwardsOnlyKnownFieldsToTheConfiguredGateway(t *testing.T) {
	setupEpayRelayTest(t)
	r := epayRelayRouter()
	params := signedEpayOrder(t, nil)
	v := formValues(params)
	// Fields a caller might add to steer or extend the form.
	for _, extra := range []string{"action", "url", "gateway", "submit", "target", "device", "clientip", "param", "redirect"} {
		v.Set(extra, "https://evil.example/collect")
	}
	w := relayGET(r, v.Encode())
	require.Equal(t, http.StatusOK, w.Code)
	f := parseRelayForm(t, w.Body.String())
	assert.Equal(t, epayRelayTestSubmit, f.action)
	assert.Equal(t, params, f.fields)
	assert.NotContains(t, w.Body.String(), "evil.example")

	// The target follows PayAddress, never the request.
	operation_setting.PayAddress = "https://pay2.example.com/base"
	w = relayGET(r, formValues(signedEpayOrder(t, nil)).Encode())
	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "https://pay2.example.com/base/api/pay/submit", parseRelayForm(t, w.Body.String()).action)
}

func TestEpayRelayEscapesValues(t *testing.T) {
	setupEpayRelayTest(t)
	r := epayRelayRouter()
	// A hostile product name, validly signed (only the site can do that, but
	// the page must stay inert whatever the value is).
	// ('&' and '=' are refused by the signer itself.)
	evil := `"><script>alert(1)</script><input name='x' value="<'>` + "\u2028 抹茶"
	params := signedEpayOrder(t, func(m map[string]string) { m["name"] = evil })
	for _, w := range []*httptest.ResponseRecorder{relayGET(r, formValues(params).Encode()), relayPOST(r, formValues(params).Encode())} {
		require.Equal(t, http.StatusOK, w.Code)
		body := w.Body.String()
		assert.NotContains(t, body, "<script>alert")
		assert.Equal(t, 1, strings.Count(body, "<script"), "only the page's own script")
		f := parseRelayForm(t, body)
		assert.Equal(t, evil, f.fields["name"], "escaped in HTML, unchanged after the browser decodes it")
		assert.Equal(t, params, f.fields)
	}
}

func TestEpayRelayRejectsAnythingButThisMerchantsSignedOrder(t *testing.T) {
	keys := setupEpayRelayTest(t)
	r := epayRelayRouter()
	good := signedEpayOrder(t, nil)

	clone := func(edit func(url.Values)) string {
		v := formValues(good)
		edit(v)
		return v.Encode()
	}
	// Another merchant id, correctly signed with our key.
	otherPid := map[string]string{}
	for k, v := range good {
		otherPid[k] = v
	}
	otherPid["pid"] = "9999"
	otherPid["sign"] = matchaEpaySign(t, keys.merchant, otherPid)

	cases := map[string]string{
		"amount changed after signing": clone(func(v url.Values) { v.Set("money", "0.01") }),
		"return_url changed":           clone(func(v url.Values) { v.Set("return_url", "https://evil.example/") }),
		"signed with another key":      clone(func(v url.Values) { v.Set("sign", matchaEpaySign(t, keys.platform, good)) }),
		"no signature":                 clone(func(v url.Values) { v.Del("sign") }),
		"declared as MD5":              clone(func(v url.Values) { v.Set("sign_type", "MD5") }),
		"duplicated field":             clone(func(v url.Values) { v.Add("money", "7.00") }),
		"no order number":              clone(func(v url.Values) { v.Del("out_trade_no") }),
		"another merchant":             formValues(otherPid).Encode(),
		"empty":                        "",
	}
	for name, q := range cases {
		for _, w := range []*httptest.ResponseRecorder{relayGET(r, q), relayPOST(r, q)} {
			assert.Equal(t, http.StatusBadRequest, w.Code, name)
			assert.Zero(t, parseRelayForm(t, w.Body.String()).forms, "%s: no form", name)
			assert.NotContains(t, w.Body.String(), "<script", name)
			assertRelaySecurityHeaders(t, w)
		}
	}

	// POST takes the body only; parameters in the query string do not count.
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, epayRelayPath+"?"+formValues(good).Encode(), nil)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	// MD5 mode has no relay.
	operation_setting.GetPaymentSetting().EpaySignType = operation_setting.EpaySignTypeMD5
	operation_setting.EpayKey = "md5-key"
	w = relayGET(r, formValues(good).Encode())
	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Zero(t, parseRelayForm(t, w.Body.String()).forms)
}

func TestEpayPurchaseURLForPicksTheRelayOnlyForTearoomOnOwnDomains(t *testing.T) {
	setupEpayRelayTest(t)
	const gw = epayRelayTestSubmit
	call := func(host, ua string, headers map[string]string) string {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodPost, "/api/user/pay", nil)
		c.Request.Host = host
		c.Request.Header.Set("User-Agent", ua)
		for k, v := range headers {
			c.Request.Header.Set(k, v)
		}
		return epayPurchaseURLFor(c, gw)
	}
	const app = "MatchaTearoom/1.0"
	browser := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0 Safari/537.36"
	edge := map[string]string{"Cdn-Loop": "TencentEdgeOne; loops=2, cloudflare; loops=1"}

	assert.Equal(t, gw, call("router.example.com", browser, nil), "the web console keeps posting to the gateway")
	assert.Equal(t, gw, call("router.example.com", browser, edge))
	assert.Equal(t, "https://router.example.com/api/user/epay/relay", call("router.example.com", app, nil))
	assert.Equal(t, "https://cn.example.com/api/user/epay/relay", call("router.example.com", app, edge), "mainland mirror")
	assert.Equal(t, "https://cn.example.com/api/user/epay/relay", call("cn.example.com", app, nil))
	assert.Equal(t, "https://router.example.com/api/user/epay/relay", call("router.example.com:443", app, nil))
	// A Host that is not ours never becomes the link.
	assert.Equal(t, "https://router.example.com/api/user/epay/relay", call("evil.example", app, nil))
	assert.Equal(t, "https://router.example.com/api/user/epay/relay", call("10.0.0.5:3000", app, map[string]string{"X-Forwarded-Host": "evil.example"}))

	t.Setenv(epayRelayEdgeOneURLEnv, "")
	assert.Equal(t, "https://router.example.com/api/user/epay/relay", call("router.example.com", app, edge), "no mirror configured")
	t.Setenv(epayRelayEdgeOneURLEnv, "http://cn.example.com")
	assert.Equal(t, "https://router.example.com/api/user/epay/relay", call("router.example.com", app, edge), "non-https mirror ignored")

	system_setting.ServerAddress = "http://localhost:3000"
	operation_setting.CustomCallbackAddress = ""
	t.Setenv(epayRelayEdgeOneURLEnv, "")
	assert.Equal(t, gw, call("localhost:3000", app, nil), "no https site address: keep the gateway URL")

	system_setting.ServerAddress = "https://router.example.com"
	operation_setting.GetPaymentSetting().EpaySignType = operation_setting.EpaySignTypeMD5
	assert.Equal(t, gw, call("router.example.com", app, nil), "MD5 mode unchanged")
}

// End to end: what a released tearoom build does with /api/user/pay's answer
// now lands on a form that posts the untouched order to the gateway.
func TestRequestEpayGivesTearoomTheRelayAndTheRelayRepostsIt(t *testing.T) {
	setupEpayRelayTest(t)
	db := setupModelListControllerTestDB(t)
	require.NoError(t, db.AutoMigrate(&model.User{}, &model.TopUp{}))
	require.NoError(t, db.Create(&model.User{Id: 7, Username: "tea", Group: "default"}).Error)

	pay := func(ua string) (string, map[string]string) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodPost, "/api/user/pay", bytes.NewBufferString(`{"amount":1,"payment_method":"alipay"}`))
		c.Request.Host = "router.example.com"
		c.Request.Header.Set("Content-Type", "application/json")
		c.Request.Header.Set("User-Agent", ua)
		c.Set("id", 7)
		RequestEpay(c)
		var resp struct {
			Message string            `json:"message"`
			URL     string            `json:"url"`
			Data    map[string]string `json:"data"`
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp), w.Body.String())
		require.Equal(t, "success", resp.Message, w.Body.String())
		return resp.URL, resp.Data
	}

	webURL, webData := pay("Mozilla/5.0")
	assert.Equal(t, epayRelayTestSubmit, webURL)
	assert.Equal(t, "RSA", webData["sign_type"])

	appURL, appData := pay("MatchaTearoom/1.0")
	require.Equal(t, "https://router.example.com/api/user/epay/relay", appURL)
	assert.Equal(t, matchaEpayTestMerchantID, appData["pid"])

	// The tearoom appends data to url as a query string and opens it.
	u, err := url.Parse(appURL)
	require.NoError(t, err)
	w := relayGET(epayRelayRouter(), formValues(appData).Encode())
	require.Equal(t, http.StatusOK, w.Code)
	f := parseRelayForm(t, w.Body.String())
	assert.Equal(t, epayRelayTestSubmit, f.action)
	assert.Equal(t, appData, f.fields)
	assert.Equal(t, epayRelayPath, u.Path)
}
