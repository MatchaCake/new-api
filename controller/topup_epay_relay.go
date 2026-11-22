package controller

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"

	"github.com/QuantumNous/new-api/pkg/epayv2"
	"github.com/QuantumNous/new-api/setting/operation_setting"
	"github.com/QuantumNous/new-api/setting/system_setting"

	"github.com/gin-gonic/gin"
)

// Fork: Epay relay page for the Matcha Tearoom app.
//
// In RSA mode the gateway's /api/pay/submit only accepts the signed order as a
// form POST; the same parameters in a GET query string fail with
// "RSA签名校验失败" (measured 2026-11-23). The web console posts a form, but
// released tearoom builds open url+"?"+data in the system browser (GET). For
// those clients RequestEpay returns this site's relay page instead of the
// gateway URL; the page re-posts the parameters, unchanged, as a form to the
// gateway configured in PayAddress.
//
// The page is not an open redirect: the form target is always the configured
// gateway, only the known order fields are forwarded, and only when they carry
// this merchant's own signature for this merchant id.

const epayRelayPath = "/api/user/epay/relay"

// tearoomUserAgentPrefix is what every tearoom build sends on API calls
// (matcha-tearoom lib/gateway/gateway_http.dart).
const tearoomUserAgentPrefix = "MatchaTearoom/"

// epayRelayEdgeOneURLEnv names the site origin used when the request came
// through the mainland Tencent EdgeOne mirror. EdgeOne fetches from the main
// domain, so the Host header alone cannot tell the mirror apart.
const epayRelayEdgeOneURLEnv = "MATCHA_EPAY_RELAY_EDGEONE_URL"

// epayRelayFields are the order fields epayv2.Client.Purchase produces.
var epayRelayFields = []string{"money", "name", "notify_url", "out_trade_no", "pid", "return_url", "sign", "sign_type", "timestamp", "type"}

const epayRelayScript = `document.getElementById("epay-relay").submit();`

const epayRelayStyle = `body{font-family:system-ui,-apple-system,"PingFang SC","Microsoft YaHei",sans-serif;max-width:28rem;margin:4rem auto;padding:0 1rem;color:#243024;text-align:center;line-height:1.6}button{font-size:1rem;padding:.6rem 1.8rem;border:0;border-radius:.5rem;background:#5b8c3a;color:#fff;cursor:pointer}`

var epayRelayPage = template.Must(template.New("relay").Parse(`<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><title>{{.Title}}</title><style>` + epayRelayStyle + `</style></head>
<body>{{if .Action}}<form id="epay-relay" method="post" action="{{.Action}}">
{{range .Fields}}<input type="hidden" name="{{.Name}}" value="{{.Value}}">
{{end}}<p>正在跳转到支付页面，请稍候…</p><p>如果几秒后还没有跳转，请点下面的按钮。</p><button type="submit">继续支付</button>
</form>
<script>` + epayRelayScript + `</script>{{else}}<p>{{.Message}}</p>{{end}}
</body></html>
`))

func cspHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
}

// No form-action: the gateway's own page continues to the cashier and a
// redirect there must not be blocked.
var epayRelayCSP = "default-src 'none'; script-src " + cspHash(epayRelayScript) + "; style-src " + cspHash(epayRelayStyle) + "; base-uri 'none'; frame-ancestors 'none'"

type epayRelayField struct{ Name, Value string }

type epayRelayView struct {
	Title, Message, Action string
	Fields                 []epayRelayField
}

func renderEpayRelay(c *gin.Context, status int, view epayRelayView) {
	h := c.Writer.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store, max-age=0")
	h.Set("Pragma", "no-cache")
	h.Set("Expires", "0")
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
	h.Set("X-Robots-Tag", "noindex, nofollow")
	h.Set("Content-Security-Policy", epayRelayCSP)
	var buf bytes.Buffer
	if err := epayRelayPage.Execute(&buf, view); err != nil {
		c.Status(http.StatusInternalServerError)
		return
	}
	c.Status(status)
	_, _ = c.Writer.Write(buf.Bytes())
}

func epayRelayError(c *gin.Context, status int, message string) {
	renderEpayRelay(c, status, epayRelayView{Title: "无法跳转到支付页面", Message: message})
}

// epayRelayParams keeps only the known order fields; each must appear exactly once.
func epayRelayParams(values url.Values) (map[string]string, bool) {
	params := make(map[string]string, len(epayRelayFields))
	for _, name := range epayRelayFields {
		v, present := values[name]
		if !present {
			continue
		}
		if len(v) != 1 {
			return nil, false
		}
		params[name] = v[0]
	}
	for _, name := range []string{"pid", "out_trade_no", "money", "sign", "sign_type"} {
		if params[name] == "" {
			return nil, false
		}
	}
	return params, true
}

// EpayRelay serves GET and POST /api/user/epay/relay.
func EpayRelay(c *gin.Context) {
	if !isEpayRSA() {
		epayRelayError(c, http.StatusNotFound, "本站没有开启这种支付方式。")
		return
	}
	var values url.Values
	if c.Request.Method == http.MethodPost {
		if err := c.Request.ParseForm(); err != nil {
			epayRelayError(c, http.StatusBadRequest, "支付参数无效，请回到应用重新发起充值。")
			return
		}
		values = c.Request.PostForm
	} else {
		values = c.Request.URL.Query()
	}
	// Cheap shape checks first; building the client parses the RSA keys.
	params, ok := epayRelayParams(values)
	if !ok || params["pid"] != strings.TrimSpace(operation_setting.EpayId) {
		epayRelayError(c, http.StatusBadRequest, "支付参数无效，请回到应用重新发起充值。")
		return
	}
	client, _ := getEpayService().(*epayv2.Client)
	if client == nil {
		epayRelayError(c, http.StatusNotFound, "本站没有开启这种支付方式。")
		return
	}
	if params["pid"] != client.PartnerID || !client.VerifyMerchantSignature(params) {
		epayRelayError(c, http.StatusBadRequest, "支付参数无效，请回到应用重新发起充值。")
		return
	}
	names := make([]string, 0, len(params))
	for name := range params {
		names = append(names, name)
	}
	sort.Strings(names)
	fields := make([]epayRelayField, 0, len(names))
	for _, name := range names {
		fields = append(fields, epayRelayField{Name: name, Value: params[name]})
	}
	renderEpayRelay(c, http.StatusOK, epayRelayView{Title: "正在跳转到支付页面", Action: client.SubmitURL(), Fields: fields})
}

// siteOrigin returns "https://host" for an https site address, else "".
func siteOrigin(address string) string {
	u, err := url.Parse(strings.TrimSpace(address))
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return ""
	}
	return "https://" + strings.ToLower(u.Host)
}

func viaEdgeOne(c *gin.Context) bool {
	return strings.Contains(strings.ToLower(c.GetHeader("Cdn-Loop")), "tencentedgeone")
}

// epayRelayOrigin picks which of this site's own https origins the browser
// should open: the EdgeOne mirror for requests that came through it, else the
// origin matching the request Host, else ServerAddress. Never a host taken
// from the request that is not one of the configured addresses.
func epayRelayOrigin(c *gin.Context) string {
	primary := siteOrigin(system_setting.ServerAddress)
	edgeOne := siteOrigin(os.Getenv(epayRelayEdgeOneURLEnv))
	if edgeOne != "" && viaEdgeOne(c) {
		return edgeOne
	}
	host := strings.ToLower(c.Request.Host)
	if h, port, err := net.SplitHostPort(host); err == nil && port == "443" {
		host = h
	}
	for _, origin := range []string{primary, siteOrigin(operation_setting.CustomCallbackAddress), edgeOne} {
		if origin != "" && origin == "https://"+host {
			return origin
		}
	}
	return primary
}

// epayPurchaseURLFor returns the URL RequestEpay hands to the client: the relay
// page for tearoom builds in RSA mode, the gateway URL otherwise.
func epayPurchaseURLFor(c *gin.Context, gatewayURL string) string {
	if !isEpayRSA() || !strings.HasPrefix(c.GetHeader("User-Agent"), tearoomUserAgentPrefix) {
		return gatewayURL
	}
	origin := epayRelayOrigin(c)
	if origin == "" {
		return gatewayURL
	}
	return origin + epayRelayPath
}
