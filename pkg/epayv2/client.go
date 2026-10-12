// Package epayv2 implements the RSA-signed V2 protocol of 彩虹易支付-style
// payment gateways (/api/pay/submit, SHA256WithRSA). It satisfies the same
// epay.Service interface as the MD5 V1 client so callers can switch versions
// by configuration only.
//
// Signing: all non-empty parameters except sign and sign_type, sorted by key,
// joined as k=v&k=v, signed with the merchant private key. Responses and
// callbacks are verified with the platform public key.
package epayv2

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/Calcium-Ion/go-epay/epay"
	"github.com/shopspring/decimal"
)

const (
	SubmitPath = "/api/pay/submit"
	SignType   = "RSA"
)

var _ epay.Service = (*Client)(nil)

type Client struct {
	PartnerID   string
	BaseURL     *url.URL
	privateKey  *rsa.PrivateKey
	platformKey *rsa.PublicKey
	now         func() time.Time
}

// NewClient builds a V2 client. Keys may be PEM blocks or the bare base64 DER
// strings shown in the gateway's merchant console.
func NewClient(partnerID, baseURL, merchantPrivateKey, platformPublicKey string) (*Client, error) {
	u, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil {
		return nil, err
	}
	privateKey, err := ParsePrivateKey(merchantPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("epay v2 merchant private key: %w", err)
	}
	platformKey, err := ParsePublicKey(platformPublicKey)
	if err != nil {
		return nil, fmt.Errorf("epay v2 platform public key: %w", err)
	}
	return &Client{
		PartnerID:   strings.TrimSpace(partnerID),
		BaseURL:     u,
		privateKey:  privateKey,
		platformKey: platformKey,
		now:         time.Now,
	}, nil
}

// keyDER accepts PEM or bare base64 (whitespace and line breaks ignored).
func keyDER(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if block, _ := pem.Decode([]byte(s)); block != nil {
		return block.Bytes, nil
	}
	compact := strings.Join(strings.Fields(s), "")
	if compact == "" {
		return nil, errors.New("empty key")
	}
	der, err := base64.StdEncoding.DecodeString(compact)
	if err != nil {
		return nil, errors.New("key is neither PEM nor base64")
	}
	return der, nil
}

func ParsePrivateKey(s string) (*rsa.PrivateKey, error) {
	der, err := keyDER(s)
	if err != nil {
		return nil, err
	}
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("not an RSA private key")
		}
		return rsaKey, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	return nil, errors.New("unsupported private key format")
}

func ParsePublicKey(s string) (*rsa.PublicKey, error) {
	der, err := keyDER(s)
	if err != nil {
		return nil, err
	}
	if key, err := x509.ParsePKIXPublicKey(der); err == nil {
		rsaKey, ok := key.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("not an RSA public key")
		}
		return rsaKey, nil
	}
	if key, err := x509.ParsePKCS1PublicKey(der); err == nil {
		return key, nil
	}
	return nil, errors.New("unsupported public key format")
}

// signingString reuses the V1 library's filtering, ordering and separator
// validation, so ambiguous parameters are rejected the same way as in V1.
func signingString(params map[string]string) (string, error) {
	if params == nil {
		return "", fmt.Errorf("%w: nil parameter map", epay.ErrInvalidParams)
	}
	keys, values := epay.ParamsSort(epay.ParamsFilter(params))
	return epay.CreateUrlStringWithError(keys, values)
}

// Sign returns the base64 SHA256WithRSA signature of params.
func (c *Client) Sign(params map[string]string) (string, error) {
	content, err := signingString(params)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(content))
	sig, err := rsa.SignPKCS1v15(rand.Reader, c.privateKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sig), nil
}

// VerifySignature checks params["sign"] against the platform public key.
func (c *Client) VerifySignature(params map[string]string) (bool, error) {
	content, err := signingString(params)
	if err != nil {
		return false, err
	}
	if signType := params["sign_type"]; signType != "" && signType != SignType {
		return false, nil
	}
	sig, err := base64.StdEncoding.DecodeString(params["sign"])
	if err != nil || len(sig) == 0 {
		return false, nil
	}
	digest := sha256.Sum256([]byte(content))
	return rsa.VerifyPKCS1v15(c.platformKey, crypto.SHA256, digest[:], sig) == nil, nil
}

// Purchase returns the page-jump submit URL and signed form parameters; the
// browser POSTs them to the gateway exactly like the V1 flow.
func (c *Client) Purchase(args *epay.PurchaseArgs) (string, map[string]string, error) {
	params := map[string]string{
		"pid":          c.PartnerID,
		"type":         args.Type,
		"out_trade_no": args.ServiceTradeNo,
		"notify_url":   args.NotifyUrl.String(),
		"return_url":   args.ReturnUrl.String(),
		"name":         args.Name,
		"money":        args.Money,
		"timestamp":    strconv.FormatInt(c.now().Unix(), 10),
	}
	sign, err := c.Sign(params)
	if err != nil {
		return "", nil, err
	}
	params["sign"] = sign
	params["sign_type"] = SignType

	u := *c.BaseURL
	u.Path = path.Join(u.Path, SubmitPath)
	return u.String(), params, nil
}

// Verify checks a notify/return callback. VerifyStatus is true only when the
// RSA signature is valid and the callback belongs to this merchant.
func (c *Client) Verify(params map[string]string) (*epay.VerifyRes, error) {
	ok, err := c.VerifySignature(params)
	if err != nil {
		return nil, err
	}
	return &epay.VerifyRes{
		Type:           params["type"],
		TradeNo:        params["trade_no"],
		ServiceTradeNo: params["out_trade_no"],
		Name:           params["name"],
		Money:          params["money"],
		TradeStatus:    params["trade_status"],
		VerifyStatus:   ok && params["pid"] == c.PartnerID,
	}, nil
}

// AmountMatches reports whether a callback money string equals the order's
// expected amount at the gateway's two-decimal precision.
func AmountMatches(expected float64, callbackMoney string) bool {
	got, err := decimal.NewFromString(strings.TrimSpace(callbackMoney))
	if err != nil {
		return false
	}
	return decimal.NewFromFloat(expected).Round(2).Equal(got.Round(2))
}
