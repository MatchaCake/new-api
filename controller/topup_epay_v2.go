package controller

import (
	"strings"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/pkg/epayv2"
	"github.com/QuantumNous/new-api/setting/operation_setting"

	"github.com/Calcium-Ion/go-epay/epay"
)

// Fork: the Epay handlers call getEpayService instead of GetEpayClient. The
// signature type and both RSA keys come from upstream's payment settings; in
// RSA mode the fork signs and verifies with pkg/epayv2 instead of go-epay.
//
// In RSA mode every merchant of a gateway shares the platform key, so a valid
// signature does not prove a callback is ours. pkg/epayv2 also requires the
// callback's pid to be this merchant, and the handlers require the paid amount
// to equal the stored order (epayV2AmountMismatch).

func isEpayRSA() bool {
	return operation_setting.GetPaymentSetting().EpaySignType == operation_setting.EpaySignTypeRSA
}

// getEpayService returns nil (never a typed nil) when Epay is not usable, so
// callers' `client == nil` checks work through the epay.Service type.
func getEpayService() epay.Service {
	if isEpayRSA() {
		return getEpayV2Client()
	}
	if client := GetEpayClient(); client != nil {
		return client
	}
	return nil
}

func getEpayV2Client() epay.Service {
	paymentSetting := operation_setting.GetPaymentSetting()
	if strings.TrimSpace(operation_setting.PayAddress) == "" ||
		strings.TrimSpace(operation_setting.EpayId) == "" ||
		strings.TrimSpace(paymentSetting.EpayMerchantPrivateKey) == "" ||
		strings.TrimSpace(paymentSetting.EpayPlatformPublicKey) == "" {
		return nil
	}
	client, err := epayv2.NewClient(
		operation_setting.EpayId,
		operation_setting.PayAddress,
		paymentSetting.EpayMerchantPrivateKey,
		paymentSetting.EpayPlatformPublicKey,
	)
	if err != nil {
		// The error names which key failed to parse; it never contains key material.
		common.SysError(common.LogText("Epay RSA client configuration invalid: %s", err.Error()))
		return nil
	}
	return client
}

// epayV2AmountMismatch rejects RSA callbacks whose paid amount differs from
// the stored order. MD5 behavior is unchanged.
func epayV2AmountMismatch(expected float64, callbackMoney string) bool {
	return isEpayRSA() && !epayv2.AmountMatches(expected, callbackMoney)
}
