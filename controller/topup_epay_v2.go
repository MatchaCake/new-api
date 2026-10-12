package controller

import (
	"strings"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/pkg/epayv2"
	"github.com/QuantumNous/new-api/setting/operation_setting"

	"github.com/Calcium-Ion/go-epay/epay"
)

// getEpayV2Client returns nil (never a typed nil) when V2 is not usable, so
// callers' `client == nil` checks keep working through the epay.Service type.
func getEpayV2Client() epay.Service {
	if strings.TrimSpace(operation_setting.PayAddress) == "" ||
		strings.TrimSpace(operation_setting.EpayId) == "" ||
		strings.TrimSpace(operation_setting.EpayMerchantPrivateKey) == "" ||
		strings.TrimSpace(operation_setting.EpayPlatformPublicKey) == "" {
		return nil
	}
	client, err := epayv2.NewClient(
		operation_setting.EpayId,
		operation_setting.PayAddress,
		operation_setting.EpayMerchantPrivateKey,
		operation_setting.EpayPlatformPublicKey,
	)
	if err != nil {
		// The error names which key failed to parse; it never contains key material.
		common.SysError(common.LogText("Epay V2 client configuration invalid: %s", err.Error()))
		return nil
	}
	return client
}

// epayV2AmountMismatch rejects V2 callbacks whose paid amount differs from the
// stored order. V1 behavior is unchanged.
func epayV2AmountMismatch(expected float64, callbackMoney string) bool {
	return operation_setting.IsEpayV2() && !epayv2.AmountMatches(expected, callbackMoney)
}
