package operation_setting

import "strings"

// Epay V2 (RSA) settings. EpayVersion "v2" switches the Epay gateway from the
// MD5 V1 protocol to the RSA-signed V2 protocol; any other value keeps V1.
var EpayVersion = "v1"
var EpayMerchantPrivateKey = ""
var EpayPlatformPublicKey = ""

func IsEpayV2() bool {
	return strings.EqualFold(strings.TrimSpace(EpayVersion), "v2")
}
