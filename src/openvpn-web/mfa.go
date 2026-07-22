package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"image/png"

	"github.com/boombuler/barcode"
	"github.com/boombuler/barcode/qr"
	"github.com/pquerna/otp/totp"
)

func GenMfa(user string) (secret string, uri string, qrCode string, err error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "openvpn-web",
		AccountName: user,
	})
	if err != nil {
		return "", "", "", err
	}

	code, err := qr.Encode(key.URL(), qr.M, qr.Auto)
	if err != nil {
		return "", "", "", fmt.Errorf("encode MFA QR code: %w", err)
	}
	code, err = barcode.Scale(code, 256, 256)
	if err != nil {
		return "", "", "", fmt.Errorf("scale MFA QR code: %w", err)
	}
	var image bytes.Buffer
	if err := png.Encode(&image, code); err != nil {
		return "", "", "", fmt.Errorf("render MFA QR code: %w", err)
	}

	return key.Secret(), key.URL(), "data:image/png;base64," + base64.StdEncoding.EncodeToString(image.Bytes()), nil
}

func ValidateMfa(passcode, key string) bool {
	return totp.Validate(passcode, key)
}
