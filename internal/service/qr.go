package service

import (
	"encoding/base64"

	qrcode "github.com/skip2/go-qrcode"
)

// encodeQR renders a QR code (PNG) for the client configuration. The input is
// only ever the freshly generated profile, which is returned to the caller a
// single time and never persisted.
func encodeQR(content string) (string, error) {
	png, err := qrcode.Encode(content, qrcode.Medium, 320)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(png), nil
}
