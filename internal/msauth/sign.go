package msauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"time"
)

type DeviceKey struct {
	ID   string
	Key  *ecdsa.PrivateKey
	X, Y string
}

func GenerateDeviceKey() (*DeviceKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating device key: %w", err)
	}
	id, err := newUUID()
	if err != nil {
		return nil, err
	}
	return newDeviceKey(id, key), nil
}

func ParseDeviceKey(id, privateKeyPEM string) (*DeviceKey, error) {
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return nil, errors.New("device key is not valid PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing device key: %w", err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, errors.New("device key is not a P-256 key")
	}
	return newDeviceKey(id, key), nil
}

func newDeviceKey(id string, key *ecdsa.PrivateKey) *DeviceKey {
	return &DeviceKey{
		ID:  id,
		Key: key,
		X:   base64.RawURLEncoding.EncodeToString(padLeft(key.PublicKey.X.Bytes(), 32)),
		Y:   base64.RawURLEncoding.EncodeToString(padLeft(key.PublicKey.Y.Bytes(), 32)),
	}
}

func (k *DeviceKey) PrivateKeyPEM() (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k.Key)
	if err != nil {
		return "", fmt.Errorf("encoding device key: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}

func (k *DeviceKey) ProofKey() map[string]string {
	return map[string]string{
		"kty": "EC",
		"x":   k.X,
		"y":   k.Y,
		"crv": "P-256",
		"alg": "ES256",
		"use": "sig",
	}
}

func filetime(t time.Time) uint64 {
	return uint64(t.Unix()+11644473600) * 10000000
}

func signatureBuffer(ft uint64, path, authorization string, body []byte) []byte {
	var buf []byte
	buf = binary.BigEndian.AppendUint32(buf, 1)
	buf = append(buf, 0)
	buf = binary.BigEndian.AppendUint64(buf, ft)
	buf = append(buf, 0)
	buf = append(buf, "POST"...)
	buf = append(buf, 0)
	buf = append(buf, path...)
	buf = append(buf, 0)
	buf = append(buf, authorization...)
	buf = append(buf, 0)
	buf = append(buf, body...)
	buf = append(buf, 0)
	return buf
}

func (k *DeviceKey) signRequest(now time.Time, path, authorization string, body []byte) (string, error) {
	ft := filetime(now)
	digest := sha256.Sum256(signatureBuffer(ft, path, authorization, body))

	r, s, err := ecdsa.Sign(rand.Reader, k.Key, digest[:])
	if err != nil {
		return "", fmt.Errorf("signing request: %w", err)
	}

	var sig []byte
	sig = binary.BigEndian.AppendUint32(sig, 1)
	sig = binary.BigEndian.AppendUint64(sig, ft)
	sig = append(sig, padLeft(r.Bytes(), 32)...)
	sig = append(sig, padLeft(s.Bytes(), 32)...)
	return base64.StdEncoding.EncodeToString(sig), nil
}

func padLeft(b []byte, n int) []byte {
	if len(b) >= n {
		return b
	}
	out := make([]byte, n)
	copy(out[n-len(b):], b)
	return out
}

func newUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generating uuid: %w", err)
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}
