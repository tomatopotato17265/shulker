package msauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"sync/atomic"
	"testing"
	"time"
)

func TestFiletime(t *testing.T) {
	if got := filetime(time.Unix(0, 0)); got != 116444736000000000 {
		t.Fatalf("filetime(epoch) = %d", got)
	}
	
	if got := filetime(time.Unix(1704067200, 0)); got != 133485408000000000 {
		t.Fatalf("filetime(2024) = %d", got)
	}
}

func TestSignatureBufferLayout(t *testing.T) {
	got := signatureBuffer(0x0102030405060708, "/p", "auth", []byte("{}"))
	want := []byte{0, 0, 0, 1, 0}
	want = append(want, 1, 2, 3, 4, 5, 6, 7, 8, 0)
	want = append(want, "POST"...)
	want = append(want, 0)
	want = append(want, "/p"...)
	want = append(want, 0)
	want = append(want, "auth"...)
	want = append(want, 0)
	want = append(want, "{}"...)
	want = append(want, 0)
	if string(got) != string(want) {
		t.Fatalf("buffer = %v; want %v", got, want)
	}
}

func TestSignRequestVerifies(t *testing.T) {
	k, err := GenerateDeviceKey()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1704067200, 0)
	body := []byte(`{"a":1}`)

	header, err := k.signRequest(now, "/device/authenticate", "", body)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := base64.StdEncoding.DecodeString(header)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != 4+8+64 {
		t.Fatalf("signature length = %d; want 76", len(sig))
	}
	if v := binary.BigEndian.Uint32(sig[:4]); v != 1 {
		t.Fatalf("version = %d", v)
	}
	ft := binary.BigEndian.Uint64(sig[4:12])
	if ft != filetime(now) {
		t.Fatalf("timestamp = %d; want %d", ft, filetime(now))
	}

	digest := sha256.Sum256(signatureBuffer(ft, "/device/authenticate", "", body))
	r := new(big.Int).SetBytes(sig[12:44])
	s := new(big.Int).SetBytes(sig[44:76])
	if !ecdsa.Verify(&k.Key.PublicKey, digest[:], r, s) {
		t.Fatal("signature does not verify")
	}
}

func TestDeviceKeyRoundTrip(t *testing.T) {
	k, err := GenerateDeviceKey()
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(k.ID) {
		t.Fatalf("bad uuid %q", k.ID)
	}
	for name, c := range map[string]string{"x": k.X, "y": k.Y} {
		raw, err := base64.RawURLEncoding.DecodeString(c)
		if err != nil || len(raw) != 32 {
			t.Fatalf("%s = %q: len %d, err %v", name, c, len(raw), err)
		}
	}

	pemStr, err := k.PrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	back, err := ParseDeviceKey(k.ID, pemStr)
	if err != nil {
		t.Fatal(err)
	}
	if back.ID != k.ID || back.X != k.X || back.Y != k.Y || !back.Key.Equal(k.Key) {
		t.Fatal("round-tripped key differs")
	}

	if _, err := ParseDeviceKey(k.ID, "garbage"); err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}

func TestSendsContractVersion(t *testing.T) {
	if sendsContractVersion("https://sisu.xboxlive.com/authorize") {
		t.Fatal("sisu authorize must not send the contract version")
	}
	for _, u := range []string{
		"https://sisu.xboxlive.com/authenticate",
		"https://device.auth.xboxlive.com/device/authenticate",
		"https://xsts.auth.xboxlive.com/xsts/authorize",
	} {
		if !sendsContractVersion(u) {
			t.Fatalf("%s should send the contract version", u)
		}
	}
}

func TestMarshalBodyNoHTMLEscape(t *testing.T) {
	got, err := marshalBody(map[string]string{"k": "a&b<c>"})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"k":"a&b<c>"}` {
		t.Fatalf("body = %s", got)
	}
}

func TestSendSignedRequest(t *testing.T) {
	k, _ := GenerateDeviceKey()
	serverDate := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		if req.Method != http.MethodPost || req.URL.Path != "/device/authenticate" {
			t.Errorf("unexpected request %s %s", req.Method, req.URL.Path)
		}
		if req.Header.Get("x-xbl-contract-version") != "1" {
			t.Error("missing contract version header")
		}
		if req.Header.Get("Authorization") != "Bearer x" {
			t.Errorf("Authorization = %q", req.Header.Get("Authorization"))
		}
		if req.Header.Get("Content-Type") != "application/json; charset=utf-8" {
			t.Errorf("Content-Type = %q", req.Header.Get("Content-Type"))
		}

		sig, err := base64.StdEncoding.DecodeString(req.Header.Get("Signature"))
		if err != nil || len(sig) != 76 {
			t.Errorf("bad signature header: %v", err)
		} else {
			ft := binary.BigEndian.Uint64(sig[4:12])
			digest := sha256.Sum256(signatureBuffer(ft, "/device/authenticate", "Bearer x", body))
			r := new(big.Int).SetBytes(sig[12:44])
			s := new(big.Int).SetBytes(sig[44:76])
			if !ecdsa.Verify(&k.Key.PublicKey, digest[:], r, s) {
				t.Error("signature over the sent body does not verify")
			}
		}

		w.Header().Set("Date", serverDate.Format(http.TimeFormat))
		w.Header().Set("X-Test", "yes")
		io.WriteString(w, `{"Token":"abc"}`)
	}))
	defer srv.Close()

	res, err := sendSignedRequest[struct{ Token string }](context.Background(), srv.Client(), signedRequest{
		URL:           srv.URL + "/device/authenticate",
		Path:          "/device/authenticate",
		Authorization: "Bearer x",
		Body:          map[string]string{"hello": "world"},
		Key:           k,
		Step:          StepDeviceToken,
		Date:          time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Body.Token != "abc" || res.Header.Get("X-Test") != "yes" {
		t.Fatalf("unexpected response %+v", res)
	}
	if !res.Date.Equal(serverDate) {
		t.Fatalf("Date = %v; want %v", res.Date, serverDate)
	}
}

func TestSendSignedRequestErrorStatus(t *testing.T) {
	k, _ := GenerateDeviceKey()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		io.WriteString(w, `{"XErr":2148916233}`)
	}))
	defer srv.Close()

	_, err := sendSignedRequest[map[string]any](context.Background(), srv.Client(), signedRequest{
		URL: srv.URL, Path: "/", Body: map[string]string{}, Key: k,
		Step: StepXSTSAuthorize, Date: time.Now(),
	})
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("err = %v; want *Error", err)
	}
	if e.Step != StepXSTSAuthorize || e.Status != 401 || e.Raw != `{"XErr":2148916233}` {
		t.Fatalf("unexpected error %+v", e)
	}
}

func TestDateHeaderFallback(t *testing.T) {
	before := time.Now().UTC().Add(-time.Second)
	if got := dateHeader(http.Header{}); got.Before(before) {
		t.Fatalf("fallback date %v is too old", got)
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

var _ net.Error = timeoutErr{}

func TestAuthRetry(t *testing.T) {
	old := retryWait
	retryWait = time.Millisecond
	defer func() { retryWait = old }()

	t.Run("retries timeouts then succeeds", func(t *testing.T) {
		var calls atomic.Int32
		resp, err := authRetry(context.Background(), func() (*http.Response, error) {
			if calls.Add(1) < 3 {
				return nil, timeoutErr{}
			}
			return &http.Response{StatusCode: 200}, nil
		})
		if err != nil || resp == nil || calls.Load() != 3 {
			t.Fatalf("resp=%v err=%v calls=%d", resp, err, calls.Load())
		}
	})

	t.Run("gives up after five attempts", func(t *testing.T) {
		var calls atomic.Int32
		_, err := authRetry(context.Background(), func() (*http.Response, error) {
			calls.Add(1)
			return nil, timeoutErr{}
		})
		if err == nil || calls.Load() != 5 {
			t.Fatalf("err=%v calls=%d; want error after 5 calls", err, calls.Load())
		}
	})

	t.Run("does not retry other errors", func(t *testing.T) {
		var calls atomic.Int32
		_, err := authRetry(context.Background(), func() (*http.Response, error) {
			calls.Add(1)
			return nil, errors.New("boom")
		})
		if err == nil || calls.Load() != 1 {
			t.Fatalf("err=%v calls=%d; want 1 call", err, calls.Load())
		}
	})
}
