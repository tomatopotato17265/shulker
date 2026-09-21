package msauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

const sisuAuthorizeURL = "https://sisu.xboxlive.com/authorize"

const (
	retryAttempts = 5
)

var retryWait = 250 * time.Millisecond

type signedRequest struct {
	URL           string
	Path          string
	Authorization string
	Body          any
	Key           *DeviceKey
	Step          Step
	Date          time.Time
}

type signedResponse[T any] struct {
	Header http.Header
	Date   time.Time
	Body   T
}

func sendSignedRequest[T any](ctx context.Context, client *http.Client, r signedRequest) (*signedResponse[T], error) {
	fail := func(status int, raw string, err error) error {
		return &Error{Step: r.Step, Status: status, Raw: raw, Err: err}
	}

	body, err := marshalBody(r.Body)
	if err != nil {
		return nil, fail(0, "", fmt.Errorf("serializing body: %w", err))
	}
	signature, err := r.Key.signRequest(r.Date, r.Path, r.Authorization, body)
	if err != nil {
		return nil, fail(0, "", err)
	}

	resp, err := authRetry(ctx, func() (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.URL, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Signature", signature)
		if sendsContractVersion(r.URL) {
			req.Header.Set("x-xbl-contract-version", "1")
		}
		if r.Authorization != "" {
			req.Header.Set("Authorization", r.Authorization)
		}
		return client.Do(req)
	})
	if err != nil {
		return nil, fail(0, "", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fail(resp.StatusCode, "", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fail(resp.StatusCode, string(raw), errors.New("unexpected response status"))
	}

	var decoded T
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return nil, fail(resp.StatusCode, string(raw), fmt.Errorf("decoding response: %w", err))
	}
	return &signedResponse[T]{
		Header: resp.Header,
		Date:   dateHeader(resp.Header),
		Body:   decoded,
	}, nil
}

func sendsContractVersion(url string) bool {
	return url != sisuAuthorizeURL
}

func marshalBody(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

func dateHeader(h http.Header) time.Time {
	if t, err := http.ParseTime(h.Get("Date")); err == nil {
		return t.UTC()
	}
	return time.Now().UTC()
}

func authRetry(ctx context.Context, do func() (*http.Response, error)) (*http.Response, error) {
	var (
		resp *http.Response
		err  error
	)
	for attempt := 0; attempt < retryAttempts; attempt++ {
		resp, err = do()
		if err == nil || !isRetryable(err) || ctx.Err() != nil {
			break
		}
		if attempt < retryAttempts-1 {
			select {
			case <-time.After(retryWait):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
	}
	return resp, err
}

func isRetryable(err error) bool {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	var opErr *net.OpError
	return errors.As(err, &opErr) && opErr.Op == "dial"
}
