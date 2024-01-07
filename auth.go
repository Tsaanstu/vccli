package vccli

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	vmwareSessionIDHeader string = "vmware-api-session-id"
)

type authRoundTrip struct {
	cli *Client
}

func (rt *authRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) {
	rt.cli.Mutex.Lock()

	_, err := getSessionInfo(r.Context(), rt.cli.BaseURL, rt.cli.Token)
	if err != nil && !errors.Is(err, errUnauthorized) {
		rt.cli.Mutex.Unlock()

		return nil, fmt.Errorf("can't get session info: %w", err)
	}

	if err == nil {
		r.Header.Add(vmwareSessionIDHeader, rt.cli.Token)

		rt.cli.Mutex.Unlock()

		return http.DefaultTransport.RoundTrip(r)
	}

	token, err := createSessionKey(
		r.Context(),
		rt.cli.BaseURL,
		base64.StdEncoding.EncodeToString([]byte(rt.cli.username+":"+rt.cli.password)),
	)
	if err != nil {
		rt.cli.Mutex.Unlock()

		return nil, fmt.Errorf("can't create session: %w", err)
	}

	log.Println("new session created")

	rt.cli.Token = token

	r.Header.Add(vmwareSessionIDHeader, token)

	rt.cli.Mutex.Unlock()

	return http.DefaultTransport.RoundTrip(r)
}

var errUnauthorized = errors.New("unauthorized")

type SessionInfo struct {
	User        string    `json:"user"`
	CreatedTime time.Time `json:"created_time"`
}

func getSessionInfo(ctx context.Context, baseURL *url.URL, token string) (*SessionInfo, error) {
	cli := http.Client{}

	requestPath, err := url.JoinPath(baseURL.String(), "/api/session")
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestPath, http.NoBody)
	if err != nil {
		return nil, err
	}

	req.Header.Add(vmwareSessionIDHeader, token)

	resp, err := cli.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		var parsedResponseBody SessionInfo

		err = json.NewDecoder(resp.Body).Decode(&parsedResponseBody)
		if err != nil {
			return nil, fmt.Errorf("can't decode response body: %w", err)
		}

		return &parsedResponseBody, nil
	case http.StatusUnauthorized:
		return nil, errUnauthorized
	default:
		var rawResponseBody json.RawMessage

		err = json.NewDecoder(resp.Body).Decode(&rawResponseBody)
		if err != nil {
			return nil, fmt.Errorf("can't decode body of unsuccess response with status code %d: %w", resp.StatusCode, err)
		}

		return nil, fmt.Errorf("incorrect response, status %d, body %v", resp.StatusCode, rawResponseBody)
	}
}

func createSessionKey(ctx context.Context, baseURL *url.URL, baseAuthFormatValue string) (string, error) {
	cli := http.Client{}

	requestPath, err := url.JoinPath(baseURL.String(), "/api/session")
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, requestPath, http.NoBody)
	if err != nil {
		return "", err
	}

	req.Header.Add("authorization", "Basic "+baseAuthFormatValue)
	req.Header.Add("Content-type", "application/json")

	resp, err := cli.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		var rawResponseBody json.RawMessage

		err = json.NewDecoder(resp.Body).Decode(&rawResponseBody)
		if err != nil {
			return "", fmt.Errorf("can't decode body of unsuccess response with status code %d: %w", resp.StatusCode, err)
		}

		return "", fmt.Errorf("incorrect response, status %d, body %q", resp.StatusCode, string(rawResponseBody))
	}

	token, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return strings.Trim(string(token), "\""), nil
}
