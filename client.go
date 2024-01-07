package vccli

import (
	"net/http"
	"net/url"
	"sync"
)

func NewClient(baseURL, username, password string) (*Client, error) {
	parsedBase, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}

	cli := &Client{
		BaseURL:  parsedBase,
		username: username,
		password: password,
	}

	httpCli := http.Client{
		Transport: &authRoundTrip{cli: cli},
	}

	cli.Client = httpCli

	return cli, nil
}

type Client struct {
	http.Client
	BaseURL            *url.URL
	username, password string
	Token              string
	Mutex              sync.Mutex
}
