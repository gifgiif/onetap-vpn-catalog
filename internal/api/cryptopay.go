package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type InvoiceProvider interface {
	CreateInvoice(context.Context, string) (providerInvoice, error)
}
type providerInvoice struct {
	ID     int64  `json:"invoiceId"`
	PayURL string `json:"payUrl"`
	Status string `json:"status"`
}

type cryptoPayClient struct {
	token, endpoint string
	client          *http.Client
}

func newCryptoPayClient(token, endpoint string) InvoiceProvider {
	if endpoint == "" {
		endpoint = "https://pay.crypt.bot/api"
	}
	return &cryptoPayClient{token: token, endpoint: strings.TrimRight(endpoint, "/"), client: &http.Client{Timeout: 15 * time.Second}}
}
func (c *cryptoPayClient) CreateInvoice(ctx context.Context, payload string) (providerInvoice, error) {
	body, _ := json.Marshal(map[string]string{"currency_type": "fiat", "fiat": "RUB", "amount": "99", "description": "OneTap VPN — отключение рекламы на 30 дней", "payload": payload})
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint+"/createInvoice", bytes.NewReader(body))
	if err != nil {
		return providerInvoice{}, err
	}
	request.Header.Set("Crypto-Pay-API-Token", c.token)
	request.Header.Set("Content-Type", "application/json")
	response, err := c.client.Do(request)
	if err != nil {
		return providerInvoice{}, err
	}
	defer response.Body.Close()
	var decoded struct {
		OK     bool   `json:"ok"`
		Error  string `json:"error"`
		Result struct {
			InvoiceID int64  `json:"invoice_id"`
			PayURL    string `json:"pay_url"`
			Status    string `json:"status"`
		} `json:"result"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 64<<10)).Decode(&decoded); err != nil {
		return providerInvoice{}, err
	}
	if !responseIsSuccess(response.StatusCode, decoded.OK) || decoded.Result.InvoiceID == 0 || decoded.Result.PayURL == "" {
		return providerInvoice{}, fmt.Errorf("Crypto Pay createInvoice failed: %s", decoded.Error)
	}
	return providerInvoice{ID: decoded.Result.InvoiceID, PayURL: decoded.Result.PayURL, Status: decoded.Result.Status}, nil
}
func responseIsSuccess(status int, ok bool) bool { return status >= 200 && status < 300 && ok }
