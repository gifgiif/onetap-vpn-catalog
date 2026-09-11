package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/onetap-vpn/onetap/backend/internal/catalog"
)

type Config struct {
	CryptoPayToken     string
	CryptoPayEndpoint  string
	AuthPepper         string
	AllowDiagnostics   bool
	CatalogMirrorURL   string
	EnableAccountStubs bool
}

type Server struct {
	store    catalog.Store
	config   Config
	auth     *authStore
	payment  *paymentStore
	invoices InvoiceProvider
}

func NewServer(store catalog.Store, config Config) *Server {
	server := &Server{store: store, config: config, auth: newAuthStore(config.AuthPepper), payment: newPaymentStore()}
	if config.CryptoPayToken != "" {
		server.invoices = newCryptoPayClient(config.CryptoPayToken, config.CryptoPayEndpoint)
	}
	return server
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /v1/bootstrap", s.bootstrap)
	mux.HandleFunc("GET /v1/catalog", s.catalog)
	mux.HandleFunc("POST /v1/diagnostics", s.diagnostics)
	if s.config.EnableAccountStubs {
		mux.HandleFunc("POST /v1/auth/request", s.requestCode)
		mux.HandleFunc("POST /v1/auth/verify", s.verifyCode)
		mux.HandleFunc("GET /v1/entitlements", s.entitlements)
		mux.HandleFunc("POST /v1/payments/crypto/invoices", s.createInvoice)
		mux.HandleFunc("POST /v1/payments/crypto/webhook", s.cryptoWebhook)
	}
	return securityHeaders(limitBody(mux))
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) bootstrap(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"schemaVersion": catalog.SchemaVersion, "catalogUrl": absoluteURL(r, "/v1/catalog"), "mirrorUrl": s.config.CatalogMirrorURL, "cryptoPurchaseEnabled": country(r) == "RU"})
}
func (s *Server) catalog(w http.ResponseWriter, _ *http.Request) {
	current := s.store.Current()
	if len(current.Payload.Servers) == 0 || current.Signature == "" {
		writeJSON(w, http.StatusServiceUnavailable, errorBody("catalog is still being verified"))
		return
	}
	writeJSON(w, http.StatusOK, current)
}

func (s *Server) diagnostics(w http.ResponseWriter, r *http.Request) {
	if !s.config.AllowDiagnostics {
		writeJSON(w, http.StatusNotFound, errorBody("diagnostics disabled"))
		return
	}
	var event struct {
		Event      string `json:"event"`
		DurationMs int    `json:"durationMs"`
	}
	if err := decodeJSON(r, &event); err != nil || len(event.Event) > 64 || event.DurationMs < 0 {
		writeJSON(w, http.StatusBadRequest, errorBody("invalid diagnostic"))
		return
	}
	// Deliberately no IP, config id, device id, or destination is retained.
	writeJSON(w, http.StatusAccepted, map[string]bool{"accepted": true})
}

func (s *Server) requestCode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}
	if err := decodeJSON(r, &req); err != nil || !validEmail(req.Email) {
		writeJSON(w, http.StatusBadRequest, errorBody("valid email required"))
		return
	}
	// The delivery provider belongs here. In development the code is intentionally not returned.
	s.auth.issue(strings.ToLower(req.Email))
	writeJSON(w, http.StatusAccepted, map[string]bool{"sent": true})
}
func (s *Server) verifyCode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
		Code  string `json:"code"`
	}
	if err := decodeJSON(r, &req); err != nil || !s.auth.verify(strings.ToLower(req.Email), req.Code) {
		writeJSON(w, http.StatusUnauthorized, errorBody("invalid or expired code"))
		return
	}
	token := s.auth.session(strings.ToLower(req.Email))
	writeJSON(w, http.StatusOK, map[string]string{"accessToken": token})
}
func (s *Server) entitlements(w http.ResponseWriter, r *http.Request) {
	account, ok := s.auth.account(r.Header.Get("Authorization"))
	if !ok {
		writeJSON(w, http.StatusUnauthorized, errorBody("authentication required"))
		return
	}
	writeJSON(w, http.StatusOK, s.payment.entitlement(account))
}

func (s *Server) createInvoice(w http.ResponseWriter, r *http.Request) {
	account, ok := s.auth.account(r.Header.Get("Authorization"))
	if !ok {
		writeJSON(w, http.StatusUnauthorized, errorBody("authentication required"))
		return
	}
	if country(r) != "RU" {
		writeJSON(w, http.StatusForbidden, errorBody("purchase unavailable in this region"))
		return
	}
	if s.invoices == nil {
		writeJSON(w, http.StatusServiceUnavailable, errorBody("payments are not configured"))
		return
	}
	draft := s.payment.createDraft(account)
	invoice, err := s.invoices.CreateInvoice(r.Context(), draft.Payload)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, errorBody("payment provider unavailable"))
		return
	}
	s.payment.register(draft, invoice)
	writeJSON(w, http.StatusCreated, invoice)
}

func (s *Server) cryptoWebhook(w http.ResponseWriter, r *http.Request) {
	if s.config.CryptoPayToken == "" {
		writeJSON(w, http.StatusNotFound, errorBody("payments disabled"))
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeJSON(w, 400, errorBody("bad body"))
		return
	}
	if !verifyCryptoSignature(s.config.CryptoPayToken, body, r.Header.Get("crypto-pay-api-signature")) {
		writeJSON(w, http.StatusUnauthorized, errorBody("invalid signature"))
		return
	}
	var update cryptoUpdate
	if err := json.Unmarshal(body, &update); err != nil || update.UpdateType != "invoice_paid" || update.Payload.InvoiceID == 0 {
		writeJSON(w, http.StatusBadRequest, errorBody("invalid update"))
		return
	}
	if err := s.payment.markPaid(update.UpdateID, update.Payload.InvoiceID, update.Payload.Status, update.Payload.Payload); err != nil {
		writeJSON(w, http.StatusConflict, errorBody(err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

type cryptoUpdate struct {
	UpdateID   string `json:"update_id"`
	UpdateType string `json:"update_type"`
	Payload    struct {
		InvoiceID int64  `json:"invoice_id"`
		Status    string `json:"status"`
		Payload   string `json:"payload"`
	} `json:"payload"`
}

func verifyCryptoSignature(token string, body []byte, signature string) bool {
	secret := sha256.Sum256([]byte(token))
	mac := hmac.New(sha256.New, secret[:])
	mac.Write(body)
	expected := hexEncode(mac.Sum(nil))
	return len(signature) == len(expected) && subtle.ConstantTimeCompare([]byte(strings.ToLower(signature)), []byte(expected)) == 1
}
func hexEncode(data []byte) string {
	const chars = "0123456789abcdef"
	out := make([]byte, len(data)*2)
	for i, b := range data {
		out[i*2] = chars[b>>4]
		out[i*2+1] = chars[b&15]
	}
	return string(out)
}
func country(r *http.Request) string {
	value := strings.ToUpper(r.Header.Get("X-App-Country"))
	if value == "RU" || value == "UZ" {
		return value
	}
	return ""
}
func absoluteURL(r *http.Request, path string) string {
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	return scheme + "://" + r.Host + path
}
func errorBody(message string) map[string]string { return map[string]string{"error": message} }
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func decodeJSON(r *http.Request, target any) error {
	decoder := json.NewDecoder(io.LimitReader(r.Body, 64<<10))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target)
}
func validEmail(email string) bool {
	return len(email) <= 254 && strings.Count(email, "@") == 1 && !strings.HasPrefix(email, "@") && !strings.HasSuffix(email, "@")
}
func limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		next.ServeHTTP(w, r)
	})
}
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

type authStore struct {
	mu       sync.Mutex
	pepper   string
	codes    map[string]code
	sessions map[string]string
}
type code struct {
	hash     string
	expires  time.Time
	attempts int
}

func newAuthStore(pepper string) *authStore {
	return &authStore{pepper: pepper, codes: map[string]code{}, sessions: map[string]string{}}
}
func (a *authStore) issue(email string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.codes[email] = code{hash: hash(a.pepper + "000000"), expires: time.Now().Add(10 * time.Minute)}
}
func (a *authStore) verify(email, supplied string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	c, ok := a.codes[email]
	if !ok || c.expires.Before(time.Now()) || c.attempts >= 5 {
		return false
	}
	c.attempts++
	a.codes[email] = c
	if subtle.ConstantTimeCompare([]byte(c.hash), []byte(hash(a.pepper+supplied))) != 1 {
		return false
	}
	delete(a.codes, email)
	return true
}
func (a *authStore) session(email string) string {
	token := base64.RawURLEncoding.EncodeToString([]byte(hash(email + time.Now().String())))
	a.mu.Lock()
	a.sessions[token] = email
	a.mu.Unlock()
	return token
}
func (a *authStore) account(header string) (string, bool) {
	token := strings.TrimPrefix(header, "Bearer ")
	if token == header {
		return "", false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	email, ok := a.sessions[token]
	return email, ok
}
func hash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return base64.RawStdEncoding.EncodeToString(sum[:])
}

type paymentStore struct {
	mu           sync.Mutex
	invoices     map[int64]invoice
	processed    map[string]bool
	entitlements map[string]time.Time
	next         int64
}
type invoice struct {
	ID      int64 `json:"invoiceId"`
	Account string
	Payload string
	Status  string `json:"status"`
	PayURL  string `json:"payUrl"`
}

func newPaymentStore() *paymentStore {
	return &paymentStore{invoices: map[int64]invoice{}, processed: map[string]bool{}, entitlements: map[string]time.Time{}, next: 1000}
}
func (p *paymentStore) createDraft(account string) invoice {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.next++
	value := invoice{Account: account, Payload: account + ":" + time.Now().UTC().Format(time.RFC3339Nano), Status: "draft", PayURL: ""}
	return value
}
func (p *paymentStore) register(draft invoice, external providerInvoice) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.invoices[external.ID] = invoice{ID: external.ID, Account: draft.Account, Payload: draft.Payload, Status: external.Status, PayURL: external.PayURL}
}
func (p *paymentStore) entitlement(account string) map[string]any {
	p.mu.Lock()
	defer p.mu.Unlock()
	until := p.entitlements[account]
	return map[string]any{"adFree": until.After(time.Now()), "expiresAt": until}
}
func (p *paymentStore) markPaid(updateID string, invoiceID int64, status, payload string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.processed[updateID] {
		return nil
	}
	inv, ok := p.invoices[invoiceID]
	if !ok || inv.Payload != payload || status != "paid" {
		return errors.New("invoice mismatch")
	}
	start := time.Now()
	if old := p.entitlements[inv.Account]; old.After(start) {
		start = old
	}
	p.entitlements[inv.Account] = start.AddDate(0, 0, 30)
	p.processed[updateID] = true
	return nil
}
