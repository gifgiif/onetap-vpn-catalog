// Package verify performs isolated end-to-end checks before a public server is
// allowed into the signed catalog. It never executes an upstream configuration:
// the Xray JSON is built from the restricted catalog.VLESS model.
package verify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/onetap-vpn/onetap/backend/internal/catalog"
	"golang.org/x/net/proxy"
)

const (
	probeBytes             = 256 << 10
	defaultProbeURL        = "https://speed.cloudflare.com/__down?bytes=262144"
	defaultYouTubeProbeURL = "https://youtube.com/generate_204"
	optionalProbeTimeout   = 4 * time.Second
)

type XrayChecker struct {
	Binary          string
	Timeout         time.Duration
	ProbeURL        string
	YouTubeProbeURL string
}

func (c XrayChecker) Probe(ctx context.Context, server catalog.VLESS) (catalog.ProbeMetrics, error) {
	if c.Binary == "" {
		return catalog.ProbeMetrics{}, fmt.Errorf("xray checker is not configured")
	}
	if c.Timeout <= 0 {
		c.Timeout = 12 * time.Second
	}
	resolved, err := resolvePublicHost(ctx, server.Host)
	if err != nil {
		return catalog.ProbeMetrics{}, err
	}
	if server.SNI == "" {
		server.SNI = server.Host
	}
	server.Host = resolved // Pin the validated answer; Xray cannot re-resolve into a private address.
	port, err := freePort()
	if err != nil {
		return catalog.ProbeMetrics{}, err
	}
	dir, err := os.MkdirTemp("", "onetap-xray-check-")
	if err != nil {
		return catalog.ProbeMetrics{}, err
	}
	defer os.RemoveAll(dir)
	data, err := json.Marshal(xrayConfig(server, port))
	if err != nil {
		return catalog.ProbeMetrics{}, err
	}
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return catalog.ProbeMetrics{}, err
	}

	checkCtx, cancel := context.WithTimeout(ctx, c.Timeout)
	defer cancel()
	var stderr bytes.Buffer
	cmd := exec.CommandContext(checkCtx, c.Binary, "run", "-c", path)
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		return catalog.ProbeMetrics{}, fmt.Errorf("start xray: %w", err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()

	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	if err := waitForSocks(checkCtx, address); err != nil {
		return catalog.ProbeMetrics{}, fmt.Errorf("xray did not open SOCKS: %w: %s", err, stderr.String())
	}
	dialer, err := proxy.SOCKS5("tcp", address, nil, proxy.Direct)
	if err != nil {
		return catalog.ProbeMetrics{}, err
	}
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return dialer.(proxy.ContextDialer).DialContext(ctx, network, address)
	}}}
	youtubeURL := c.YouTubeProbeURL
	if youtubeURL == "" {
		youtubeURL = defaultYouTubeProbeURL
	}
	// A route is publishable only after an actual YouTube HTTPS request crossed
	// its VLESS tunnel. TCP, SOCKS startup and a generic CDN download alone do
	// not prove that the route can serve the application's primary use case.
	youtubeLatency, err := requireYouTube204(checkCtx, client, youtubeURL)
	if err != nil {
		return catalog.ProbeMetrics{}, err
	}
	metrics := catalog.ProbeMetrics{LatencyMs: int(youtubeLatency.Milliseconds())}
	// Resolve the exit country while the checker budget is still available.
	// Country diversity is part of publication, whereas a throughput number is
	// only a ranking hint and can safely be skipped near the deadline.
	geoCtx, geoCancel := context.WithTimeout(checkCtx, 1500*time.Millisecond)
	defer geoCancel()
	geoRequest, _ := http.NewRequestWithContext(geoCtx, http.MethodGet, "https://www.cloudflare.com/cdn-cgi/trace", nil)
	if geoResponse, geoErr := client.Do(geoRequest); geoErr == nil {
		if geoResponse.StatusCode == http.StatusOK {
			body, _ := io.ReadAll(io.LimitReader(geoResponse.Body, 4096))
			metrics.CountryCode = traceCountry(string(body))
		}
		geoResponse.Body.Close()
	}

	// The Cloudflare transfer is a noisy ranking signal, not a gate. A healthy
	// YouTube route remains in the catalog when this optional endpoint is slow,
	// rate-limited, or temporarily unavailable from the checker region.
	probeURL := c.ProbeURL
	if probeURL == "" {
		probeURL = defaultProbeURL
	}
	if throughput, ok := optionalThroughput(checkCtx, client, probeURL); ok {
		metrics.ThroughputKbps = throughput
	}
	return metrics, nil
}

// requireYouTube204 verifies the documented lightweight YouTube endpoint.
// Keeping it separate from Xray process management makes the publication gate
// independently testable and prevents a successful unrelated HTTPS request
// from admitting a route.
func requireYouTube204(ctx context.Context, client *http.Client, endpoint string) (time.Duration, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return 0, fmt.Errorf("create YouTube probe: %w", err)
	}
	started := time.Now()
	response, err := client.Do(request)
	if err != nil {
		return 0, fmt.Errorf("YouTube HTTPS probe: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		return 0, fmt.Errorf("unexpected YouTube probe status: %d", response.StatusCode)
	}
	return time.Since(started), nil
}

// optionalThroughput returns false rather than an error: it must never evict a
// route that already passed the mandatory YouTube request.
func optionalThroughput(ctx context.Context, client *http.Client, endpoint string) (int, bool) {
	probeCtx, cancel := context.WithTimeout(ctx, optionalProbeTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(probeCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return 0, false
	}
	response, err := client.Do(request)
	if err != nil {
		return 0, false
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return 0, false
	}
	started := time.Now()
	bytes, err := io.Copy(io.Discard, io.LimitReader(response.Body, probeBytes))
	if err != nil || bytes < probeBytes {
		return 0, false
	}
	duration := time.Since(started)
	if duration <= 0 {
		return 0, false
	}
	return int(float64(bytes*8) / duration.Seconds() / 1_000), true
}

func traceCountry(body string) string {
	for _, line := range strings.Split(body, "\n") {
		if code, ok := strings.CutPrefix(strings.TrimSpace(line), "loc="); ok && len(code) == 2 && code[0] >= 'A' && code[0] <= 'Z' && code[1] >= 'A' && code[1] <= 'Z' && code != "XX" {
			return code
		}
	}
	return ""
}

func resolvePublicHost(ctx context.Context, host string) (string, error) {
	if err := catalog.ValidateResolvedPublicHost(ctx, host); err != nil {
		return "", err
	}
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(addresses) == 0 {
		return "", fmt.Errorf("resolve destination")
	}
	for _, address := range addresses {
		if err := catalog.ValidateResolvedPublicHost(ctx, address.String()); err != nil {
			return "", err
		}
	}
	for _, address := range addresses {
		if address.Is4() {
			return address.String(), nil
		}
	}
	return addresses[0].String(), nil
}

func ensurePublicHost(ctx context.Context, host string) error {
	if ip, err := netip.ParseAddr(host); err == nil {
		if !publicIP(ip) {
			return fmt.Errorf("non-public destination")
		}
		return nil
	}
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(addresses) == 0 {
		return fmt.Errorf("resolve destination: %w", err)
	}
	for _, ip := range addresses {
		if !publicIP(ip) {
			return fmt.Errorf("destination resolves to a non-public address")
		}
	}
	return nil
}

func publicIP(ip netip.Addr) bool {
	return ip.IsGlobalUnicast() && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsMulticast()
}

func freePort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port, nil
}

func waitForSocks(ctx context.Context, address string) error {
	for {
		connection, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
		if err == nil {
			_ = connection.Close()
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func xrayConfig(server catalog.VLESS, port int) map[string]any {
	stream := map[string]any{"network": server.Type, "security": server.Security}
	if server.Security == "reality" {
		stream["realitySettings"] = map[string]any{"serverName": server.SNI, "publicKey": server.PublicKey, "shortId": server.ShortID, "fingerprint": "chrome"}
	} else {
		serverName := server.SNI
		if serverName == "" {
			serverName = server.Host
		}
		stream["tlsSettings"] = map[string]any{"serverName": serverName, "allowInsecure": false}
	}
	user := map[string]any{"id": server.UUID, "encryption": "none"}
	if server.Flow != "" {
		user["flow"] = server.Flow
	}
	return map[string]any{
		"log":       map[string]any{"loglevel": "warning"},
		"inbounds":  []any{map[string]any{"listen": "127.0.0.1", "port": port, "protocol": "socks", "settings": map[string]any{"udp": false}}},
		"outbounds": []any{map[string]any{"protocol": "vless", "settings": map[string]any{"vnext": []any{map[string]any{"address": server.Host, "port": server.Port, "users": []any{user}}}}, "streamSettings": stream}},
	}
}
