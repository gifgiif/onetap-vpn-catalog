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
	"time"

	"github.com/onetap-vpn/onetap/backend/internal/catalog"
	"golang.org/x/net/proxy"
)

const probeBytes = 256 << 10
const defaultProbeURL = "https://speed.cloudflare.com/__down?bytes=262144"

type XrayChecker struct {
	Binary   string
	Timeout  time.Duration
	ProbeURL string
}

func (c XrayChecker) Probe(ctx context.Context, server catalog.VLESS) (catalog.ProbeMetrics, error) {
	if c.Binary == "" {
		return catalog.ProbeMetrics{}, fmt.Errorf("xray checker is not configured")
	}
	if c.Timeout <= 0 {
		c.Timeout = 12 * time.Second
	}
	if err := ensurePublicHost(ctx, server.Host); err != nil {
		return catalog.ProbeMetrics{}, err
	}
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
		return dialer.Dial(network, address)
	}}}
	probeURL := c.ProbeURL
	if probeURL == "" {
		probeURL = defaultProbeURL
	}
	request, err := http.NewRequestWithContext(checkCtx, http.MethodGet, probeURL, nil)
	if err != nil {
		return catalog.ProbeMetrics{}, err
	}
	requestedAt := time.Now()
	response, err := client.Do(request)
	if err != nil {
		return catalog.ProbeMetrics{}, fmt.Errorf("HTTPS probe: %w", err)
	}
	defer response.Body.Close()
	responseLatency := time.Since(requestedAt)
	if response.StatusCode != http.StatusOK {
		return catalog.ProbeMetrics{}, fmt.Errorf("unexpected HTTPS probe status: %d", response.StatusCode)
	}
	bodyStarted := time.Now()
	bytes, err := io.Copy(io.Discard, io.LimitReader(response.Body, probeBytes))
	if err != nil {
		return catalog.ProbeMetrics{}, fmt.Errorf("read HTTPS probe: %w", err)
	}
	if bytes < probeBytes {
		return catalog.ProbeMetrics{}, fmt.Errorf("HTTPS probe returned only %d bytes", bytes)
	}
	duration := time.Since(bodyStarted)
	throughput := int(float64(bytes*8) / duration.Seconds() / 1_000)
	return catalog.ProbeMetrics{LatencyMs: int(responseLatency.Milliseconds()), ThroughputKbps: throughput}, nil
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
