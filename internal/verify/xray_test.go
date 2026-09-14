package verify

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestDefaultYouTubeProbeUsesGenerate204(t *testing.T) {
	if defaultYouTubeProbeURL != "https://www.youtube.com/generate_204" {
		t.Fatalf("unexpected YouTube publication gate: %s", defaultYouTubeProbeURL)
	}
}

func TestRequireYouTube204AcceptsOnlyNoContent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			t.Fatalf("got method %s", request.Method)
		}
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	latency, err := requireYouTube204(context.Background(), server.Client(), server.URL)
	if err != nil {
		t.Fatalf("204 YouTube probe rejected: %v", err)
	}
	if latency < 0 {
		t.Fatalf("invalid latency: %s", latency)
	}
}

func TestRequireYouTube204RejectsUnexpectedStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	if _, err := requireYouTube204(context.Background(), server.Client(), server.URL); err == nil {
		t.Fatal("200 response admitted as a YouTube route")
	}
}

func TestOptionalThroughputDoesNotActAsPublicationGate(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, ok := optionalThroughput(ctx, server.Client(), server.URL); ok {
		t.Fatal("failed optional transfer reported a throughput value")
	}
}

func TestThroughputMeasurementIsOptIn(t *testing.T) {
	if (XrayChecker{}).EnableThroughput {
		t.Fatal("a scheduled health probe must not download a speed sample by default")
	}
}

func TestCountryOnlyComesFromExactTraceField(t *testing.T) {
	for input, want := range map[string]string{"loc=DE\n": "DE", "ip=1.1.1.1\nloc=NL\ntls=TLSv1.3": "NL", "location=DE": "", "loc=XX": "", "loc=<script>": ""} {
		if got := traceCountry(input); got != want {
			t.Fatalf("got %q want %q", got, want)
		}
	}
}

func TestCheckerRejectsInternalAndMappedDestinations(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "10.0.0.1", "100.64.0.1", "::1", "::ffff:192.168.0.1", "fc00::1", "198.18.0.1"} {
		if _, err := resolvePublicHost(context.Background(), host); err == nil {
			t.Fatalf("accepted %s", host)
		}
	}
}
