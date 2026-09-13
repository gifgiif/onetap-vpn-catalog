package verify

import (
	"context"
	"testing"
)

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
