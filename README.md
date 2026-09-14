# OneTap verified server catalog

This repository publishes a signed static catalog for the OneTap Android pilot.
It contains no VPN traffic proxy and no user accounts. GitHub Actions fetches
untrusted public VLESS feeds, accepts only the restricted VLESS model supported
by the app, and verifies each selected candidate through a clean Xray process
and an HTTPS download before it can enter `public/catalog.json`.

The Android app verifies the ECDSA P-256 signature and expiry before using the
catalog. The signing private key is stored only as a GitHub Actions secret.

Each refresh writes one `catalog_refresh_report={...}` record to the GitHub
Actions log. It contains only aggregate operational counters: source status,
line parsing, candidate selection, probe outcomes, published server count and
duration. It never contains VLESS URIs, hosts, UUIDs, public keys, source URLs,
or user data.

`cmd/api` is a local diagnostic API, not a catalog worker. Its optional importer
runs once per launch and checks at most 12 candidates by default (32 only with
an explicit local override). Recurring catalog publication runs only in the
bounded GitHub Actions workflow, so a development Mac or mobile hotspot cannot
silently consume traffic by continuously checking the public feeds.
