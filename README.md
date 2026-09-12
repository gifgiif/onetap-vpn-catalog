# OneTap verified server catalog

This repository publishes a signed static catalog for the OneTap Android pilot.
It contains no VPN traffic proxy and no user accounts. GitHub Actions fetches
untrusted public VLESS feeds, accepts only the restricted VLESS model supported
by the app, and verifies each selected candidate through a clean Xray process
and an HTTPS download before it can enter `public/catalog.json`.

The Android app verifies the ECDSA P-256 signature and expiry before using the
catalog. The signing private key is stored only as a GitHub Actions secret.
