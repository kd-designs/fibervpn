# FiberVPN

Pay-per-hour and pay-per-MB WireGuard VPN exit gateway powered by Nervos Fiber Network.

No accounts, no emails and no monthly subscriptions. A user selects a time or bandwidth tier, pays a Fiber invoice and gets a WireGuard `.conf` / QR code immediately. When either the paid duration expires or the byte quota is hit, the gateway disconnects the WireGuard peer and recycles its tunnel IP.

## Current status (`v0.1.0`)

This release contains the core TypeScript gateway manager, WireGuard adapter, IP pool allocator and FNN JSON-RPC invoice client:

- `src/wireguard.ts`: Curve25519 base64 key validation, `/24` IP pool allocator, client `.conf` builder and `WgCliAdapter` (`wg set` / `wg show transfer` via `execFile`).
- `src/fiber-rpc.ts`: JSON-RPC client for `fnn` (`new_invoice`, `get_invoice`) plus `InMemoryFiberClient` for offline testing.
- `src/manager.ts`: `VpnManager` session lifecycle with post-payment IP allocation, concurrent activation locking and automatic time/byte quota enforcement.

## Run tests and demo

```bash
npm install
npm test
npm run demo
```

