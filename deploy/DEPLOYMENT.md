# Linux deployment boundary

These assets are a hardened deployment scaffold, not a production-ready VPN installer.

## Current safety state

- `ivpn-netbroker` recognizes only the compiled endpoint catalog and rejects endpoints not dedicated to the requested platform.
- Status and typed dry-run requests work.
- Linux namespace and WireGuard activation is deliberately disabled.
- The broker has no Linux capabilities and cannot create routes or namespaces.
- No cloud credentials, public IPs, VPN keys, DNS servers, tokens, or signer material are supplied.

This means publication through the broker is unavailable, which is the intended fail-closed state until network isolation has proof.

## Install scaffold

1. Create a locked system user and group named `ivpn`.
2. Install the controller at `/usr/local/bin/ivpn-controller` and broker at `/usr/local/libexec/ivpn-netbroker`, both owned by root and not writable by `ivpn`.
3. Install `ivpn-tmpfiles.conf` under `/usr/lib/tmpfiles.d/`, run `systemd-tmpfiles --create`, and install both service files under `/etc/systemd/system/`.
4. Keep `/etc/ivpn/controller.env` root-owned with mode `0640`. It must contain references to a host secret store, not raw long-lived credentials.
5. Place the management TLS listener behind the management VPN only. Do not expose it on a public interface.
6. Run `ivpn-netbroker -mode=status` and a known-endpoint dry run before enabling either unit.

Example dry run:

```sh
/usr/local/libexec/ivpn-netbroker \
  -mode=dry-run \
  -job=deployment_check_001 \
  -platform=nostr \
  -endpoint=gcp-fr-1
```

## Gate for real namespace execution

Do not enable privileged execution by editing the service file alone. A separate reviewed implementation must use fixed root-owned endpoint configuration, create a fresh namespace and tmpfs per attempt, expose only loopback and `wg0`, disable IPv6 or tunnel it, install drop-by-default nftables policy, force the gateway resolver, drop the worker UID and capabilities, and destroy all ephemeral state.

Before capabilities are granted, three clean adversarial rounds must demonstrate with packet captures that tunnel loss during DNS, TLS, token refresh, NIP-46 signing, Nostr publication, X transmission, and response handling produces zero direct fallback traffic. Any medium-or-higher finding resets all three rounds.
