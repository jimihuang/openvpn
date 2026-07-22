# Deployment and HTTPS

This document covers production deployment, native HTTPS configuration, certificate storage, upgrades, rollback, and troubleshooting for `openvpn-web`.

## Runtime architecture

The container runs two supervised processes:

- OpenVPN listens on TCP `1194` by default.
- The public Web listener uses port `8833` and serves either HTTP or HTTPS according to `system.base.https_enabled`.
- An internal HTTP listener uses `127.0.0.1:8834` inside the container.
- OpenVPN authentication, connection history, and firewall callbacks use the internal listener. Port `8834` must never be published by Docker.

The internal listener allows the public listener to use HTTPS without breaking OpenVPN callbacks that are intentionally limited to the container loopback interface.

## Docker Compose deployment

Use an immutable image tag in production:

```yaml
services:
  openvpn:
    image: registry.example.com/network/openvpn-web:<version>
    container_name: openvpn-web
    restart: unless-stopped
    cap_add:
      - NET_ADMIN
    ports:
      - "1194:1194/tcp"
      - "8833:8833/tcp"
    volumes:
      - ./data:/data
      - /etc/localtime:/etc/localtime:ro
    logging:
      driver: json-file
      options:
        max-size: "20m"
        max-file: "5"
```

Start and verify the service:

```bash
docker compose pull
docker compose up -d
docker compose ps
docker compose logs --tail=100 openvpn
```

The persistent `data` directory contains configuration, the database, the OpenVPN PKI, client profiles, CCD files, TLS material, and backups. Back it up before upgrades or certificate replacement.

## Initial administrator access

A fresh upstream installation creates the `admin` administrator. Change its password immediately before exposing the Web port to an untrusted network.

The Tencent Cloud deployment at `tx.t3t3.top` was initialized with a random password. Its value is stored only in this root-readable file on that host:

```text
/opt/openvpn-web/initial-admin-password
```

Do not copy administrator passwords, private keys, session cookies, or API tokens into tickets, chat messages, source control, or command logs.

## Enable native HTTPS

Prepare the following PEM material:

- Certificate chain: the server certificate first, followed by any intermediate CA certificates.
- Private key: the unencrypted private key matching the server certificate.

In the administrator UI:

1. Open **Settings**.
2. Set **Site URL** to the final HTTPS URL.
3. Enable **Web HTTPS**.
4. Paste the certificate chain and matching private key.
5. Save the General section.
6. Restart the container.

```bash
docker compose restart openvpn
docker compose ps
```

The application rejects HTTPS enablement unless both PEM fields are present on first enable. It also rejects malformed, mismatched, not-yet-valid, or expired certificates.

Certificate material is stored separately from `config.json`:

```text
/data/tls/server.crt  mode 0644
/data/tls/server.key  mode 0600
```

The private key is never returned by the settings API. When valid material already exists, leaving both PEM fields blank retains the existing files.

HTTPS changes take effect after a process or container restart. When HTTPS is enabled, plain HTTP requests to the public port are rejected.

## Use standard HTTPS port 443

The application can keep listening on container port `8833` while Docker publishes standard port `443`:

```yaml
ports:
  - "1194:1194/tcp"
  - "443:8833/tcp"
```

Set the Site URL to a URL without the internal container port:

```text
https://vpn.example.com
```

After changing the Compose port mapping:

```bash
docker compose up -d
```

Do not publish both the HTTP and HTTPS versions of the management application. If a reverse proxy or cloud load balancer terminates TLS instead, keep the application port bound to loopback or a private network and do not enable native HTTPS.

## Network access policy

Recommended inbound rules:

- TCP `1194`: allow the expected VPN client source ranges. Use `0.0.0.0/0` only when roaming clients require unrestricted source addresses.
- TCP `443`: allow Web portal users after HTTPS is enabled.
- TCP `8833`: do not expose when Docker publishes `443:8833`. During initial setup, restrict it to a trusted administrator address or use an SSH tunnel.
- TCP `22`: restrict SSH to trusted administration addresses.

Example setup tunnel without exposing port `8833` publicly:

```bash
ssh -L 8833:127.0.0.1:8833 root@vpn.example.com
```

Then open `http://127.0.0.1:8833`, configure the certificate, restart the service, and switch the cloud firewall to the final HTTPS port.

Cloud security groups are evaluated before the host firewall. A service can be healthy and listening locally while public connections still time out if its security group does not permit the port.

## Certificate renewal and replacement

To replace the Web certificate:

1. Paste the new certificate chain and matching private key in Settings.
2. Save the General section.
3. Restart the container.
4. Verify the served certificate and expiration date.

```bash
openssl s_client -connect vpn.example.com:443 -servername vpn.example.com </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates
```

Web HTTPS certificates are independent of the OpenVPN CA, server certificate, client certificates, CRL, and `tls-crypt` key. Replacing one set does not rotate the other.

## Upgrade

Back up persistent data first:

```bash
cd /opt/openvpn-web
tar -czf openvpn-data-$(date +%Y%m%d%H%M%S).tar.gz data
```

Update the immutable image tag in `docker-compose.yml`, then run:

```bash
docker compose pull
docker compose up -d
docker compose ps
docker compose logs --tail=100 openvpn
```

Verify all of the following:

- The container health status is `healthy`.
- `openvpn` and `openvpn-web` are `RUNNING` under Supervisor.
- The login page responds over the configured HTTP or HTTPS scheme.
- The OpenVPN port accepts TCP connections.
- A test VPN account can authenticate and reach an expected route.

## Rollback

To roll back application code:

1. Restore the previous immutable image tag in `docker-compose.yml`.
2. Run `docker compose pull`.
3. Run `docker compose up -d`.

Restore the persistent data backup only when a data migration or configuration change is known to be incompatible. Restoring data replaces current accounts, certificates, configuration, and connection history.

## Troubleshooting

### Public connection times out

Check the layers in this order:

```bash
docker compose ps
docker exec openvpn-web supervisorctl status
ss -lntp
iptables -S INPUT
nft list ruleset
```

If Docker DNAT counters remain at zero during an external connection attempt, inspect the cloud security group, public IP association, and upstream firewall.

### HTTPS does not start

Inspect logs without printing private key material:

```bash
docker compose logs --tail=100 openvpn
stat -c '%a %n' data/tls/server.crt data/tls/server.key
```

Typical causes are missing files, an expired certificate, a private key mismatch, or invalid PEM formatting. To recover, correct the certificate files or set `system.base.https_enabled` to `false` in `data/config.json`, then restart the container.

### VPN authentication fails after enabling HTTPS

Confirm that the internal listener is active and the OpenVPN callback URLs use port `8834`:

```bash
docker exec openvpn-web sh -lc 'netstat -lnt; grep "setenv .*_api" /data/server.conf'
```

Expected callback URLs begin with:

```text
http://127.0.0.1:8834/
```

Restart the container after enabling HTTPS so both the Web listener and OpenVPN process load the updated configuration.
