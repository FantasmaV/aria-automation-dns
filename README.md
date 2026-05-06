# aria-automation-dns

**Aria Automation ABX Action — Microsoft DNS Dynamic Update**

Manages DNS A and PTR records in Microsoft DNS during VM provisioning and deprovisioning. Completes the Aria Automation end-to-end provisioning pipeline alongside `vm-naming-convention` and `aria-automation-ipam`.

---

## Provisioning Pipeline

```
vm-naming-convention  →  aria-automation-ipam  →  aria-automation-dns
     VM Name          →       IP Address        →      DNS Record
VM-PROD-WEB-TXD-001   →    192.168.10.45        →  A + PTR registered
```

---

## What it does

- Registers **A records** and **PTR records** in Microsoft DNS during provisioning
- Removes both record types cleanly during deprovisioning
- Validates for hostname and IP conflicts before registering
- Uses RFC 2136 dynamic DNS updates via `dnspython` — no WinRM required
- Supports TSIG authenticated updates for secure DNS environments

---

## Request Types

| Type | Description |
|---|---|
| `REGISTER` | Conflict check then create A + PTR records |
| `DEREGISTER` | Remove A + PTR records, skip gracefully if not found |
| `VALIDATE` | Dry-run conflict check — no changes made |

---

## DNS Record Format

```
A Record:   VM-PROD-WEB-TXD-001.corp.contoso.com  →  192.168.10.45
PTR Record: 45.10.168.192.in-addr.arpa             →  VM-PROD-WEB-TXD-001.corp.contoso.com
```

---

## Inputs / Outputs

**Inputs (from Aria blueprint):**

| Key | Type | Required | Description |
|---|---|---|---|
| `vmName` | string | ✅ | VM hostname (from vm-naming-convention) |
| `ipAddress` | string | ✅ | IP address (from aria-automation-ipam) |
| `requestType` | string | ✅ | REGISTER / DEREGISTER / VALIDATE |
| `dnsZone` | string | ❌ | DNS zone override (defaults to DNS_ZONE env var) |
| `ttl` | int | ❌ | TTL in seconds (default 300) |

**Outputs:**

| Key | Type | Description |
|---|---|---|
| `status` | string | `registered` / `deregistered` / `validated` / `conflict` |
| `vmName` | string | Fully qualified domain name |
| `ipAddress` | string | IP address operated on |
| `aRecord` | string | A record result |
| `ptrRecord` | string | PTR record result |
| `message` | string | Human-readable result summary |

---

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `DNS_SERVER` | ✅ | IP address of the Microsoft DNS server |
| `DNS_ZONE` | ✅ | Forward lookup zone (e.g. `corp.contoso.com`) |
| `DNS_KEY_NAME` | ❌ | TSIG key name for authenticated updates |
| `DNS_KEY_SECRET` | ❌ | TSIG key secret (base64) |
| `DNS_KEY_ALGORITHM` | ❌ | TSIG algorithm (default: `hmac-sha256`) |
| `DNS_TTL` | ❌ | Default TTL in seconds (default: `300`) |
| `DNS_TIMEOUT` | ❌ | Query timeout in seconds (default: `10`) |

---

## Dependencies

```bash
pip install dnspython
```

---

## Running Tests

```bash
pip install pytest dnspython
pytest tests/test_dns_update.py -v
```

Tests use `unittest.mock` — no live DNS server required.

---

## Author

**Randolph Barden** — [@FantasmaV](https://github.com/FantasmaV)

Senior VCF / Aria Automation Engineer | VMware by Broadcom
