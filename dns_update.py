"""
dns_update.py
-------------
Aria Automation ABX Action — Microsoft DNS Dynamic Update

Manages DNS A and PTR records in Microsoft DNS during VM provisioning
and deprovisioning workflows. Uses the dnspython library to send
RFC 2136 dynamic DNS update messages directly to the DNS server.

Completes the Aria Automation provisioning pipeline:
    vm-naming-convention  →  aria-automation-ipam  →  aria-automation-dns
         VM Name          →       IP Address        →      DNS Record

Naming Convention:
    A Record:   {vmName}.{dnsZone}  →  {ipAddress}
    PTR Record: {reverse}.in-addr.arpa  →  {vmName}.{dnsZone}

Request Types:
    REGISTER    → Validate no conflicts, create A + PTR records
    DEREGISTER  → Remove A + PTR records for the VM
    VALIDATE    → Dry-run check for hostname/IP conflicts

Environment Variables (set in Aria Automation ABX Action properties):
    DNS_SERVER          IP address of the Microsoft DNS server
    DNS_ZONE            Forward lookup zone (e.g. corp.contoso.com)
    DNS_KEY_NAME        TSIG key name for authenticated updates (optional)
    DNS_KEY_SECRET      TSIG key secret (base64) for authenticated updates (optional)
    DNS_KEY_ALGORITHM   TSIG algorithm (default: hmac-sha256)
    DNS_TTL             Default TTL in seconds (default: 300)
    DNS_TIMEOUT         Query timeout in seconds (default: 10)

Author: Randolph Barden
Repo:   github.com/FantasmaV/aria-automation-dns
"""

import os
import logging
import ipaddress

import dns.resolver
import dns.update
import dns.query
import dns.rdatatype
import dns.rdata
import dns.reversename
import dns.tsigkeyring
import dns.name

# ── Logging ────────────────────────────────────────────────────────────────────
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# ── Configuration ──────────────────────────────────────────────────────────────
DNS_SERVER        = os.environ.get("DNS_SERVER", "")
DNS_ZONE          = os.environ.get("DNS_ZONE", "")
DNS_KEY_NAME      = os.environ.get("DNS_KEY_NAME", "")
DNS_KEY_SECRET    = os.environ.get("DNS_KEY_SECRET", "")
DNS_KEY_ALGORITHM = os.environ.get("DNS_KEY_ALGORITHM", "hmac-sha256")
DNS_TTL           = int(os.environ.get("DNS_TTL", "300"))
DNS_TIMEOUT       = int(os.environ.get("DNS_TIMEOUT", "10"))

ALLOWED_REQUEST_TYPES = {"REGISTER", "DEREGISTER", "VALIDATE"}


# ── ABX Entry Point ────────────────────────────────────────────────────────────
def handler(context, inputs: dict) -> dict:
    """
    ABX handler called by Aria Automation during VM provisioning/deprovisioning.

    Routes the request to the appropriate DNS operation based on requestType.
    Designed to consume outputs from aria-automation-ipam and
    vm-naming-convention as upstream inputs.

    Args:
        context: Aria Automation execution context (unused directly).
        inputs:  Dictionary of inputs passed from the Aria blueprint.
                 Expected keys:
                   - vmName (str):      VM hostname (from vm-naming-convention).
                   - ipAddress (str):   VM IP address (from aria-automation-ipam).
                   - requestType (str): REGISTER / DEREGISTER / VALIDATE.
                   - dnsZone (str):     Target DNS zone (overrides env var).
                   - ttl (int):         TTL in seconds (optional, default 300).

    Returns:
        dict with keys:
          - status (str):      "registered" / "deregistered" / "validated" / "conflict"
          - vmName (str):      Fully qualified domain name.
          - ipAddress (str):   IP address operated on.
          - aRecord (str):     A record created/removed.
          - ptrRecord (str):   PTR record created/removed.
          - message (str):     Human-readable result summary.

    Raises:
        ValueError:        If inputs are invalid or DNS operation fails.
        KeyError:          If required inputs are missing.
        EnvironmentError:  If required environment variables are not set.
    """
    logger.info("[dns] Starting DNS update action")

    # ── Validate environment configuration ────────────────────────────────────
    _validate_config()

    # ── Extract and normalize inputs ──────────────────────────────────────────
    try:
        vm_name      = inputs["vmName"].strip().upper()
        ip_address   = inputs["ipAddress"].strip()
        request_type = inputs["requestType"].strip().upper()
    except KeyError as e:
        raise KeyError(f"Required input missing from blueprint: {e}")

    dns_zone = inputs.get("dnsZone", DNS_ZONE).strip().rstrip(".")
    ttl      = int(inputs.get("ttl", DNS_TTL))

    logger.info(
        f"[dns] VM: {vm_name} | IP: {ip_address} | "
        f"REQUEST: {request_type} | ZONE: {dns_zone}"
    )

    # ── Validate request type ─────────────────────────────────────────────────
    if request_type not in ALLOWED_REQUEST_TYPES:
        raise ValueError(
            f"Invalid requestType '{request_type}'. "
            f"Allowed values: {sorted(ALLOWED_REQUEST_TYPES)}"
        )

    # ── Validate IP address format ────────────────────────────────────────────
    try:
        ipaddress.IPv4Address(ip_address)
    except ValueError:
        raise ValueError(
            f"Invalid IP address '{ip_address}'. Must be a valid IPv4 address."
        )

    # ── Build FQDN ────────────────────────────────────────────────────────────
    fqdn = f"{vm_name}.{dns_zone}"

    # ── Build PTR record name ─────────────────────────────────────────────────
    ptr_name = str(dns.reversename.from_address(ip_address))

    logger.info(f"[dns] FQDN: {fqdn} | PTR: {ptr_name}")

    # ── Route to request handler ──────────────────────────────────────────────
    if request_type == "REGISTER":
        return handle_register(fqdn, ip_address, ptr_name, dns_zone, ttl, vm_name)
    elif request_type == "DEREGISTER":
        return handle_deregister(fqdn, ip_address, ptr_name, dns_zone, vm_name)
    elif request_type == "VALIDATE":
        return handle_validate(fqdn, ip_address, ptr_name, vm_name)


# ── REGISTER Handler ───────────────────────────────────────────────────────────
def handle_register(
    fqdn: str,
    ip_address: str,
    ptr_name: str,
    dns_zone: str,
    ttl: int,
    vm_name: str
) -> dict:
    """
    Validate no conflicts exist then register A and PTR records in Microsoft DNS.

    Steps:
        1. Check for existing A record conflict.
        2. Check for existing PTR record conflict.
        3. Send RFC 2136 dynamic update for A record.
        4. Send RFC 2136 dynamic update for PTR record.

    Args:
        fqdn:       Fully qualified domain name (e.g. VM-PROD-WEB-TXD-001.corp.contoso.com).
        ip_address: IPv4 address string.
        ptr_name:   Reverse DNS PTR record name.
        dns_zone:   Forward lookup zone name.
        ttl:        Time-to-live in seconds.
        vm_name:    Short hostname for logging.

    Returns:
        dict: Registration result with A and PTR record details.

    Raises:
        ValueError: If a conflicting record already exists.
    """
    logger.info(f"[dns] Processing REGISTER for {fqdn} → {ip_address}")

    # ── Conflict checks ────────────────────────────────────────────────────────
    existing_a = _query_a_record(fqdn)
    if existing_a:
        raise ValueError(
            f"DNS conflict — A record already exists for '{fqdn}': {existing_a}. "
            f"Deregister the existing record before creating a new one."
        )

    existing_ptr = _query_ptr_record(ip_address)
    if existing_ptr:
        raise ValueError(
            f"DNS conflict — PTR record already exists for '{ip_address}': {existing_ptr}. "
            f"Deregister the existing record before registering this IP."
        )

    # ── Register A record ──────────────────────────────────────────────────────
    _update_dns(
        zone=dns_zone,
        record_name=fqdn,
        record_type="A",
        record_value=ip_address,
        ttl=ttl,
        operation="add"
    )
    logger.info(f"[dns] A record registered: {fqdn} → {ip_address}")

    # ── Register PTR record ────────────────────────────────────────────────────
    reverse_zone = _get_reverse_zone(ip_address)
    _update_dns(
        zone=reverse_zone,
        record_name=ptr_name,
        record_type="PTR",
        record_value=f"{fqdn}.",
        ttl=ttl,
        operation="add"
    )
    logger.info(f"[dns] PTR record registered: {ptr_name} → {fqdn}")

    return {
        "status":    "registered",
        "vmName":    fqdn,
        "ipAddress": ip_address,
        "aRecord":   f"{fqdn} → {ip_address}",
        "ptrRecord": f"{ptr_name} → {fqdn}",
        "ttl":       ttl,
        "message":   f"DNS records registered successfully for '{vm_name}' ({ip_address}).",
    }


# ── DEREGISTER Handler ─────────────────────────────────────────────────────────
def handle_deregister(
    fqdn: str,
    ip_address: str,
    ptr_name: str,
    dns_zone: str,
    vm_name: str
) -> dict:
    """
    Remove A and PTR records from Microsoft DNS during VM deprovisioning.

    Args:
        fqdn:       Fully qualified domain name.
        ip_address: IPv4 address string.
        ptr_name:   Reverse DNS PTR record name.
        dns_zone:   Forward lookup zone name.
        vm_name:    Short hostname for logging.

    Returns:
        dict: Deregistration result with removed record details.
    """
    logger.info(f"[dns] Processing DEREGISTER for {fqdn}")

    removed_a   = False
    removed_ptr = False

    # ── Remove A record ────────────────────────────────────────────────────────
    existing_a = _query_a_record(fqdn)
    if existing_a:
        _update_dns(
            zone=dns_zone,
            record_name=fqdn,
            record_type="A",
            record_value=ip_address,
            ttl=0,
            operation="delete"
        )
        logger.info(f"[dns] A record removed: {fqdn}")
        removed_a = True
    else:
        logger.warning(f"[dns] No A record found for {fqdn} — skipping A removal")

    # ── Remove PTR record ──────────────────────────────────────────────────────
    existing_ptr = _query_ptr_record(ip_address)
    if existing_ptr:
        reverse_zone = _get_reverse_zone(ip_address)
        _update_dns(
            zone=reverse_zone,
            record_name=ptr_name,
            record_type="PTR",
            record_value=f"{fqdn}.",
            ttl=0,
            operation="delete"
        )
        logger.info(f"[dns] PTR record removed: {ptr_name}")
        removed_ptr = True
    else:
        logger.warning(f"[dns] No PTR record found for {ip_address} — skipping PTR removal")

    return {
        "status":    "deregistered",
        "vmName":    fqdn,
        "ipAddress": ip_address,
        "aRecord":   f"Removed: {fqdn}" if removed_a else f"Not found: {fqdn}",
        "ptrRecord": f"Removed: {ptr_name}" if removed_ptr else f"Not found: {ptr_name}",
        "message":   f"DNS deregistration complete for '{vm_name}' ({ip_address}).",
    }


# ── VALIDATE Handler ───────────────────────────────────────────────────────────
def handle_validate(
    fqdn: str,
    ip_address: str,
    ptr_name: str,
    vm_name: str
) -> dict:
    """
    Dry-run DNS conflict check without making any changes.

    Args:
        fqdn:       Fully qualified domain name.
        ip_address: IPv4 address string.
        ptr_name:   Reverse DNS PTR record name.
        vm_name:    Short hostname for logging.

    Returns:
        dict: Validation result with conflict details if found.
    """
    logger.info(f"[dns] Processing VALIDATE for {fqdn} / {ip_address}")

    existing_a   = _query_a_record(fqdn)
    existing_ptr = _query_ptr_record(ip_address)

    has_conflict = bool(existing_a or existing_ptr)
    status       = "conflict" if has_conflict else "validated"

    logger.info(
        f"[dns] VALIDATE result — A conflict: {bool(existing_a)} | "
        f"PTR conflict: {bool(existing_ptr)}"
    )

    return {
        "status":          status,
        "vmName":          fqdn,
        "ipAddress":       ip_address,
        "aRecord":         existing_a or "No conflict",
        "ptrRecord":       existing_ptr or "No conflict",
        "hasConflict":     has_conflict,
        "canRegister":     not has_conflict,
        "message": (
            f"DNS conflict detected for '{vm_name}' — "
            f"A: {existing_a}, PTR: {existing_ptr}"
            if has_conflict else
            f"No DNS conflicts found for '{vm_name}' ({ip_address}). Safe to register."
        ),
    }


# ── DNS Query Helpers ──────────────────────────────────────────────────────────
def _query_a_record(fqdn: str) -> str:
    """
    Query the DNS server for an existing A record.

    Args:
        fqdn: Fully qualified domain name to query.

    Returns:
        str: Existing IP address if A record found, empty string if not.
    """
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [DNS_SERVER]
        resolver.timeout     = DNS_TIMEOUT
        resolver.lifetime    = DNS_TIMEOUT

        answers = resolver.resolve(fqdn, "A")
        result  = str(answers[0])
        logger.info(f"[dns] Existing A record found: {fqdn} → {result}")
        return result

    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return ""
    except Exception as e:
        logger.warning(f"[dns] A record query error for {fqdn}: {e}")
        return ""


def _query_ptr_record(ip_address: str) -> str:
    """
    Query the DNS server for an existing PTR record.

    Args:
        ip_address: IPv4 address string to query.

    Returns:
        str: Existing hostname if PTR record found, empty string if not.
    """
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [DNS_SERVER]
        resolver.timeout     = DNS_TIMEOUT
        resolver.lifetime    = DNS_TIMEOUT

        ptr_name = dns.reversename.from_address(ip_address)
        answers  = resolver.resolve(ptr_name, "PTR")
        result   = str(answers[0])
        logger.info(f"[dns] Existing PTR record found: {ip_address} → {result}")
        return result

    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return ""
    except Exception as e:
        logger.warning(f"[dns] PTR record query error for {ip_address}: {e}")
        return ""


# ── DNS Update Helper ──────────────────────────────────────────────────────────
def _update_dns(
    zone: str,
    record_name: str,
    record_type: str,
    record_value: str,
    ttl: int,
    operation: str
) -> None:
    """
    Send an RFC 2136 dynamic DNS update to the Microsoft DNS server.

    Args:
        zone:         DNS zone to update.
        record_name:  Full record name.
        record_type:  Record type string ("A" or "PTR").
        record_value: Record value (IP for A, FQDN for PTR).
        ttl:          Time-to-live in seconds.
        operation:    "add" or "delete".

    Raises:
        ValueError: If the DNS update is rejected by the server.
    """
    update = dns.update.Update(zone, keyring=_get_keyring(), keyalgorithm=DNS_KEY_ALGORITHM)

    rd_type = dns.rdatatype.from_text(record_type)

    if operation == "add":
        update.add(record_name, ttl, rd_type, record_value)
    elif operation == "delete":
        update.delete(record_name, rd_type, record_value)

    response = dns.query.tcp(update, DNS_SERVER, timeout=DNS_TIMEOUT)

    rcode = response.rcode()
    if rcode != dns.rcode.NOERROR:
        raise ValueError(
            f"DNS update failed for {record_name} ({operation}). "
            f"Server returned rcode: {dns.rcode.to_text(rcode)}"
        )

    logger.info(f"[dns] DNS update successful — {operation} {record_type} {record_name}")


# ── Utility Helpers ────────────────────────────────────────────────────────────
def _get_keyring() -> dict:
    """
    Build TSIG keyring for authenticated DNS updates if credentials are set.

    Returns:
        dict: TSIG keyring dict, or None if no credentials configured.
    """
    if DNS_KEY_NAME and DNS_KEY_SECRET:
        return dns.tsigkeyring.make_keyring({DNS_KEY_NAME: DNS_KEY_SECRET})
    return None


def _get_reverse_zone(ip_address: str) -> str:
    """
    Derive the reverse lookup zone from an IPv4 address.

    Example: 192.168.10.45 → 10.168.192.in-addr.arpa

    Args:
        ip_address: IPv4 address string.

    Returns:
        str: Reverse lookup zone name.
    """
    parts = ip_address.split(".")
    return f"{parts[2]}.{parts[1]}.{parts[0]}.in-addr.arpa"


def _validate_config() -> None:
    """
    Validate required environment variables are set before processing.

    Raises:
        EnvironmentError: If DNS_SERVER or DNS_ZONE are not configured.
    """
    errors = []

    if not DNS_SERVER:
        errors.append("DNS_SERVER environment variable is not set.")
    if not DNS_ZONE:
        errors.append("DNS_ZONE environment variable is not set.")

    if errors:
        raise EnvironmentError(
            "DNS action configuration incomplete:\n" +
            "\n".join(f"  • {e}" for e in errors)
        )

    logger.info(f"[dns] Configuration validated — Server: {DNS_SERVER} | Zone: {DNS_ZONE}")
