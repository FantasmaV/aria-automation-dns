"""
test_dns_update.py
------------------
Unit tests for the Aria Automation ABX Action — Microsoft DNS Dynamic Update.

Tests cover REGISTER, DEREGISTER, and VALIDATE request types, conflict
detection, PTR record management, and all error paths. DNS queries and
updates are fully mocked — no live DNS server required.

Run with:
    pytest tests/test_dns_update.py -v
"""

import pytest
from unittest.mock import patch, MagicMock
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../abx-actions'))
import dns_update


# ── Fixtures ───────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def set_env_vars(monkeypatch):
    """Set required environment variables for every test."""
    monkeypatch.setattr(dns_update, "DNS_SERVER", "192.168.1.10")
    monkeypatch.setattr(dns_update, "DNS_ZONE",   "corp.contoso.com")
    monkeypatch.setattr(dns_update, "DNS_TTL",    300)
    monkeypatch.setattr(dns_update, "DNS_TIMEOUT", 10)
    monkeypatch.setattr(dns_update, "DNS_KEY_NAME",   "")
    monkeypatch.setattr(dns_update, "DNS_KEY_SECRET",  "")


@pytest.fixture
def base_inputs():
    """Base valid inputs for a REGISTER request."""
    return {
        "vmName":      "VM-PROD-WEB-TXD-001",
        "ipAddress":   "192.168.10.45",
        "requestType": "REGISTER",
        "dnsZone":     "corp.contoso.com",
    }


# ── handler() routing tests ────────────────────────────────────────────────────

class TestHandlerRouting:

    def test_raises_on_missing_vm_name(self, base_inputs):
        """handler() should raise KeyError if vmName missing."""
        del base_inputs["vmName"]
        with pytest.raises(KeyError, match="vmName"):
            dns_update.handler(context=None, inputs=base_inputs)

    def test_raises_on_missing_ip_address(self, base_inputs):
        """handler() should raise KeyError if ipAddress missing."""
        del base_inputs["ipAddress"]
        with pytest.raises(KeyError, match="ipAddress"):
            dns_update.handler(context=None, inputs=base_inputs)

    def test_raises_on_invalid_request_type(self, base_inputs):
        """handler() should raise ValueError for unknown requestType."""
        base_inputs["requestType"] = "UPDATE"
        with patch("dns_update._query_a_record", return_value=""):
            with pytest.raises(ValueError, match="Invalid requestType"):
                dns_update.handler(context=None, inputs=base_inputs)

    def test_raises_on_invalid_ip_format(self, base_inputs):
        """handler() should raise ValueError for malformed IP address."""
        base_inputs["ipAddress"] = "not-an-ip"
        with pytest.raises(ValueError, match="Invalid IP address"):
            dns_update.handler(context=None, inputs=base_inputs)

    def test_raises_when_dns_server_not_configured(self, base_inputs, monkeypatch):
        """handler() should raise EnvironmentError if DNS_SERVER not set."""
        monkeypatch.setattr(dns_update, "DNS_SERVER", "")
        with pytest.raises(EnvironmentError, match="DNS_SERVER"):
            dns_update.handler(context=None, inputs=base_inputs)

    def test_raises_when_dns_zone_not_configured(self, base_inputs, monkeypatch):
        """handler() should raise EnvironmentError if DNS_ZONE not set."""
        monkeypatch.setattr(dns_update, "DNS_ZONE", "")
        with pytest.raises(EnvironmentError, match="DNS_ZONE"):
            dns_update.handler(context=None, inputs=base_inputs)

    def test_normalizes_vm_name_to_uppercase(self, base_inputs):
        """handler() should normalize vmName to uppercase."""
        base_inputs["vmName"] = "vm-prod-web-txd-001"
        with patch("dns_update._query_a_record", return_value=""), \
             patch("dns_update._query_ptr_record", return_value=""), \
             patch("dns_update._update_dns"):
            result = dns_update.handler(context=None, inputs=base_inputs)
        assert "VM-PROD-WEB-TXD-001" in result["vmName"]


# ── REGISTER tests ─────────────────────────────────────────────────────────────

class TestHandleRegister:

    def test_register_success_no_conflicts(self, base_inputs):
        """REGISTER should succeed when no existing A or PTR records."""
        with patch("dns_update._query_a_record",   return_value=""), \
             patch("dns_update._query_ptr_record",  return_value=""), \
             patch("dns_update._update_dns") as mock_update:
            result = dns_update.handler(context=None, inputs=base_inputs)

        assert result["status"]    == "registered"
        assert "192.168.10.45"     in result["ipAddress"]
        assert mock_update.call_count == 2  # A record + PTR record

    def test_register_raises_on_existing_a_record(self, base_inputs):
        """REGISTER should raise ValueError if A record already exists."""
        with patch("dns_update._query_a_record", return_value="192.168.10.45"):
            with pytest.raises(ValueError, match="A record already exists"):
                dns_update.handler(context=None, inputs=base_inputs)

    def test_register_raises_on_existing_ptr_record(self, base_inputs):
        """REGISTER should raise ValueError if PTR record already exists."""
        with patch("dns_update._query_a_record",  return_value=""), \
             patch("dns_update._query_ptr_record", return_value="existing-vm.corp.contoso.com"):
            with pytest.raises(ValueError, match="PTR record already exists"):
                dns_update.handler(context=None, inputs=base_inputs)

    def test_register_creates_both_records(self, base_inputs):
        """REGISTER should create both A and PTR records."""
        update_calls = []
        def mock_update(zone, record_name, record_type, record_value, ttl, operation):
            update_calls.append(record_type)

        with patch("dns_update._query_a_record",  return_value=""), \
             patch("dns_update._query_ptr_record", return_value=""), \
             patch("dns_update._update_dns", side_effect=mock_update):
            dns_update.handler(context=None, inputs=base_inputs)

        assert "A"   in update_calls
        assert "PTR" in update_calls

    def test_register_result_contains_fqdn(self, base_inputs):
        """REGISTER result should contain the full FQDN."""
        with patch("dns_update._query_a_record",  return_value=""), \
             patch("dns_update._query_ptr_record", return_value=""), \
             patch("dns_update._update_dns"):
            result = dns_update.handler(context=None, inputs=base_inputs)

        assert "VM-PROD-WEB-TXD-001.corp.contoso.com" in result["vmName"]

    def test_register_uses_custom_ttl(self, base_inputs):
        """REGISTER should use TTL from inputs when provided."""
        base_inputs["ttl"] = 600
        ttl_used = []

        def mock_update(zone, record_name, record_type, record_value, ttl, operation):
            ttl_used.append(ttl)

        with patch("dns_update._query_a_record",  return_value=""), \
             patch("dns_update._query_ptr_record", return_value=""), \
             patch("dns_update._update_dns", side_effect=mock_update):
            dns_update.handler(context=None, inputs=base_inputs)

        assert all(t == 600 for t in ttl_used)


# ── DEREGISTER tests ───────────────────────────────────────────────────────────

class TestHandleDeregister:

    def test_deregister_removes_both_records(self, base_inputs):
        """DEREGISTER should remove both A and PTR records when found."""
        base_inputs["requestType"] = "DEREGISTER"
        delete_calls = []

        def mock_update(zone, record_name, record_type, record_value, ttl, operation):
            delete_calls.append((record_type, operation))

        with patch("dns_update._query_a_record",   return_value="192.168.10.45"), \
             patch("dns_update._query_ptr_record",  return_value="VM-PROD-WEB-TXD-001.corp.contoso.com"), \
             patch("dns_update._update_dns", side_effect=mock_update):
            result = dns_update.handler(context=None, inputs=base_inputs)

        assert result["status"] == "deregistered"
        assert ("A",   "delete") in delete_calls
        assert ("PTR", "delete") in delete_calls

    def test_deregister_skips_missing_a_record(self, base_inputs):
        """DEREGISTER should skip A removal gracefully if record not found."""
        base_inputs["requestType"] = "DEREGISTER"

        with patch("dns_update._query_a_record",   return_value=""), \
             patch("dns_update._query_ptr_record",  return_value="VM-PROD-WEB-TXD-001.corp.contoso.com"), \
             patch("dns_update._update_dns") as mock_update:
            result = dns_update.handler(context=None, inputs=base_inputs)

        assert result["status"] == "deregistered"
        assert "Not found" in result["aRecord"]

    def test_deregister_skips_missing_ptr_record(self, base_inputs):
        """DEREGISTER should skip PTR removal gracefully if record not found."""
        base_inputs["requestType"] = "DEREGISTER"

        with patch("dns_update._query_a_record",   return_value="192.168.10.45"), \
             patch("dns_update._query_ptr_record",  return_value=""), \
             patch("dns_update._update_dns"):
            result = dns_update.handler(context=None, inputs=base_inputs)

        assert result["status"] == "deregistered"
        assert "Not found" in result["ptrRecord"]


# ── VALIDATE tests ─────────────────────────────────────────────────────────────

class TestHandleValidate:

    def test_validate_no_conflicts(self, base_inputs):
        """VALIDATE should return canRegister True when no conflicts exist."""
        base_inputs["requestType"] = "VALIDATE"
        with patch("dns_update._query_a_record",  return_value=""), \
             patch("dns_update._query_ptr_record", return_value=""):
            result = dns_update.handler(context=None, inputs=base_inputs)

        assert result["status"]      == "validated"
        assert result["canRegister"] == True
        assert result["hasConflict"] == False

    def test_validate_detects_a_record_conflict(self, base_inputs):
        """VALIDATE should detect existing A record conflict."""
        base_inputs["requestType"] = "VALIDATE"
        with patch("dns_update._query_a_record",  return_value="192.168.10.45"), \
             patch("dns_update._query_ptr_record", return_value=""):
            result = dns_update.handler(context=None, inputs=base_inputs)

        assert result["status"]      == "conflict"
        assert result["canRegister"] == False
        assert result["hasConflict"] == True

    def test_validate_detects_ptr_record_conflict(self, base_inputs):
        """VALIDATE should detect existing PTR record conflict."""
        base_inputs["requestType"] = "VALIDATE"
        with patch("dns_update._query_a_record",  return_value=""), \
             patch("dns_update._query_ptr_record", return_value="other-vm.corp.contoso.com"):
            result = dns_update.handler(context=None, inputs=base_inputs)

        assert result["status"]      == "conflict"
        assert result["canRegister"] == False

    def test_validate_no_dns_changes_made(self, base_inputs):
        """VALIDATE should never call _update_dns."""
        base_inputs["requestType"] = "VALIDATE"
        with patch("dns_update._query_a_record",  return_value=""), \
             patch("dns_update._query_ptr_record", return_value=""), \
             patch("dns_update._update_dns") as mock_update:
            dns_update.handler(context=None, inputs=base_inputs)

        mock_update.assert_not_called()


# ── Utility helper tests ───────────────────────────────────────────────────────

class TestUtilityHelpers:

    def test_get_reverse_zone_class_c(self):
        """_get_reverse_zone() should return correct Class C reverse zone."""
        zone = dns_update._get_reverse_zone("192.168.10.45")
        assert zone == "10.168.192.in-addr.arpa"

    def test_get_reverse_zone_different_subnets(self):
        """_get_reverse_zone() should handle different subnets correctly."""
        assert dns_update._get_reverse_zone("10.0.1.100")  == "1.0.10.in-addr.arpa"
        assert dns_update._get_reverse_zone("172.16.5.22") == "5.16.172.in-addr.arpa"

    def test_get_keyring_returns_none_when_no_credentials(self, monkeypatch):
        """_get_keyring() should return None when no TSIG credentials set."""
        monkeypatch.setattr(dns_update, "DNS_KEY_NAME",   "")
        monkeypatch.setattr(dns_update, "DNS_KEY_SECRET",  "")
        assert dns_update._get_keyring() is None
