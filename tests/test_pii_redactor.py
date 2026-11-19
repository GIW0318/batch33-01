import threading

import pytest

import pii_redactor as pr


def redactor():
    return pr.PiiRedactor()


def test_email_is_redacted():
    result = redactor().redact("contact alice@example.com")
    assert "alice@example.com" not in result
    assert "[email]" in result


def test_phone_is_redacted():
    result = redactor().redact("phone 13800138000")
    assert "13800138000" not in result
    assert "[phone]" in result


def test_id_is_redacted():
    result = redactor().redact("id 110101199001011234")
    assert "110101199001011234" not in result
    assert "[id]" in result


def test_ipv4_is_redacted():
    result = redactor().redact("ip 10.0.0.1")
    assert "10.0.0.1" not in result
    assert "[ip]" in result


def test_nested_dict_is_redacted():
    result = redactor().redact({"user": {"email": "a@example.com"}})
    assert "a@example.com" not in str(result)
    assert "[email]" in str(result)


def test_list_is_redacted():
    result = redactor().redact(["a@example.com"])
    assert "a@example.com" not in str(result)
    assert "[email]" in str(result)


def test_multiple_matches_are_redacted():
    result = redactor().redact("a@example.com and b@example.com")
    assert "a@example.com" not in result and "b@example.com" not in result
    assert result.count("[email]") == 2


def test_version_number_is_not_ip():
    result = redactor().redact("version 1.2.3.4 contact a@example.com")
    assert "1.2.3.4" in result
    assert "[email]" in result


def test_input_is_not_mutated():
    source = {"email": "a@example.com"}
    result = redactor().redact(source)
    assert "[email]" in str(result)
    assert source["email"] == "a@example.com"


def test_redaction_is_idempotent():
    game = redactor()
    once = game.redact("a@example.com")
    assert "[email]" in once
    assert game.redact(once) == once


def test_non_string_is_preserved():
    result = redactor().redact({"n": 123, "email": "a@example.com"})
    assert result["n"] == 123
    assert "[email]" in result["email"]


def test_random_pii_strings_are_redacted():
    game = redactor()
    for i in range(300):
        result = game.redact(f"user{i}@example.com")
        assert "[email]" in result
        assert "@example.com" not in result


def test_concurrent_redaction_is_stable():
    game = redactor()
    results = []

    def worker():
        results.append(game.redact("a@example.com 13800138000"))

    threads = [threading.Thread(target=worker) for _ in range(32)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(results) == 32
    assert len(set(results)) == 1
    assert "[email]" in results[0]


def test_dict_keys_are_preserved():
    result = redactor().redact({"email": "a@example.com"})
    assert "email" in result
    assert "[email]" in result["email"]


def test_multiple_pii_types_in_one_string():
    result = redactor().redact("a@example.com 13800138000")
    assert "a@example.com" not in result and "13800138000" not in result
    assert "[email]" in result and "[phone]" in result
