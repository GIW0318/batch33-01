import pytest

import csv_guard as cg


def guard():
    return cg.CsvGuard()


def test_plain_text_is_unchanged():
    assert guard().sanitize("alice") == "alice"


def test_equals_prefix_is_escaped():
    assert guard().sanitize("=1+1") == "'=1+1"


def test_plus_prefix_is_escaped():
    assert guard().sanitize("+1") == "'+1"


def test_minus_prefix_is_escaped():
    assert guard().sanitize("-1") == "'-1"


def test_at_prefix_is_escaped():
    assert guard().sanitize("@SUM(A1)") == "'@SUM(A1)"


def test_tab_prefix_is_escaped():
    assert guard().sanitize("\t=1") == "'\t=1"


def test_carriage_return_prefix_is_escaped():
    assert guard().sanitize("\r=1") == "'\r=1"


def test_nul_is_rejected():
    with pytest.raises(ValueError):
        guard().sanitize("a\x00b")


def test_non_string_is_converted():
    assert guard().sanitize(123) == "123"


def test_row_joins_plain_values():
    assert guard().row(["a", "b"]) == "a,b"


def test_row_quotes_comma_field():
    assert guard().row(["a,b", "c"]) == '"a,b",c'


def test_row_doubles_quotes():
    assert guard().row(['a"b', "c"]) == '"a""b",c'


def test_row_sanitizes_each_field():
    assert guard().row(["=1", "ok"]) == "'=1,ok"


def test_empty_row():
    assert guard().row([]) == ""


def test_row_rejects_nul():
    with pytest.raises(ValueError):
        guard().row(["ok", "a\x00b"])
