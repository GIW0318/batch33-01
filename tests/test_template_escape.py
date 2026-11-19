import pytest

import template_escape as te


def esc():
    return te.TemplateEscaper()


def test_html_escapes_tags():
    assert esc().escape("<b>", "html") == "&lt;b&gt;"


def test_html_escapes_ampersand():
    assert esc().escape("a&b", "html") == "a&amp;b"


def test_attr_escapes_quotes():
    assert esc().escape('" onmouseover="x', "attr") == "&quot; onmouseover=&quot;x"


def test_attr_escapes_single_quote():
    assert esc().escape("'x", "attr") == "&#39;x"


def test_js_escapes_quotes_and_backslash():
    assert esc().escape('"\\', "js") == "\\\"\\\\"


def test_js_escapes_newline():
    assert esc().escape("a\nb", "js") == "a\\nb"


def test_js_escapes_script_close():
    assert esc().escape("</script>", "js") == "<\\/script>"


def test_css_escapes_non_alnum():
    assert esc().escape("a b", "css") == "a\\20 b"


def test_url_encodes_space_and_quote():
    assert esc().escape('a b"', "url") == "a%20b%22"


def test_unknown_context_raises():
    with pytest.raises(ValueError):
        esc().escape("x", "xml")


def test_non_string_raises():
    with pytest.raises(ValueError):
        esc().escape(1, "html")


def test_nul_is_rejected():
    with pytest.raises(ValueError):
        esc().escape("a\x00b", "html")


def test_control_char_is_rejected():
    with pytest.raises(ValueError):
        esc().escape("a\x01b", "attr")


def test_plain_text_unchanged_in_html():
    assert esc().escape("hello", "html") == "hello"


def test_context_is_case_sensitive():
    with pytest.raises(ValueError):
        esc().escape("x", "HTML")
