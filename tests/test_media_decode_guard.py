import pytest

import media_decode_guard as md


def guard(max_pixels=1000000, max_bytes=1000000):
    return md.MediaDecodeGuard(max_pixels, max_bytes)


def header(**overrides):
    value = {"format": "png", "width": 100, "height": 100, "channels": 4, "bytes": 1000, "frames": 1, "has_external": False}
    value.update(overrides)
    return value


def test_valid_image():
    result = guard().inspect(header())
    assert result["width"] == 100


def test_unknown_format_raises():
    with pytest.raises(ValueError):
        guard().inspect(header(format="exe"))


def test_too_many_pixels_raises():
    with pytest.raises(ValueError):
        guard(max_pixels=100).inspect(header(width=20, height=20))


def test_too_many_bytes_raises():
    with pytest.raises(ValueError):
        guard(max_bytes=100).inspect(header(bytes=1000))


def test_negative_width_raises():
    with pytest.raises(ValueError):
        guard().inspect(header(width=-1))


def test_zero_height_raises():
    with pytest.raises(ValueError):
        guard().inspect(header(height=0))


def test_animated_frames_limit():
    with pytest.raises(ValueError):
        guard().inspect(header(format="gif", frames=1000))


def test_non_integer_dimension_raises():
    with pytest.raises(ValueError):
        guard().inspect(header(width=1.5))


def test_external_metadata_is_stripped():
    result = guard().inspect(header(has_external=True))
    assert result["has_external"] is False


def test_pixel_count_is_reported():
    assert guard().inspect(header(width=10, height=20))["pixels"] == 200


def test_compression_ratio_is_checked():
    with pytest.raises(ValueError):
        guard(max_bytes=10000).inspect(header(width=1000, height=1000, bytes=10))


def test_gif_single_frame_allowed():
    assert guard().inspect(header(format="gif", frames=1))["format"] == "gif"


def test_invalid_channels_raises():
    with pytest.raises(ValueError):
        guard().inspect(header(channels=0))


def test_invalid_header_type_raises():
    with pytest.raises(ValueError):
        guard().inspect([])


def test_metadata_is_normalized():
    result = guard().inspect(header(format="jpeg"))
    assert result["format"] == "jpeg"
