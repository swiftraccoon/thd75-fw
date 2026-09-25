"""Tests for the theme colour model."""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from thd75_fw.theme.colour import (
    DEEP_ORANGE,
    TRANSPARENT_KEY,
    colourise,
    colourise_rgb,
    invert,
    is_achromatic,
    luminance,
    rgb565_to_rgb,
    rgb_to_rgb565,
)


class TestConversions:
    def test_deep_orange_is_fc60(self) -> None:
        assert rgb_to_rgb565(DEEP_ORANGE) == 0xFC60

    @pytest.mark.parametrize(
        ("value", "rgb"),
        [
            (0xFFFF, (255, 255, 255)),
            (0x0000, (0, 0, 0)),
            (0x528A, (82, 81, 82)),
            (0xF800, (255, 0, 0)),
            (0x3314, (49, 97, 165)),
        ],
    )
    def test_rgb565_to_rgb_known_values(
        self, value: int, rgb: tuple[int, int, int]
    ) -> None:
        assert rgb565_to_rgb(value) == rgb

    def test_out_of_range_rejected(self) -> None:
        with pytest.raises(ValueError, match="RGB565"):
            _ = rgb565_to_rgb(0x10000)
        with pytest.raises(ValueError, match="component"):
            _ = rgb_to_rgb565((256, 0, 0))

    @given(st.integers(min_value=0, max_value=0xFFFF))
    def test_round_trip_is_stable(self, value: int) -> None:
        assert rgb_to_rgb565(rgb565_to_rgb(value)) == value


class TestClassification:
    def test_greys_are_achromatic(self) -> None:
        assert is_achromatic((197, 194, 197))
        assert is_achromatic((255, 255, 255))
        assert not is_achromatic((255, 0, 0))
        assert not is_achromatic((49, 97, 165))

    def test_luminance_of_white_and_black(self) -> None:
        assert abs(luminance((255, 255, 255)) - 1.0) < 1e-9
        assert luminance((0, 0, 0)) == 0.0


class TestColourise:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            (0xFFFF, 0xFC60),  # white -> full deep orange
            (0x0000, 0x0000),  # black stays black
            (0x528A, 0x5160),  # grey 32% -> dark orange
            (0xC618, 0xC340),  # grey 76% -> lighter orange
            (0x2104, 0x2080),  # grey 13% -> very dark orange
            (0xF800, 0xF800),  # red stays red
            (0x3314, 0x3314),  # blue stays blue
            (TRANSPARENT_KEY, TRANSPARENT_KEY),
        ],
    )
    def test_colourise_known_values(self, value: int, expected: int) -> None:
        assert colourise(value, DEEP_ORANGE) == expected

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            (0xFFFF, 0x0000),  # white -> black
            (0x0000, 0xFC60),  # black -> full deep orange
            (0x528A, 0xAAE0),  # grey 32% -> orange at 68%
            (0xC618, 0x3900),  # grey 76% -> orange at 24%
            (0xF800, 0xF800),
            (TRANSPARENT_KEY, TRANSPARENT_KEY),
        ],
    )
    def test_invert_known_values(self, value: int, expected: int) -> None:
        assert invert(value, DEEP_ORANGE) == expected

    def test_colourise_rgb_keeps_chromatic(self) -> None:
        assert colourise_rgb((44, 127, 172), DEEP_ORANGE) == (44, 127, 172)
        assert colourise_rgb((255, 255, 255), DEEP_ORANGE) == (255, 140, 0)

    @given(st.integers(min_value=0, max_value=0xFFFF))
    def test_results_stay_in_range_and_chromatic_is_identity(self, value: int) -> None:
        out = colourise(value, DEEP_ORANGE)
        assert 0 <= out <= 0xFFFF
        assert 0 <= invert(value, DEEP_ORANGE) <= 0xFFFF
        if not is_achromatic(rgb565_to_rgb(value)):
            assert out == value
