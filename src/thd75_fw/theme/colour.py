"""RGB565 colour model for the display theme.

The TH-D75 framebuffer, its image palettes and its text palette are all
RGB565. A theme recolours the achromatic entries (white, greys, black)
of the White scheme's assets to shades of one theme colour and leaves
chromatic accents alone.
"""

from __future__ import annotations

from typing import Final, TypeAlias

__all__: list[str] = [
    "ACHROMATIC_SPREAD",
    "DEEP_ORANGE",
    "RGB",
    "TRANSPARENT_KEY",
    "colourise",
    "colourise_rgb",
    "invert",
    "invert_rgb",
    "is_achromatic",
    "luminance",
    "rgb565_to_rgb",
    "rgb_to_rgb565",
]

RGB: TypeAlias = tuple[int, int, int]
"""An 8-bit-per-channel colour."""

TRANSPARENT_KEY: int = 0xF81F
"""RGB565 magenta: the blitter's transparency key, never recoloured."""

ACHROMATIC_SPREAD: int = 24
"""Largest channel spread (max minus min, 0..255) still treated as grey."""

DEEP_ORANGE: RGB = (255, 140, 0)
"""The catalog theme colour, RGB565 0xFC60."""

_CHANNEL_MAX: Final[int] = 0xFF
"""Largest value of one 8-bit colour channel."""

_RGB565_MAX: Final[int] = 0xFFFF
"""Largest RGB565 word."""


def _check_rgb(colour: RGB) -> None:
    for component in colour:
        if isinstance(component, bool) or not 0 <= component <= _CHANNEL_MAX:
            msg = f"colour component out of range: {colour!r}"
            raise ValueError(msg)


def rgb565_to_rgb(value: int) -> RGB:
    """Expand an RGB565 word to 8-bit channels (rounded)."""
    if isinstance(value, bool) or not 0 <= value <= _RGB565_MAX:
        msg = f"RGB565 value out of range: {value!r}"
        raise ValueError(msg)
    red = (value >> 11) & 0x1F
    green = (value >> 5) & 0x3F
    blue = value & 0x1F
    return ((red * 255 + 15) // 31, (green * 255 + 31) // 63, (blue * 255 + 15) // 31)


def rgb_to_rgb565(colour: RGB) -> int:
    """Quantise 8-bit channels to an RGB565 word (rounded)."""
    _check_rgb(colour)
    red, green, blue = colour
    return (
        ((red * 31 + 127) // 255) << 11
        | ((green * 63 + 127) // 255) << 5
        | ((blue * 31 + 127) // 255)
    )


def luminance(colour: RGB) -> float:
    """Relative luminance in 0.0..1.0 (Rec. 709 weights on gamma-encoded channels)."""
    red, green, blue = colour
    return (0.2126 * red + 0.7152 * green + 0.0722 * blue) / 255


def is_achromatic(colour: RGB) -> bool:
    """Return True when the channel spread is within ``ACHROMATIC_SPREAD``."""
    return max(colour) - min(colour) <= ACHROMATIC_SPREAD


def _scaled(theme: RGB, factor: float) -> RGB:
    red, green, blue = theme
    return (round(red * factor), round(green * factor), round(blue * factor))


def colourise_rgb(colour: RGB, theme: RGB) -> RGB:
    """Map an achromatic colour to ``theme`` scaled by its luminance; keep chromatic ones."""
    _check_rgb(colour)
    _check_rgb(theme)
    if not is_achromatic(colour):
        return colour
    return _scaled(theme, luminance(colour))


def invert_rgb(colour: RGB, theme: RGB) -> RGB:
    """Map an achromatic colour to ``theme`` scaled by one minus its luminance."""
    _check_rgb(colour)
    _check_rgb(theme)
    if not is_achromatic(colour):
        return colour
    return _scaled(theme, 1.0 - luminance(colour))


def colourise(value: int, theme: RGB) -> int:
    """``colourise_rgb`` on an RGB565 word; the transparency key passes through."""
    if value == TRANSPARENT_KEY:
        return value
    return rgb_to_rgb565(colourise_rgb(rgb565_to_rgb(value), theme))


def invert(value: int, theme: RGB) -> int:
    """``invert_rgb`` on an RGB565 word; the transparency key passes through."""
    if value == TRANSPARENT_KEY:
        return value
    return rgb_to_rgb565(invert_rgb(rgb565_to_rgb(value), theme))
