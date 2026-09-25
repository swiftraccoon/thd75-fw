"""Display theme generator: recolours the TH-D75 White scheme."""

from __future__ import annotations

from .build import (
    DEFAULT_NAME,
    DEFAULT_TARGET,
    ThemeBuild,
    ThemeOptions,
    ThemeReport,
    build_theme,
)
from .colour import DEEP_ORANGE, RGB, colourise, invert
from .toml_out import ByteRun, PatchTomlContent, render_patch_toml
from .twins import V103_ROLE_OVERRIDES, Role, ThemeError

__all__: list[str] = [
    "DEEP_ORANGE",
    "DEFAULT_NAME",
    "DEFAULT_TARGET",
    "RGB",
    "V103_ROLE_OVERRIDES",
    "ByteRun",
    "PatchTomlContent",
    "Role",
    "ThemeBuild",
    "ThemeError",
    "ThemeOptions",
    "ThemeReport",
    "build_theme",
    "colourise",
    "invert",
    "render_patch_toml",
]
