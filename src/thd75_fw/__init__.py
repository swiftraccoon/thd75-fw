"""Kenwood TH-D75 firmware extraction and cipher tools.

This package exposes the cipher and parser primitives used by the
official updater so they can be reused for analysis, interoperability
research, and amateur radio experimentation.

Copyright (C) 2025 Swift Raccoon

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, version 3.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.
"""

from __future__ import annotations

from . import (
    file_cipher,
    flash,
    images,
    intel_hex,
    kex,
    patch,
    resource,
    sections,
    serial_cipher,
    voice,
)
from .file_cipher import (
    DecryptedBlock,
    DecryptedResource,
    RollingKeyState,
    decrypt_line,
    decrypt_resource,
    encrypt_line,
)
from .flash.commands import AckCode, NakSubcode, Verb
from .flash.segments import FlatImageOptions, SegmentDescriptor
from .flash.session import (
    FlashError,
    FlashOutcome,
    FlashRunOptions,
    FlashSession,
    FlashSessionOptions,
    TargetInfo,
)
from .images import Image, ImageDatabase
from .intel_hex import ParseResult, RecordType
from .kex import (
    Kex,
    KexBlock,
    firmware_checksum,
    parse_encrypted_resource,
    parse_kex_bytes,
    parse_resource,
    patch_kex,
    patch_kex_stack,
    patch_resource,
    patch_resource_stack,
    render,
    section_image,
)
from .patch import (
    ByteChange,
    ByteContext,
    Patch,
    PatchIntegrityError,
    PatchVerificationError,
    SectionHashes,
    expand_run,
    iter_catalog,
    load_patch,
    parse_patch,
)
from .sections import (
    FLASH_BASE,
    SECTIONS,
    FlashAddress,
    SectionInfo,
    lookup_by_address,
    lookup_by_name,
    name_for_address,
)
from .serial_cipher import (
    DEFAULT_KEY,
    SubstitutionTable,
    decrypt,
    encrypt,
    verify_round_trip,
)
from .voice import (
    Language,
    Prompt,
    PromptDatabase,
    classify_language,
)

__version__ = "0.3.1"

__all__ = [
    "DEFAULT_KEY",
    "FLASH_BASE",
    "SECTIONS",
    "AckCode",
    "ByteChange",
    "ByteContext",
    "DecryptedBlock",
    "DecryptedResource",
    "FlashAddress",
    "FlashError",
    "FlashOutcome",
    "FlashRunOptions",
    "FlashSession",
    "FlashSessionOptions",
    "FlatImageOptions",
    "Image",
    "ImageDatabase",
    "Kex",
    "KexBlock",
    "Language",
    "NakSubcode",
    "ParseResult",
    "Patch",
    "PatchIntegrityError",
    "PatchVerificationError",
    "Prompt",
    "PromptDatabase",
    "RecordType",
    "RollingKeyState",
    "SectionHashes",
    "SectionInfo",
    "SegmentDescriptor",
    "SubstitutionTable",
    "TargetInfo",
    "Verb",
    "__version__",
    "classify_language",
    "decrypt",
    "decrypt_line",
    "decrypt_resource",
    "encrypt",
    "encrypt_line",
    "expand_run",
    "file_cipher",
    "firmware_checksum",
    "flash",
    "images",
    "intel_hex",
    "iter_catalog",
    "kex",
    "load_patch",
    "lookup_by_address",
    "lookup_by_name",
    "name_for_address",
    "parse_encrypted_resource",
    "parse_kex_bytes",
    "parse_patch",
    "parse_resource",
    "patch",
    "patch_kex",
    "patch_kex_stack",
    "patch_resource",
    "patch_resource_stack",
    "render",
    "resource",
    "section_image",
    "sections",
    "serial_cipher",
    "verify_round_trip",
    "voice",
]
