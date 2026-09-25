# Type stubs for the subset of the Unicorn CPU emulator the overlay auditor uses.
#
# Only the class, constants, and submodule imported by
# ``scripts/build_radio_automation.py`` are declared.  Signatures follow the
# Unicorn 2.x Python binding (``unicorn.unicorn_py3.unicorn``).  The runtime
# package ships ``py.typed``, but its inline annotations leave ``hook_add``
# callbacks and ``reg_read`` results loosely typed, so these stubs pin the exact
# shapes the auditor relies on and also let the type checkers resolve the import
# when the optional package is absent.
from collections.abc import Callable

from . import arm_const as arm_const

__version__: str

UC_ARCH_ARM: int
UC_MODE_THUMB: int
UC_HOOK_CODE: int

class Uc:
    def __init__(self, arch: int, mode: int, cpu: int | None = ...) -> None: ...
    def mem_map(self, address: int, size: int, perms: int = ...) -> None: ...
    def mem_write(self, address: int, data: bytes) -> None: ...
    def mem_read(self, address: int, size: int) -> bytearray: ...
    def reg_read(self, reg_id: int) -> int: ...
    def reg_write(self, reg_id: int, value: int) -> None: ...
    def hook_add(
        self,
        htype: int,
        callback: Callable[[Uc, int, int, object], None],
    ) -> int: ...
    def emu_start(
        self,
        begin: int,
        until: int,
        timeout: int = ...,
        count: int = ...,
    ) -> None: ...
    def emu_stop(self) -> None: ...
