"""Win32 .rodata segment — read-only initialized data."""

from typing import Optional

from .data import Win32SegData


class Win32SegRodata(Win32SegData):
    LINKER_SECTION = ".rodata"
    SECTION_FLAGS = "a"
    DETECT_STRINGS = True
    HEURISTIC_POINTERS = True

    @staticmethod
    def is_data() -> bool:
        return False

    @staticmethod
    def is_rodata() -> bool:
        return True
