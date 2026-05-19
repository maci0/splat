"""Win32 binary blob segment — reuse the common bin segment for things like
.rsrc / .reloc / .idata where assembly is not useful."""

from ..common.bin import CommonSegBin


class Win32SegBin(CommonSegBin):
    pass
