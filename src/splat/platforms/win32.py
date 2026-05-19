"""Win32 PE platform support.

Parses the PE/COFF header of the target binary at `init()` time and exposes
the result via module-level globals that win32 segtypes can consult.

The parser intentionally implements only what splat needs (DOS stub, file
header, optional header, section table). It accepts both PE32 (i386, what
MSVC6 emits) and PE32+ (x86_64) optional headers but the rest of the win32
support is geared at PE32 / i386.
"""

from dataclasses import dataclass, field
import struct
from typing import List, Optional, Set, Tuple

from ..util import log


DOS_MAGIC = b"MZ"
PE_MAGIC = b"PE\x00\x00"

MACHINE_I386 = 0x014C
MACHINE_AMD64 = 0x8664

# Section header flags (IMAGE_SCN_*)
SCN_CNT_CODE = 0x00000020
SCN_CNT_INITIALIZED_DATA = 0x00000040
SCN_CNT_UNINITIALIZED_DATA = 0x00000080
SCN_MEM_READ = 0x40000000
SCN_MEM_WRITE = 0x80000000
SCN_MEM_EXECUTE = 0x20000000


@dataclass
class PESection:
    name: str
    virtual_size: int
    virtual_address: int  # RVA
    raw_size: int
    raw_pointer: int  # file offset
    characteristics: int

    @property
    def is_code(self) -> bool:
        return bool(self.characteristics & (SCN_CNT_CODE | SCN_MEM_EXECUTE))

    @property
    def is_bss(self) -> bool:
        return bool(self.characteristics & SCN_CNT_UNINITIALIZED_DATA)

    @property
    def is_writable(self) -> bool:
        return bool(self.characteristics & SCN_MEM_WRITE)

    @property
    def is_readonly_data(self) -> bool:
        return (
            bool(self.characteristics & SCN_CNT_INITIALIZED_DATA)
            and not self.is_writable
            and not self.is_code
        )


@dataclass
class PEExport:
    name: Optional[str]  # None for ordinal-only exports
    ordinal: int
    rva: int
    forwarder: Optional[str] = None  # set when the export points outside the image

    @property
    def va_for(self):
        return None  # placeholder so dataclass stays dataclass; actual VA computed via PEInfo


@dataclass
class PEImport:
    dll: str
    name: Optional[str]  # None for ordinal-only imports
    ordinal: Optional[int]  # set when name is None
    iat_rva: int  # IAT slot RVA — what `call dword ptr [<iat_va>]` reads


@dataclass
class PEBoundImport:
    """IMAGE_BOUND_IMPORT_DESCRIPTOR entry.

    `timestamp` is the DLL build timestamp the binary was bound against;
    `forwarder_refs` are 0-N additional DLLs the bound-import chain
    transitively pre-resolved through."""

    dll: str
    timestamp: int
    forwarder_refs: List[str] = field(default_factory=list)


@dataclass
class PEResource:
    """One leaf in the .rsrc tree.

    `rtype` is the resource-type ID (or a UTF-16 name for custom types).
    `rid` is the per-type identifier or name. `language` is the locale id.
    `rva` / `size` point at the resource's raw bytes inside the image.
    """

    rtype: object  # int (standard) or str (custom-named type)
    rid: object  # int or str
    language: int
    rva: int
    size: int


@dataclass
class PEInfo:
    machine: int = 0
    num_sections: int = 0
    timestamp: int = 0
    characteristics: int = 0

    is_pe32_plus: bool = False
    image_base: int = 0
    entry_point_rva: int = 0
    section_alignment: int = 0
    file_alignment: int = 0
    size_of_image: int = 0
    size_of_headers: int = 0
    subsystem: int = 0
    dll_characteristics: int = 0
    size_of_stack_reserve: int = 0
    size_of_stack_commit: int = 0
    size_of_heap_reserve: int = 0
    size_of_heap_commit: int = 0
    linker_major: int = 0
    linker_minor: int = 0

    pe_header_offset: int = 0
    sections: List[PESection] = field(default_factory=list)

    # 16 (rva, size) entries from the optional header. Populated only when
    # NumberOfRvaAndSizes is large enough.
    data_directories: List[Tuple[int, int]] = field(default_factory=list)
    exports: List[PEExport] = field(default_factory=list)
    export_dll_name: Optional[str] = None
    imports: List[PEImport] = field(default_factory=list)
    bound_imports: List[PEBoundImport] = field(default_factory=list)
    delay_imports: List[PEImport] = field(default_factory=list)
    # PE32+ / ARM: array of (begin_rva, end_rva, unwind_rva) describing
    # function bounds for SEH unwinding. Empty for PE32.
    runtime_functions: List[Tuple[int, int, int]] = field(default_factory=list)
    # /GS security cookie VA (data dir 10 → IMAGE_LOAD_CONFIG_DIRECTORY).
    security_cookie_va: int = 0
    # /SAFESEH handler RVAs (PE32 only).
    safe_seh_handlers: List[int] = field(default_factory=list)
    # /guard:cf — array of valid indirect-call target RVAs.
    cfg_function_rvas: List[int] = field(default_factory=list)
    cfg_flags: int = 0
    # RVAs the loader's base-relocation logic identifies as absolute
    # pointers (HIGHLOW for PE32, DIR64 for PE32+). Useful for emitting
    # data-section .long/.quad entries with symbolic targets.
    pointer_rvas: Set[int] = field(default_factory=set)
    # PDB filename embedded in the Debug directory's CodeView record, when
    # present.
    pdb_path: Optional[str] = None
    # GUID (RSDS) or 32-bit signature (NB10) identifying the matching PDB.
    pdb_guid: Optional[str] = None
    # Build age — incremented every time the PDB is updated.
    pdb_age: Optional[int] = None
    # TLS callback VAs gathered from data directory 9.
    tls_callback_vas: List[int] = field(default_factory=list)
    # Resources enumerated from data directory 2 (.rsrc).
    resources: List[PEResource] = field(default_factory=list)
    # Decoded VS_VERSIONINFO key/value pairs (CompanyName, FileVersion,
    # ProductName, OriginalFilename, etc.).
    version_info: dict = field(default_factory=dict)

    @property
    def entry_point_va(self) -> int:
        return self.image_base + self.entry_point_rva

    def section_by_name(self, name: str) -> Optional[PESection]:
        for s in self.sections:
            if s.name == name:
                return s
        return None

    def rva_to_file_offset(self, rva: int) -> Optional[int]:
        for s in self.sections:
            if s.virtual_address <= rva < s.virtual_address + max(
                s.virtual_size, s.raw_size
            ):
                return s.raw_pointer + (rva - s.virtual_address)
        return None

    def va_to_file_offset(self, va: int) -> Optional[int]:
        return self.rva_to_file_offset(va - self.image_base)


# Populated by `init`, consulted by segtypes/disassembler.
info: PEInfo = PEInfo()
# Full file bytes — kept on the side so heuristics in segtypes can peek
# at arbitrary section content (e.g. validate a candidate function start
# byte) without threading rom_bytes through every call.
raw_image: bytes = b""


def parse_pe(data: bytes) -> PEInfo:
    if len(data) < 0x40 or data[:2] != DOS_MAGIC:
        log.error("win32 target does not start with an MZ DOS header")

    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_off + 24 > len(data) or data[pe_off : pe_off + 4] != PE_MAGIC:
        log.error(f"win32 target does not contain a PE header at 0x{pe_off:X}")

    # COFF file header (20 bytes) follows the 4-byte PE signature.
    coff_off = pe_off + 4
    (
        machine,
        num_sections,
        timestamp,
        _ptr_to_symtab,
        _num_symbols,
        size_of_optional_header,
        characteristics,
    ) = struct.unpack_from("<HHIIIHH", data, coff_off)

    opt_off = coff_off + 20
    if size_of_optional_header < 2:
        log.error("win32 target has no PE optional header")
    if opt_off + size_of_optional_header > len(data):
        log.error("win32 optional header runs past end of file")

    magic = struct.unpack_from("<H", data, opt_off)[0]
    is_pe32_plus = magic == 0x20B
    if magic not in (0x10B, 0x20B):
        log.error(f"win32 target has unknown optional header magic 0x{magic:04X}")

    # Reject truncated optional headers: PE32 needs 96 bytes (standard +
    # windows-specific); PE32+ needs 112. Anything smaller can't carry the
    # data-directory offsets we expect.
    min_opt = 112 if is_pe32_plus else 96
    if size_of_optional_header < min_opt:
        log.error(
            f"win32 optional header is {size_of_optional_header} bytes; "
            f"need at least {min_opt} for the data directories"
        )

    pe = PEInfo(
        machine=machine,
        num_sections=num_sections,
        timestamp=timestamp,
        characteristics=characteristics,
        is_pe32_plus=is_pe32_plus,
        pe_header_offset=pe_off,
    )

    # MajorLinkerVersion + MinorLinkerVersion (BYTE BYTE) at opt_off + 2.
    pe.linker_major = data[opt_off + 2] if opt_off + 2 < len(data) else 0
    pe.linker_minor = data[opt_off + 3] if opt_off + 3 < len(data) else 0

    if not is_pe32_plus:
        # PE32 optional header layout (offsets relative to opt_off).
        pe.entry_point_rva = struct.unpack_from("<I", data, opt_off + 16)[0]
        pe.image_base = struct.unpack_from("<I", data, opt_off + 28)[0]
        pe.section_alignment = struct.unpack_from("<I", data, opt_off + 32)[0]
        pe.file_alignment = struct.unpack_from("<I", data, opt_off + 36)[0]
        pe.size_of_image = struct.unpack_from("<I", data, opt_off + 56)[0]
        pe.size_of_headers = struct.unpack_from("<I", data, opt_off + 60)[0]
        pe.subsystem = struct.unpack_from("<H", data, opt_off + 68)[0]
        pe.dll_characteristics = struct.unpack_from("<H", data, opt_off + 70)[0]
        pe.size_of_stack_reserve = struct.unpack_from("<I", data, opt_off + 72)[0]
        pe.size_of_stack_commit = struct.unpack_from("<I", data, opt_off + 76)[0]
        pe.size_of_heap_reserve = struct.unpack_from("<I", data, opt_off + 80)[0]
        pe.size_of_heap_commit = struct.unpack_from("<I", data, opt_off + 84)[0]
        num_rva = struct.unpack_from("<I", data, opt_off + 92)[0]
        dd_off = opt_off + 96
    else:
        pe.entry_point_rva = struct.unpack_from("<I", data, opt_off + 16)[0]
        pe.image_base = struct.unpack_from("<Q", data, opt_off + 24)[0]
        pe.section_alignment = struct.unpack_from("<I", data, opt_off + 32)[0]
        pe.file_alignment = struct.unpack_from("<I", data, opt_off + 36)[0]
        pe.size_of_image = struct.unpack_from("<I", data, opt_off + 56)[0]
        pe.size_of_headers = struct.unpack_from("<I", data, opt_off + 60)[0]
        pe.subsystem = struct.unpack_from("<H", data, opt_off + 68)[0]
        pe.dll_characteristics = struct.unpack_from("<H", data, opt_off + 70)[0]
        pe.size_of_stack_reserve = struct.unpack_from("<Q", data, opt_off + 72)[0]
        pe.size_of_stack_commit = struct.unpack_from("<Q", data, opt_off + 80)[0]
        pe.size_of_heap_reserve = struct.unpack_from("<Q", data, opt_off + 88)[0]
        pe.size_of_heap_commit = struct.unpack_from("<Q", data, opt_off + 96)[0]
        num_rva = struct.unpack_from("<I", data, opt_off + 108)[0]
        dd_off = opt_off + 112

    for i in range(min(num_rva, 16)):
        if dd_off + 8 > opt_off + size_of_optional_header:
            break
        rva = struct.unpack_from("<I", data, dd_off + i * 8)[0]
        size = struct.unpack_from("<I", data, dd_off + i * 8 + 4)[0]
        pe.data_directories.append((rva, size))

    section_off = opt_off + size_of_optional_header
    for i in range(num_sections):
        sh = section_off + i * 40
        if sh + 40 > len(data):
            log.error(f"win32 section header {i} runs past end of file")
        raw_name = data[sh : sh + 8]
        name = raw_name.split(b"\x00", 1)[0].decode("ascii", errors="replace")
        (
            virt_size,
            virt_addr,
            raw_size,
            raw_ptr,
            _ptr_relocs,
            _ptr_linenums,
            _num_relocs,
            _num_linenums,
            scn_chars,
        ) = struct.unpack_from("<IIIIIIHHI", data, sh + 8)
        pe.sections.append(
            PESection(
                name=name,
                virtual_size=virt_size,
                virtual_address=virt_addr,
                raw_size=raw_size,
                raw_pointer=raw_ptr,
                characteristics=scn_chars,
            )
        )

    parse_exports(data, pe)
    parse_imports(data, pe)
    parse_bound_imports(data, pe)
    parse_delay_imports(data, pe)
    parse_relocations(data, pe)
    parse_exception_table(data, pe)
    parse_load_config(data, pe)
    parse_debug(data, pe)
    parse_tls(data, pe)
    parse_resources(data, pe)
    parse_version_info(data, pe)
    return pe


_MAX_CSTR_LEN = 4096


def _read_cstr(data: bytes, off: int) -> str:
    """Read a NUL-terminated ASCII string. Truncates at `_MAX_CSTR_LEN`
    to bound parse-time cost on malformed or non-NUL-terminated input."""
    if off < 0 or off >= len(data):
        return ""
    cap = min(off + _MAX_CSTR_LEN, len(data))
    end = data.find(b"\x00", off, cap)
    if end < 0:
        end = cap
    return data[off:end].decode("ascii", errors="replace")


def parse_exports(data: bytes, pe: PEInfo) -> None:
    """Populate `pe.exports` and `pe.export_dll_name` from data directory 0."""
    if not pe.data_directories:
        return
    exp_rva, exp_size = pe.data_directories[0]
    if exp_rva == 0 or exp_size == 0:
        return
    exp_off = pe.rva_to_file_offset(exp_rva)
    if exp_off is None or exp_off + 40 > len(data):
        return

    (
        _flags,
        _ts,
        _vmaj,
        _vmin,
        name_rva,
        ord_base,
        num_funcs,
        num_names,
        funcs_rva,
        names_rva,
        ordinals_rva,
    ) = struct.unpack_from("<IIHHIIIIIII", data, exp_off)

    if name_rva:
        name_off = pe.rva_to_file_offset(name_rva)
        if name_off is not None:
            pe.export_dll_name = _read_cstr(data, name_off)

    funcs_off = pe.rva_to_file_offset(funcs_rva) if funcs_rva else None
    names_off = pe.rva_to_file_offset(names_rva) if names_rva else None
    ordinals_off = pe.rva_to_file_offset(ordinals_rva) if ordinals_rva else None

    if funcs_off is None:
        return

    # Map ordinal-index → name (some functions are export-by-ordinal only).
    name_for_ordinal: dict = {}
    if names_off is not None and ordinals_off is not None:
        for i in range(num_names):
            if names_off + i * 4 + 4 > len(data):
                break
            if ordinals_off + i * 2 + 2 > len(data):
                break
            name_ptr_rva = struct.unpack_from("<I", data, names_off + i * 4)[0]
            ordinal_idx = struct.unpack_from("<H", data, ordinals_off + i * 2)[0]
            name_off = pe.rva_to_file_offset(name_ptr_rva)
            if name_off is None:
                continue
            name_for_ordinal[ordinal_idx] = _read_cstr(data, name_off)

    for i in range(num_funcs):
        if funcs_off + i * 4 + 4 > len(data):
            break
        func_rva = struct.unpack_from("<I", data, funcs_off + i * 4)[0]
        if func_rva == 0:
            continue
        forwarder: Optional[str] = None
        # When the function RVA falls inside the export directory itself,
        # it's a forwarder string (DLL.Func or DLL.#ord) rather than code.
        if exp_rva <= func_rva < exp_rva + exp_size:
            f_off = pe.rva_to_file_offset(func_rva)
            if f_off is not None:
                forwarder = _read_cstr(data, f_off)
        pe.exports.append(
            PEExport(
                name=name_for_ordinal.get(i),
                ordinal=i + ord_base,
                rva=func_rva,
                forwarder=forwarder,
            )
        )


def parse_imports(data: bytes, pe: PEInfo) -> None:
    """Populate `pe.imports` from data directory 1 (the Import Table).

    Reads IMAGE_IMPORT_DESCRIPTOR entries until the null terminator. For
    each DLL walks the Import Lookup Table (OriginalFirstThunk) — falling
    back to the IAT (FirstThunk) when the ILT is absent — and records the
    DLL name, imported symbol, and the IAT slot RVA so call sites that
    reach the IAT can be tagged with the imported name.
    """
    if len(pe.data_directories) < 2:
        return
    imp_rva, imp_size = pe.data_directories[1]
    if imp_rva == 0 or imp_size == 0:
        return
    imp_off = pe.rva_to_file_offset(imp_rva)
    if imp_off is None:
        return

    is_pe32_plus = pe.is_pe32_plus
    thunk_size = 8 if is_pe32_plus else 4
    ordinal_flag = (1 << 63) if is_pe32_plus else (1 << 31)
    thunk_fmt = "<Q" if is_pe32_plus else "<I"

    desc_off = imp_off
    # Cap descriptor count at a sane maximum to bound parse cost on
    # malformed binaries.
    for _desc_i in range(4096):
        if desc_off + 20 > len(data):
            break
        ilt_rva, _ts, _fwd, dll_name_rva, iat_rva = struct.unpack_from(
            "<IIIII", data, desc_off
        )
        if ilt_rva == 0 and dll_name_rva == 0 and iat_rva == 0:
            break
        desc_off += 20

        dll_off = pe.rva_to_file_offset(dll_name_rva)
        dll_name = _read_cstr(data, dll_off) if dll_off is not None else "?"

        # Prefer the Import Lookup Table; fall back to the IAT if absent.
        thunk_array_rva = ilt_rva if ilt_rva else iat_rva
        thunk_off = pe.rva_to_file_offset(thunk_array_rva)
        if thunk_off is None or iat_rva == 0:
            # Without an IAT RVA we can't compute meaningful slot VAs for
            # the entries we discover; skip the descriptor.
            continue

        slot_rva = iat_rva
        for _thunk_i in range(65536):
            if thunk_off + thunk_size > len(data):
                break
            thunk = struct.unpack_from(thunk_fmt, data, thunk_off)[0]
            if thunk == 0:
                break
            name: Optional[str] = None
            ordinal: Optional[int] = None
            if thunk & ordinal_flag:
                ordinal = thunk & 0xFFFF
            else:
                hint_off = pe.rva_to_file_offset(thunk & 0x7FFFFFFF)
                if hint_off is not None and hint_off + 2 < len(data):
                    name = _read_cstr(data, hint_off + 2)
            pe.imports.append(
                PEImport(
                    dll=dll_name,
                    name=name,
                    ordinal=ordinal,
                    iat_rva=slot_rva,
                )
            )
            thunk_off += thunk_size
            slot_rva += thunk_size


def parse_delay_imports(data: bytes, pe: PEInfo) -> None:
    """Parse data directory 13 (Delay Import). MSVC `__declspec(dllimport)`
    with `/DELAYLOAD` produces a separate import table for lazy resolution.

    Each IMAGE_DELAYLOAD_DESCRIPTOR is 32 bytes; entries are NULL-terminated.
    `Attributes` flag bit 0 indicates RVA-based fields (v2); else they're
    VAs that need ImageBase subtraction (v1, legacy)."""
    if len(pe.data_directories) < 14:
        return
    di_rva, di_size = pe.data_directories[13]
    if di_rva == 0 or di_size == 0:
        return
    di_off = pe.rva_to_file_offset(di_rva)
    if di_off is None:
        return

    is_pe32_plus = pe.is_pe32_plus
    thunk_size = 8 if is_pe32_plus else 4
    ordinal_flag = (1 << 63) if is_pe32_plus else (1 << 31)
    thunk_fmt = "<Q" if is_pe32_plus else "<I"

    desc_off = di_off
    end = di_off + di_size
    for _desc_i in range(4096):
        if desc_off + 32 > end or desc_off + 32 > len(data):
            break
        (
            attrs,
            dll_name_field,
            _module_handle,
            iat_field,
            int_field,
            _bound_iat,
            _unload_iat,
            _ts,
        ) = struct.unpack_from("<IIIIIIII", data, desc_off)
        if attrs == 0 and dll_name_field == 0 and iat_field == 0 and int_field == 0:
            break
        desc_off += 32

        # Translate fields (RVAs for v2, VAs for v1).
        def to_rva(field: int) -> int:
            if attrs & 1:
                return field
            return field - pe.image_base if field >= pe.image_base else field

        dll_name_rva = to_rva(dll_name_field)
        iat_rva = to_rva(iat_field)
        int_rva = to_rva(int_field) if int_field else iat_rva

        dll_off = pe.rva_to_file_offset(dll_name_rva)
        dll_name = _read_cstr(data, dll_off) if dll_off is not None else "?"

        int_off = pe.rva_to_file_offset(int_rva)
        if int_off is None or iat_rva == 0:
            continue

        slot_rva = iat_rva
        for _thunk_i in range(65536):
            if int_off + thunk_size > len(data):
                break
            thunk = struct.unpack_from(thunk_fmt, data, int_off)[0]
            if thunk == 0:
                break
            name: Optional[str] = None
            ordinal: Optional[int] = None
            if thunk & ordinal_flag:
                ordinal = thunk & 0xFFFF
            else:
                hint_off = pe.rva_to_file_offset(thunk & 0x7FFFFFFF)
                if hint_off is not None and hint_off + 2 < len(data):
                    name = _read_cstr(data, hint_off + 2)
            pe.delay_imports.append(
                PEImport(
                    dll=dll_name,
                    name=name,
                    ordinal=ordinal,
                    iat_rva=slot_rva,
                )
            )
            int_off += thunk_size
            slot_rva += thunk_size


def parse_bound_imports(data: bytes, pe: PEInfo) -> None:
    """Parse data directory 11 (Bound Import Table).

    Unlike the regular import table, bound-import entries reference DLL
    names by an offset relative to the start of the bound-import directory
    itself (NOT an RVA). Entries are 8-byte IMAGE_BOUND_IMPORT_DESCRIPTOR
    structs terminated by an all-zero entry, optionally followed by
    forwarder-ref descriptors."""
    if len(pe.data_directories) < 12:
        return
    bi_rva, bi_size = pe.data_directories[11]
    if bi_rva == 0 or bi_size == 0:
        return
    bi_off = pe.rva_to_file_offset(bi_rva)
    if bi_off is None:
        return
    end = bi_off + bi_size

    cur = bi_off
    for _bi_i in range(4096):
        if cur + 8 > end or cur + 8 > len(data):
            break
        ts, name_off, n_fwd = struct.unpack_from("<IHH", data, cur)
        if ts == 0 and name_off == 0 and n_fwd == 0:
            break
        name_abs = bi_off + name_off
        dll_name = (
            _read_cstr(data, name_abs) if name_abs < len(data) else "?"
        )
        cur += 8
        fwds: List[str] = []
        # Per spec, NumberOfModuleForwarderRefs fits in a WORD — bound by
        # 0xFFFF entries.
        for _ in range(min(n_fwd, 0xFFFF)):
            if cur + 8 > len(data) or cur + 8 > end:
                break
            _ts, fname_off, _rsv = struct.unpack_from("<IHH", data, cur)
            fname_abs = bi_off + fname_off
            if fname_abs < len(data):
                fwds.append(_read_cstr(data, fname_abs))
            cur += 8
        pe.bound_imports.append(
            PEBoundImport(dll=dll_name, timestamp=ts, forwarder_refs=fwds)
        )


def parse_load_config(data: bytes, pe: PEInfo) -> None:
    """Parse data directory 10 (Load Config). Extracts:

    - SecurityCookie VA (`/GS` cookie used to detect stack-buffer overruns)
    - SEHandlerTable RVA + count: array of valid SEH handler RVAs the
      MSVC `/SAFESEH` linker switch produced for PE32 binaries.
    """
    if len(pe.data_directories) < 11:
        return
    lc_rva, lc_size = pe.data_directories[10]
    if lc_rva == 0 or lc_size == 0:
        return
    lc_off = pe.rva_to_file_offset(lc_rva)
    if lc_off is None:
        return

    if pe.is_pe32_plus:
        # PE32+ layout: SecurityCookie at +0x58 (QWORD); CFG fields at
        # +0x70/+0x78/+0x80/+0x88/+0x90.
        if lc_off + 0x60 > len(data):
            return
        pe.security_cookie_va = struct.unpack_from("<Q", data, lc_off + 0x58)[0]
        if lc_off + 0x98 <= len(data):
            cfg_table_va = struct.unpack_from("<Q", data, lc_off + 0x80)[0]
            cfg_count = struct.unpack_from("<Q", data, lc_off + 0x88)[0]
            pe.cfg_flags = struct.unpack_from("<I", data, lc_off + 0x90)[0]
            _read_cfg_table(data, pe, cfg_table_va, cfg_count)
        return

    # PE32 layout: SecurityCookie at +0x3C, SEHandlerTable at +0x40,
    # SEHandlerCount at +0x44, GuardCFFunctionTable at +0x54,
    # GuardCFFunctionCount at +0x58, GuardFlags at +0x5C.
    if lc_off + 0x48 > len(data):
        return
    pe.security_cookie_va = struct.unpack_from("<I", data, lc_off + 0x3C)[0]
    seh_table_va = struct.unpack_from("<I", data, lc_off + 0x40)[0]
    seh_count = struct.unpack_from("<I", data, lc_off + 0x44)[0]
    if seh_table_va and seh_count:
        # SEHandlerTable is a VA (already absolute), array of DWORD RVAs.
        table_off = pe.va_to_file_offset(seh_table_va)
        if table_off is not None:
            for i in range(seh_count):
                entry_off = table_off + i * 4
                if entry_off + 4 > len(data):
                    break
                pe.safe_seh_handlers.append(
                    struct.unpack_from("<I", data, entry_off)[0]
                )

    if lc_off + 0x60 <= len(data):
        cfg_table_va = struct.unpack_from("<I", data, lc_off + 0x54)[0]
        cfg_count = struct.unpack_from("<I", data, lc_off + 0x58)[0]
        pe.cfg_flags = struct.unpack_from("<I", data, lc_off + 0x5C)[0]
        _read_cfg_table(data, pe, cfg_table_va, cfg_count)


def _read_cfg_table(data: bytes, pe: PEInfo, table_va: int, count: int) -> None:
    """Read a GuardCFFunctionTable. Each entry is at least 4 bytes (RVA);
    the high bits of `GuardFlags` indicate optional metadata bytes that
    follow each RVA. We compute the per-entry stride and harvest only the
    RVA from each slot."""
    if not table_va or not count:
        return
    table_off = pe.va_to_file_offset(table_va)
    if table_off is None:
        return
    # GuardFlags bits 28..31 hold the count of extra metadata bytes per
    # entry, capped to 7. Stride is 4 + extra_bytes.
    extra = (pe.cfg_flags >> 28) & 0x0F
    stride = 4 + min(extra, 7)
    for i in range(count):
        entry_off = table_off + i * stride
        if entry_off + 4 > len(data):
            break
        rva = struct.unpack_from("<I", data, entry_off)[0]
        pe.cfg_function_rvas.append(rva)


def parse_exception_table(data: bytes, pe: PEInfo) -> None:
    """Parse data directory 3 (Exception Table). For PE32+ this is an
    array of RUNTIME_FUNCTION entries (12 bytes each) giving definitive
    function boundaries — useful both for surfacing real function starts
    and for navigating SEH unwind data."""
    if len(pe.data_directories) < 4:
        return
    et_rva, et_size = pe.data_directories[3]
    if et_rva == 0 or et_size == 0:
        return
    et_off = pe.rva_to_file_offset(et_rva)
    if et_off is None:
        return
    end = min(et_off + et_size, len(data))
    # Bound at ~1M RUNTIME_FUNCTION entries: more than any realistic PE.
    max_entries = min((end - et_off) // 12, 1_000_000)
    for i in range(max_entries):
        cur = et_off + i * 12
        if cur + 12 > end:
            break
        begin, fin, uw = struct.unpack_from("<III", data, cur)
        if begin == 0 and fin == 0 and uw == 0:
            break
        pe.runtime_functions.append((begin, fin, uw))


RELOC_TYPE_ABSOLUTE = 0
RELOC_TYPE_HIGHLOW = 3
RELOC_TYPE_DIR64 = 10


def parse_relocations(data: bytes, pe: PEInfo) -> None:
    """Populate `pe.pointer_rvas` from data directory 5 (the Base Relocation
    Table). Each block applies to one 4 KB page; entries of type 3
    (HIGHLOW, 32-bit) or 10 (DIR64, 64-bit) mark RVAs of absolute pointers
    that the PE loader needs to rebase. Padding entries (type 0) are
    skipped."""
    if len(pe.data_directories) < 6:
        return
    rel_rva, rel_size = pe.data_directories[5]
    if rel_rva == 0 or rel_size == 0:
        return
    rel_off = pe.rva_to_file_offset(rel_rva)
    if rel_off is None:
        return

    end = rel_off + rel_size
    accept = {RELOC_TYPE_HIGHLOW, RELOC_TYPE_DIR64}
    block = rel_off
    while block + 8 <= end and block + 8 <= len(data):
        page_rva, block_size = struct.unpack_from("<II", data, block)
        if block_size < 8 or block + block_size > end:
            break
        entries_end = block + block_size
        entry = block + 8
        while entry + 2 <= entries_end:
            word = struct.unpack_from("<H", data, entry)[0]
            entry += 2
            kind = word >> 12
            if kind == RELOC_TYPE_ABSOLUTE:
                continue
            if kind not in accept:
                continue
            pe.pointer_rvas.add(page_rva + (word & 0x0FFF))
        block += block_size


def parse_debug(data: bytes, pe: PEInfo) -> None:
    """Populate `pe.pdb_path` from data directory 6 (Debug). Walks the
    IMAGE_DEBUG_DIRECTORY array, looking for a CodeView (type 2) entry that
    embeds either an `RSDS`/`NB10` record with a trailing PDB filename."""
    if len(pe.data_directories) < 7:
        return
    dbg_rva, dbg_size = pe.data_directories[6]
    if dbg_rva == 0 or dbg_size == 0:
        return
    dbg_off = pe.rva_to_file_offset(dbg_rva)
    if dbg_off is None:
        return

    end = dbg_off + dbg_size
    entry = dbg_off
    while entry + 28 <= end and entry + 28 <= len(data):
        (
            _chars,
            _ts,
            _vmaj,
            _vmin,
            entry_type,
            size_of_data,
            _addr_of_raw,
            ptr_to_raw,
        ) = struct.unpack_from("<IIHHIIII", data, entry)
        entry += 28
        if entry_type != 2:  # IMAGE_DEBUG_TYPE_CODEVIEW
            continue
        if ptr_to_raw == 0 or size_of_data < 4:
            continue
        if ptr_to_raw + size_of_data > len(data):
            continue
        cv = data[ptr_to_raw : ptr_to_raw + size_of_data]
        magic = cv[:4]
        if magic == b"RSDS" and len(cv) >= 24:
            # Layout: magic(4) + GUID(16) + age(4) + name
            g0, g1, g2, g3 = struct.unpack_from("<IHH8s", cv, 4)
            tail = "-".join(f"{b:02X}" for b in g3)
            pe.pdb_guid = f"{g0:08X}-{g1:04X}-{g2:04X}-{tail}"
            pe.pdb_age = struct.unpack_from("<I", cv, 20)[0]
            pe.pdb_path = _read_cstr(cv, 24)
            return
        if magic == b"NB10" and len(cv) >= 16:
            # Layout: magic(4) + offset(4) + signature(4) + age(4) + name
            sig = struct.unpack_from("<I", cv, 8)[0]
            pe.pdb_guid = f"{sig:08X}"
            pe.pdb_age = struct.unpack_from("<I", cv, 12)[0]
            pe.pdb_path = _read_cstr(cv, 16)
            return


def parse_tls(data: bytes, pe: PEInfo) -> None:
    """Populate `pe.tls_callback_vas` from data directory 9 (TLS).
    `IMAGE_TLS_DIRECTORY` for PE32 has AddressOfCallBacks at offset 0x0C
    (PE32+ at 0x18). The pointer dereferences to a NULL-terminated array
    of callback VAs."""
    if len(pe.data_directories) < 10:
        return
    tls_rva, tls_size = pe.data_directories[9]
    if tls_rva == 0 or tls_size == 0:
        return
    tls_off = pe.rva_to_file_offset(tls_rva)
    if tls_off is None:
        return

    if pe.is_pe32_plus:
        if tls_off + 0x20 > len(data):
            return
        cb_va = struct.unpack_from("<Q", data, tls_off + 0x18)[0]
        ptr_size = 8
        ptr_fmt = "<Q"
    else:
        if tls_off + 0x10 > len(data):
            return
        cb_va = struct.unpack_from("<I", data, tls_off + 0x0C)[0]
        ptr_size = 4
        ptr_fmt = "<I"

    if cb_va == 0:
        return
    cb_off = pe.va_to_file_offset(cb_va)
    if cb_off is None:
        return

    # Bound at 1024 TLS callbacks — already absurd for a real binary.
    for _cb_i in range(1024):
        if cb_off + ptr_size > len(data):
            break
        v = struct.unpack_from(ptr_fmt, data, cb_off)[0]
        if v == 0:
            break
        pe.tls_callback_vas.append(v)
        cb_off += ptr_size


def linker_version_label(major: int, minor: int) -> str:
    """Translate an `IMAGE_OPTIONAL_HEADER.MajorLinkerVersion` value into a
    rough Visual C++ / linker product name. Real binaries are usually
    produced by Microsoft's `link.exe`; the major number tracks the MSVC
    release closely enough to surface as a hint."""
    mapping = {
        2: "MSVC 2.x",
        3: "MSVC 4.x",
        4: "MSVC 4.x",
        5: "MSVC 5.0",
        6: "MSVC 6.0",
        7: "MSVC 7.0 / VS .NET 2002",
        8: "MSVC 8.0 / VS 2005",
        9: "MSVC 9.0 / VS 2008",
        10: "MSVC 10.0 / VS 2010",
        11: "MSVC 11.0 / VS 2012",
        12: "MSVC 12.0 / VS 2013",
        14: "MSVC 14.x / VS 2015-2022",
    }
    return mapping.get(major, f"linker v{major}.{minor:02d}")


RESOURCE_TYPE_NAMES = {
    1: "CURSOR",
    2: "BITMAP",
    3: "ICON",
    4: "MENU",
    5: "DIALOG",
    6: "STRING",
    7: "FONTDIR",
    8: "FONT",
    9: "ACCELERATOR",
    10: "RCDATA",
    11: "MESSAGETABLE",
    12: "GROUP_CURSOR",
    14: "GROUP_ICON",
    16: "VERSION",
    17: "DLGINCLUDE",
    19: "PLUGPLAY",
    20: "VXD",
    21: "ANICURSOR",
    22: "ANIICON",
    23: "HTML",
    24: "MANIFEST",
}


def _read_resource_name(data: bytes, name_field: int, root_off: int) -> object:
    """Return either the integer ID, or the decoded UTF-16 name string."""
    if name_field & 0x80000000:
        name_off = root_off + (name_field & 0x7FFFFFFF)
        if name_off + 2 > len(data):
            return name_field & 0x7FFFFFFF
        length = struct.unpack_from("<H", data, name_off)[0]
        text_off = name_off + 2
        text_end = text_off + length * 2
        if text_end > len(data):
            return name_field & 0x7FFFFFFF
        return data[text_off:text_end].decode("utf-16-le", errors="replace")
    return name_field


def parse_resources(data: bytes, pe: PEInfo) -> None:
    """Walk the .rsrc tree (3 nominal levels: type → name → language) and
    record each leaf in `pe.resources`."""
    if len(pe.data_directories) < 3:
        return
    rsrc_rva, rsrc_size = pe.data_directories[2]
    if rsrc_rva == 0 or rsrc_size == 0:
        return
    root_off = pe.rva_to_file_offset(rsrc_rva)
    if root_off is None:
        return

    def walk_dir(dir_off: int, depth: int, path: tuple) -> None:
        # Bound the recursion: a valid resource tree has only 3 levels
        # (type → name → language). Anything deeper indicates a circular
        # reference or malformed data — bail out rather than recurse.
        if depth > 8:
            return
        if dir_off + 16 > len(data):
            return
        (
            _chars,
            _ts,
            _vmaj,
            _vmin,
            n_named,
            n_id,
        ) = struct.unpack_from("<IIHHHH", data, dir_off)
        # Cap entry count so a fuzzed PE can't make us iterate forever.
        total = min(n_named + n_id, 65536)
        entry_off = dir_off + 16
        for _ in range(total):
            if entry_off + 8 > len(data):
                return
            name_field, data_field = struct.unpack_from("<II", data, entry_off)
            entry_off += 8
            name_val = _read_resource_name(data, name_field, root_off)
            if data_field & 0x80000000:
                sub_off = root_off + (data_field & 0x7FFFFFFF)
                walk_dir(sub_off, depth + 1, path + (name_val,))
            else:
                leaf_off = root_off + data_field
                if leaf_off + 16 > len(data):
                    continue
                leaf_rva, leaf_size, _cp, _rsv = struct.unpack_from(
                    "<IIII", data, leaf_off
                )
                if len(path) >= 2:
                    rtype, rid = path[0], path[1]
                else:
                    rtype, rid = path[0], None
                pe.resources.append(
                    PEResource(
                        rtype=rtype,
                        rid=rid,
                        language=name_val if isinstance(name_val, int) else 0,
                        rva=leaf_rva,
                        size=leaf_size,
                    )
                )

    walk_dir(root_off, 0, ())


def _align4(off: int) -> int:
    return (off + 3) & ~3


def _read_wstr(blob: bytes, off: int) -> tuple:
    """Read a UTF-16 NUL-terminated string starting at `off`. Returns
    (decoded_string, next_offset_past_terminator)."""
    end = off
    while end + 1 < len(blob):
        if blob[end] == 0 and blob[end + 1] == 0:
            break
        end += 2
    text = blob[off:end].decode("utf-16-le", errors="replace")
    return text, end + 2


def _walk_versioninfo_node(blob: bytes, off: int, out: dict, base_off: int) -> int:
    """Walk one VS_VERSIONINFO-style node starting at `off`. Recurses into
    children. Strings are recorded into `out`. Returns the offset just past
    this node (already aligned)."""
    if off + 6 > len(blob):
        return len(blob)
    w_length, w_value_length, w_type = struct.unpack_from("<HHH", blob, off)
    node_end = off + w_length
    if w_length == 0 or node_end > len(blob):
        return len(blob)
    key, body_off = _read_wstr(blob, off + 6)
    body_off = _align4(body_off - base_off) + base_off

    value_end = body_off
    if w_value_length > 0 and body_off + (w_value_length * (2 if w_type == 1 else 1)) <= node_end:
        if w_type == 1:  # text — value is UTF-16
            value = blob[body_off : body_off + w_value_length * 2]
            # Strip trailing NUL WCHAR(s) without splitting on misaligned
            # zero pairs.
            chars = [
                value[i : i + 2]
                for i in range(0, len(value) - (len(value) & 1), 2)
            ]
            text_chars = []
            for wch in chars:
                if wch == b"\x00\x00":
                    break
                text_chars.append(wch)
            value_text = b"".join(text_chars).decode(
                "utf-16-le", errors="replace"
            )
            if key not in {"VS_VERSION_INFO", "StringFileInfo", "VarFileInfo"}:
                out[key] = value_text
            value_end = body_off + w_value_length * 2
        else:
            value_end = body_off + w_value_length
    value_end = _align4(value_end - base_off) + base_off

    # Recurse into children, if any space remains.
    child = value_end
    while child < node_end:
        next_child = _walk_versioninfo_node(blob, child, out, base_off)
        if next_child <= child:
            break
        child = _align4(next_child - base_off) + base_off

    return node_end


def parse_version_info(data: bytes, pe: PEInfo) -> None:
    """Decode the VS_VERSIONINFO StringTable entries from every VERSION
    resource (`rtype == 16`). Populates `pe.version_info` with keys like
    `CompanyName`, `FileVersion`, `ProductName`, `OriginalFilename`."""
    for r in pe.resources:
        if not (isinstance(r.rtype, int) and r.rtype == 16):
            continue
        f_off = pe.rva_to_file_offset(r.rva)
        if f_off is None:
            continue
        if f_off + r.size > len(data):
            continue
        blob = data[f_off : f_off + r.size]
        try:
            _walk_versioninfo_node(blob, 0, pe.version_info, 0)
        except Exception:
            # Malformed VERSIONINFO; leave whatever we already extracted.
            continue


MACHINE_ARM64 = 0xAA64
MACHINE_ARM32 = 0x01C4  # ARMv7 Thumb-2


def init(target_bytes: bytes):
    global info, raw_image
    info = parse_pe(target_bytes)
    raw_image = target_bytes
    if info.machine in (MACHINE_ARM64, MACHINE_ARM32):
        log.error(
            f"win32 target uses ARM architecture (machine 0x{info.machine:04X}); "
            "the splat win32 platform currently only supports x86 / x86_64 "
            "(Capstone-driven disassembly). PE structures parse cleanly but "
            "instruction decode would need a separate backend."
        )
    if info.machine not in (MACHINE_I386, MACHINE_AMD64):
        log.error(
            f"win32 target has unsupported machine type 0x{info.machine:04X} "
            "(only i386 / amd64 are recognized)"
        )
