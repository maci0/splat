#!/usr/bin/env python3
"""Unit tests for the win32 PE parsers.

Builds tiny PE32 byte blobs in memory and asserts the structured parse
output matches. Touches:

- `parse_pe`            (DOS / COFF / optional header / section table)
- `parse_exports`       (data directory 0)
- `parse_imports`       (data directory 1)
- `parse_relocations`   (data directory 5)
"""

import struct
import unittest

from src.splat.platforms import win32 as win32_platform


IMAGE_BASE = 0x00400000
SECTION_ALIGN = 0x1000
FILE_ALIGN = 0x200
DOS_STUB = b"MZ" + b"\x00" * 0x3A + struct.pack("<I", 0x40)


def _opt_header_pe32_plus(
    entry_rva: int,
    base_of_code: int = 0x1000,
    data_dirs=(),
) -> bytes:
    """PE32+ optional header (240 bytes) — matches the layout
    `Win32SegHeader._dump_optional_header` expects."""
    standard = struct.pack(
        "<HBBIIIII",
        0x020B, 14, 0,
        0x200, 0x200, 0,
        entry_rva, base_of_code,
    )
    windows = struct.pack(
        "<QIIHHHHHHIIIIHHQQQQII",
        0x140000000,                 # ImageBase
        0x1000, 0x200,               # SectionAlignment, FileAlignment
        6, 0, 0, 0, 6, 0,
        0,
        0x4000,                      # SizeOfImage
        0x200,                       # SizeOfHeaders
        0,
        3, 0,
        0x100000, 0x1000, 0x100000, 0x1000,
        0,
        16,
    )
    dirs = b""
    for i in range(16):
        if i < len(data_dirs):
            rva, size = data_dirs[i]
        else:
            rva, size = 0, 0
        dirs += struct.pack("<II", rva, size)
    blob = standard + windows + dirs
    assert len(blob) == 240, len(blob)
    return blob


def _build_pe_plus(
    sections,
    data_dirs=(),
    entry_rva=0x1000,
) -> bytes:
    pe_off = 0x40
    num_sections = len(sections)
    coff = struct.pack(
        "<HHIIIHH",
        0x8664, num_sections, 0x12345678,
        0, 0, 0xF0, 0x002F,
    )
    opt = _opt_header_pe32_plus(entry_rva, data_dirs=data_dirs)
    sec_headers = b"".join(
        _section_header(s["name"], s["vsize"], s["vaddr"], s["rsize"], s["rptr"], s["chars"])
        for s in sections
    )
    header = DOS_STUB + b"PE\x00\x00" + coff + opt + sec_headers
    header = header.ljust(FILE_ALIGN, b"\x00")
    end = max(s["rptr"] + s["rsize"] for s in sections)
    buf = bytearray(header.ljust(end, b"\x00"))
    for s in sections:
        body = s.get("body", b"")
        body = body.ljust(s["rsize"], b"\x00")
        buf[s["rptr"] : s["rptr"] + s["rsize"]] = body[: s["rsize"]]
    return bytes(buf)


def _opt_header_pe32(
    entry_rva: int,
    base_of_code: int = 0x1000,
    base_of_data: int = 0x2000,
    data_dirs=(),
) -> bytes:
    standard = struct.pack(
        "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
        0x010B,           # Magic = PE32
        6, 0,             # LinkerMajor/Minor
        0x200,            # SizeOfCode
        0x200,            # SizeOfInitializedData
        0,                # SizeOfUninitializedData
        entry_rva,        # AddressOfEntryPoint
        base_of_code,
        base_of_data,
        IMAGE_BASE,
        SECTION_ALIGN,
        FILE_ALIGN,
        4, 0, 0, 0, 4, 0,
        0,                # Win32VersionValue
        0x4000,           # SizeOfImage
        FILE_ALIGN,       # SizeOfHeaders
        0,                # CheckSum
        3, 0,             # Subsystem, DllChars
        0x100000, 0x1000, 0x100000, 0x1000,
        0,                # LoaderFlags
        16,               # NumberOfRvaAndSizes
    )
    dirs = b""
    for i in range(16):
        if i < len(data_dirs):
            rva, size = data_dirs[i]
        else:
            rva, size = 0, 0
        dirs += struct.pack("<II", rva, size)
    return standard + dirs


def _section_header(
    name: bytes,
    virt_size: int,
    virt_addr: int,
    raw_size: int,
    raw_ptr: int,
    chars: int,
) -> bytes:
    return struct.pack(
        "<8sIIIIIIHHI",
        name.ljust(8, b"\x00")[:8],
        virt_size,
        virt_addr,
        raw_size,
        raw_ptr,
        0,
        0,
        0,
        0,
        chars,
    )


def _build_pe(
    sections,
    data_dirs=(),
    entry_rva=0x1000,
) -> bytes:
    pe_off = 0x40
    num_sections = len(sections)
    coff = struct.pack(
        "<HHIIIHH",
        0x014C,                       # Machine i386
        num_sections,
        0x12345678,                   # TimeDateStamp
        0,
        0,
        0xE0,                         # SizeOfOptionalHeader
        0x010F,                       # Characteristics
    )
    opt = _opt_header_pe32(entry_rva, data_dirs=data_dirs)
    sec_headers = b"".join(
        _section_header(s["name"], s["vsize"], s["vaddr"], s["rsize"], s["rptr"], s["chars"])
        for s in sections
    )

    header = DOS_STUB + b"PE\x00\x00" + coff + opt + sec_headers
    header = header.ljust(FILE_ALIGN, b"\x00")

    end = max(s["rptr"] + s["rsize"] for s in sections)
    buf = bytearray(header.ljust(end, b"\x00"))
    for s in sections:
        body = s.get("body", b"")
        body = body.ljust(s["rsize"], b"\x00")
        buf[s["rptr"] : s["rptr"] + s["rsize"]] = body[: s["rsize"]]
    return bytes(buf)


class PEParseSmoke(unittest.TestCase):
    def test_minimal_pe(self):
        pe_bytes = _build_pe(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x10,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x10,
                },
            ],
            entry_rva=0x1000,
        )
        pe = win32_platform.parse_pe(pe_bytes)
        self.assertEqual(pe.machine, 0x014C)
        self.assertEqual(pe.image_base, IMAGE_BASE)
        self.assertEqual(pe.entry_point_va, IMAGE_BASE + 0x1000)
        self.assertEqual(len(pe.sections), 1)
        self.assertEqual(pe.sections[0].name, ".text")
        self.assertTrue(pe.sections[0].is_code)
        # No data dirs populated → no exports/imports/relocs/pointers.
        self.assertFalse(pe.exports)
        self.assertFalse(pe.imports)
        self.assertFalse(pe.pointer_rvas)


class PEExportsTest(unittest.TestCase):
    def test_named_export(self):
        # Place the export directory inside an .rdata section.
        rdata_rva = 0x2000
        rdata_rptr = FILE_ALIGN * 2
        name_offset = 40 + 4 + 2  # past directory + funcs/names/ordinals arrays
        # Layout inside .rdata:
        #   0x00: IMAGE_EXPORT_DIRECTORY
        #   0x28: function RVA array (one entry)
        #   0x2C: name RVA array (one entry)
        #   0x30: ordinal index array (one WORD)
        #   0x32: function name string
        #   0x40: dll name string
        funcs_rva = rdata_rva + 0x28
        names_rva = rdata_rva + 0x2C
        ords_rva = rdata_rva + 0x30
        func_name_rva = rdata_rva + 0x32
        dll_name_rva = rdata_rva + 0x40
        export_dir = struct.pack(
            "<IIHHIIIIIII",
            0, 0, 0, 0,
            dll_name_rva,
            1,         # ordinal base
            1, 1,      # num funcs, num names
            funcs_rva, names_rva, ords_rva,
        )
        body = bytearray(0x60)
        body[: len(export_dir)] = export_dir
        struct.pack_into("<I", body, 0x28, 0x1000)            # func RVA → entry
        struct.pack_into("<I", body, 0x2C, func_name_rva)
        struct.pack_into("<H", body, 0x30, 0)                  # ordinal index
        body[0x32 : 0x32 + 5] = b"main\x00"
        body[0x40 : 0x40 + 10] = b"mydll.dll\x00"

        pe_bytes = _build_pe(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x10,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x10,
                },
                {
                    "name": b".rdata",
                    "vsize": 0x60,
                    "vaddr": rdata_rva,
                    "rsize": FILE_ALIGN,
                    "rptr": rdata_rptr,
                    "chars": 0x40000040,
                    "body": bytes(body),
                },
            ],
            data_dirs=[(rdata_rva, 0x60)],
        )
        pe = win32_platform.parse_pe(pe_bytes)
        self.assertEqual(pe.export_dll_name, "mydll.dll")
        self.assertEqual(len(pe.exports), 1)
        self.assertEqual(pe.exports[0].name, "main")
        self.assertEqual(pe.exports[0].ordinal, 1)
        self.assertEqual(pe.exports[0].rva, 0x1000)


class PEOrdinalExportTest(unittest.TestCase):
    def test_ordinal_only_export(self):
        """Exports listed without a name (NumberOfFunctions >
        NumberOfNames) still need a PEExport entry — captured by
        ordinal, with .name == None."""
        rdata_rva = 0x2000
        rdata_rptr = FILE_ALIGN * 2
        # Layout:
        #   0x00 : IMAGE_EXPORT_DIRECTORY
        #   0x28 : funcs array (2 entries)
        #   0x30 : names array (0 entries → omitted)
        #   0x30 : ordinals array (0 entries → omitted)
        #   0x32 : DLL name
        funcs_rva = rdata_rva + 0x28
        dll_name_rva = rdata_rva + 0x32
        body = bytearray(0x80)
        struct.pack_into(
            "<IIHHIIIIIII", body, 0x00,
            0, 0, 0, 0,
            dll_name_rva,
            5,         # ordinal base
            2,         # num funcs
            0,         # num names
            funcs_rva,
            0,         # names_rva (unused)
            0,         # ords_rva (unused)
        )
        # Two function RVAs.
        struct.pack_into("<II", body, 0x28, 0x1000, 0x1100)
        body[0x32 : 0x32 + 11] = b"OrdLib.dll\x00"

        pe_bytes = _build_pe(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x200,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x200,
                },
                {
                    "name": b".rdata",
                    "vsize": 0x80,
                    "vaddr": rdata_rva,
                    "rsize": FILE_ALIGN,
                    "rptr": rdata_rptr,
                    "chars": 0x40000040,
                    "body": bytes(body),
                },
            ],
            data_dirs=[(rdata_rva, 0x80)],
        )
        pe = win32_platform.parse_pe(pe_bytes)
        self.assertEqual(pe.export_dll_name, "OrdLib.dll")
        self.assertEqual(len(pe.exports), 2)
        # Ordinal base 5 + function index 0/1 = ordinals 5/6.
        self.assertEqual([(e.name, e.ordinal) for e in pe.exports],
                         [(None, 5), (None, 6)])


class PEForwardedExportTest(unittest.TestCase):
    def test_forwarder_captured(self):
        # Construct an export directory where the single function RVA falls
        # inside the export directory's own range — that flags it as a
        # forwarder. The forwarder string sits at func_rva.
        rdata_rva = 0x2000
        rdata_rptr = FILE_ALIGN * 2

        export_dir_size = 0x60
        # Layout inside .rdata:
        #   0x00 : IMAGE_EXPORT_DIRECTORY
        #   0x28 : function RVA array (one entry pointing at the forwarder string)
        #   0x2C : name RVA array (one entry)
        #   0x30 : ordinal index
        #   0x32 : forwarder string ("KERNEL32.Sleep")
        #   0x50 : exported name ("MySleep")
        #   0x58 : dll name
        funcs_rva = rdata_rva + 0x28
        names_rva = rdata_rva + 0x2C
        ords_rva = rdata_rva + 0x30
        forwarder_rva = rdata_rva + 0x32
        export_name_rva = rdata_rva + 0x50
        dll_name_rva = rdata_rva + 0x58

        body = bytearray(0x80)
        struct.pack_into(
            "<IIHHIIIIIII", body, 0x00,
            0, 0, 0, 0,
            dll_name_rva,
            1, 1, 1,
            funcs_rva, names_rva, ords_rva,
        )
        struct.pack_into("<I", body, 0x28, forwarder_rva)
        struct.pack_into("<I", body, 0x2C, export_name_rva)
        struct.pack_into("<H", body, 0x30, 0)
        # Forwarder string
        body[0x32 : 0x32 + 15] = b"KERNEL32.Sleep\x00"
        # Export name
        body[0x50 : 0x50 + 8] = b"MySleep\x00"
        # DLL name
        body[0x58 : 0x58 + 9] = b"mydll.dll"

        pe_bytes = _build_pe(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x10,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x10,
                },
                {
                    "name": b".rdata",
                    "vsize": export_dir_size,
                    "vaddr": rdata_rva,
                    "rsize": FILE_ALIGN,
                    "rptr": rdata_rptr,
                    "chars": 0x40000040,
                    "body": bytes(body),
                },
            ],
            data_dirs=[(rdata_rva, export_dir_size)],
        )
        pe = win32_platform.parse_pe(pe_bytes)
        self.assertEqual(len(pe.exports), 1)
        self.assertEqual(pe.exports[0].name, "MySleep")
        self.assertEqual(pe.exports[0].forwarder, "KERNEL32.Sleep")


class PEImportsTest(unittest.TestCase):
    def test_named_import(self):
        rdata_rva = 0x2000
        rdata_rptr = FILE_ALIGN * 2

        # Layout inside .rdata:
        #   0x00: IMAGE_IMPORT_DESCRIPTOR (20 bytes)
        #   0x14: IMAGE_IMPORT_DESCRIPTOR null terminator (20 bytes of zero)
        #   0x28: ILT array (one DWORD + null terminator)
        #   0x30: IAT array (mirrors ILT)
        #   0x38: IMAGE_IMPORT_BY_NAME (hint + name)
        #   0x48: DLL name
        ilt_rva = rdata_rva + 0x28
        iat_rva = rdata_rva + 0x30
        ibn_rva = rdata_rva + 0x38
        dll_name_rva = rdata_rva + 0x48

        body = bytearray(0x60)
        struct.pack_into(
            "<IIIII", body, 0x00,
            ilt_rva, 0, 0, dll_name_rva, iat_rva,
        )
        # Descriptor terminator already zeroed.
        struct.pack_into("<I", body, 0x28, ibn_rva)
        struct.pack_into("<I", body, 0x2C, 0)  # ILT terminator
        struct.pack_into("<I", body, 0x30, ibn_rva)
        struct.pack_into("<I", body, 0x34, 0)
        struct.pack_into("<H", body, 0x38, 0)  # hint
        body[0x3A : 0x3A + 10] = b"DoStuff\x00"
        body[0x48 : 0x48 + 11] = b"OTHER.dll\x00"

        pe_bytes = _build_pe(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x10,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x10,
                },
                {
                    "name": b".rdata",
                    "vsize": 0x60,
                    "vaddr": rdata_rva,
                    "rsize": FILE_ALIGN,
                    "rptr": rdata_rptr,
                    "chars": 0x40000040,
                    "body": bytes(body),
                },
            ],
            data_dirs=[(0, 0), (rdata_rva, 40)],
        )
        pe = win32_platform.parse_pe(pe_bytes)
        self.assertEqual(len(pe.imports), 1)
        self.assertEqual(pe.imports[0].dll, "OTHER.dll")
        self.assertEqual(pe.imports[0].name, "DoStuff")
        self.assertEqual(pe.imports[0].iat_rva, iat_rva)
        self.assertIsNone(pe.imports[0].ordinal)


class PEDebugTest(unittest.TestCase):
    def test_nb10_pdb_path(self):
        """CodeView 5.0 (NB10) records carry a 4-byte signature + 4-byte
        age + NUL-terminated path. Cover the older format separately
        from RSDS, since legacy MSVC 6 binaries (Europa1400 etc.) use it."""
        rdata_rva = 0x2000
        rdata_rptr = FILE_ALIGN * 2
        # NB10 layout: 'NB10' + offset(4) + signature(4) + age(4) + name
        cv_record = (
            b"NB10"
            + struct.pack("<I", 0)        # CodeView offset (always 0)
            + struct.pack("<I", 0x3FFD22BC)  # signature (matches Europa1400)
            + struct.pack("<I", 2)         # age
            + b"legacy.pdb\x00"
        )
        entry = struct.pack(
            "<IIHHIIII",
            0, 0, 0, 0,
            2,                                # IMAGE_DEBUG_TYPE_CODEVIEW
            len(cv_record),
            rdata_rva + 28,                   # AddressOfRawData
            rdata_rptr + 28,                  # PointerToRawData
        )
        body = bytearray(0x100)
        body[0:28] = entry
        body[28 : 28 + len(cv_record)] = cv_record

        pe_bytes = _build_pe(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x10,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x10,
                },
                {
                    "name": b".rdata",
                    "vsize": 0x100,
                    "vaddr": rdata_rva,
                    "rsize": FILE_ALIGN,
                    "rptr": rdata_rptr,
                    "chars": 0x40000040,
                    "body": bytes(body),
                },
            ],
            data_dirs=[
                (0, 0), (0, 0), (0, 0), (0, 0), (0, 0), (0, 0),
                (rdata_rva, 28),
            ],
        )
        pe = win32_platform.parse_pe(pe_bytes)
        self.assertEqual(pe.pdb_path, "legacy.pdb")
        self.assertEqual(pe.pdb_age, 2)
        self.assertEqual(pe.pdb_guid, "3FFD22BC")

    def test_rsds_pdb_path(self):
        rdata_rva = 0x2000
        rdata_rptr = FILE_ALIGN * 2
        # Debug directory: 28 bytes per entry.
        debug_dir_rva = rdata_rva
        cv_rva = rdata_rva + 28  # CodeView record sits right after the entry
        # CodeView RSDS layout: 'RSDS' (4) + GUID (16) + age (4) + name
        # GUID: 11223344-5566-7788-99AA-BBCCDDEEFF00 in mixed endianness
        cv_record = (
            b"RSDS"
            + bytes.fromhex("44332211")            # uint32 LE
            + bytes.fromhex("6655")                # uint16 LE
            + bytes.fromhex("8877")                # uint16 LE
            + bytes.fromhex("99AABBCCDDEEFF00")    # 8 raw bytes
            + struct.pack("<I", 7)                  # age
            + b"my.pdb\x00"
        )
        entry = struct.pack(
            "<IIHHIIII",
            0,                                # characteristics
            0,                                # timestamp
            0, 0,                             # major/minor version
            2,                                # IMAGE_DEBUG_TYPE_CODEVIEW
            len(cv_record),                   # SizeOfData
            cv_rva,                           # AddressOfRawData
            rdata_rptr + 28,                  # PointerToRawData
        )
        body = bytearray(0x100)
        body[0:28] = entry
        body[28 : 28 + len(cv_record)] = cv_record

        pe_bytes = _build_pe(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x10,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x10,
                },
                {
                    "name": b".rdata",
                    "vsize": 0x100,
                    "vaddr": rdata_rva,
                    "rsize": FILE_ALIGN,
                    "rptr": rdata_rptr,
                    "chars": 0x40000040,
                    "body": bytes(body),
                },
            ],
            # Debug dir is index 6.
            data_dirs=[
                (0, 0), (0, 0), (0, 0), (0, 0), (0, 0), (0, 0),
                (debug_dir_rva, 28),
            ],
        )
        pe = win32_platform.parse_pe(pe_bytes)
        self.assertEqual(pe.pdb_path, "my.pdb")
        self.assertEqual(pe.pdb_age, 7)
        self.assertEqual(
            pe.pdb_guid,
            "11223344-5566-7788-99-AA-BB-CC-DD-EE-FF-00",
        )


class PETlsTest(unittest.TestCase):
    def test_pe32_plus_tls_callbacks(self):
        """PE32+ IMAGE_TLS_DIRECTORY puts AddressOfCallBacks at +0x18 as
        an 8-byte VA, and each callback slot is a QWORD. Verify the
        64-bit code path (the other test covers the 4-byte PE32 form)."""
        rdata_rva = 0x2000
        rdata_rptr = FILE_ALIGN * 2

        callbacks_va = 0x140000000 + rdata_rva + 0x60
        cb_a = 0x140000000 + 0x1000
        cb_b = 0x140000000 + 0x1100

        body = bytearray(0x200)
        # IMAGE_TLS_DIRECTORY64 layout: 5 QWORDs + 2 DWORDs.
        # AddressOfCallBacks is the 4th QWORD at offset 0x18.
        struct.pack_into("<Q", body, 0x18, callbacks_va)
        # Callbacks array (3 QWORDs: two callbacks + NUL).
        struct.pack_into("<QQQ", body, 0x60, cb_a, cb_b, 0)

        pe_bytes = _build_pe_plus(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x10,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x10,
                },
                {
                    "name": b".rdata",
                    "vsize": 0x200,
                    "vaddr": rdata_rva,
                    "rsize": FILE_ALIGN,
                    "rptr": rdata_rptr,
                    "chars": 0x40000040,
                    "body": bytes(body),
                },
            ],
            data_dirs=[
                (0, 0), (0, 0), (0, 0), (0, 0), (0, 0), (0, 0),
                (0, 0), (0, 0), (0, 0),
                (rdata_rva, 0x28),
            ],
        )
        pe = win32_platform.parse_pe(pe_bytes)
        self.assertTrue(pe.is_pe32_plus)
        self.assertEqual(pe.tls_callback_vas, [cb_a, cb_b])

    def test_tls_callbacks(self):
        rdata_rva = 0x2000
        rdata_rptr = FILE_ALIGN * 2
        # TLS directory layout (PE32): 24+ bytes; AddressOfCallBacks at +0x0C.
        callbacks_va = IMAGE_BASE + rdata_rva + 0x40
        # Two callbacks then a NULL terminator.
        cb_va_a = IMAGE_BASE + 0x1000
        cb_va_b = IMAGE_BASE + 0x1004
        tls_dir = struct.pack(
            "<IIIIIIII",
            0,                # StartAddressOfRawData
            0,                # EndAddressOfRawData
            0,                # AddressOfIndex
            callbacks_va,     # AddressOfCallBacks
            0,                # SizeOfZeroFill
            0,                # Characteristics
            0,                # padding
            0,                # padding
        )
        body = bytearray(0x100)
        body[0 : len(tls_dir)] = tls_dir
        # Callbacks array
        struct.pack_into("<III", body, 0x40, cb_va_a, cb_va_b, 0)

        pe_bytes = _build_pe(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x10,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x10,
                },
                {
                    "name": b".rdata",
                    "vsize": 0x100,
                    "vaddr": rdata_rva,
                    "rsize": FILE_ALIGN,
                    "rptr": rdata_rptr,
                    "chars": 0x40000040,
                    "body": bytes(body),
                },
            ],
            # TLS dir is index 9.
            data_dirs=[
                (0, 0), (0, 0), (0, 0), (0, 0), (0, 0), (0, 0),
                (0, 0), (0, 0), (0, 0),
                (rdata_rva, len(tls_dir)),
            ],
        )
        pe = win32_platform.parse_pe(pe_bytes)
        self.assertEqual(pe.tls_callback_vas, [cb_va_a, cb_va_b])


class PEResourcesTest(unittest.TestCase):
    def test_named_resource_type(self):
        """Resource directory entries can be keyed by string name as well
        as integer ID. Verify the parser captures the UTF-16 name."""
        rsrc_rva = 0x3000
        rsrc_rptr = FILE_ALIGN * 3

        body = bytearray(0x200)
        # Root (type) dir — 1 named entry, 0 id entries
        struct.pack_into("<IIHHHH", body, 0x000, 0, 0, 0, 0, 1, 0)
        # Named entry: name field has high bit set + offset to name string
        struct.pack_into("<II", body, 0x010, 0x80000000 | 0x080, 0x80000000 | 0x018)
        # Name dir
        struct.pack_into("<IIHHHH", body, 0x018, 0, 0, 0, 0, 0, 1)
        struct.pack_into("<II", body, 0x028, 1, 0x80000000 | 0x030)
        # Lang dir
        struct.pack_into("<IIHHHH", body, 0x030, 0, 0, 0, 0, 0, 1)
        struct.pack_into("<II", body, 0x040, 0x0409, 0x048)
        # Leaf entry
        struct.pack_into("<IIII", body, 0x048, rsrc_rva + 0x100, 4, 0, 0)
        # IMAGE_RESOURCE_DIR_STRING at offset 0x080: WORD length + UTF-16 chars
        name = "MYTYPE"
        utf16 = name.encode("utf-16-le")
        struct.pack_into("<H", body, 0x080, len(name))
        body[0x082 : 0x082 + len(utf16)] = utf16
        # Leaf bytes
        body[0x100 : 0x104] = b"DATA"

        pe_bytes = _build_pe(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x10,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x10,
                },
                {
                    "name": b".rsrc",
                    "vsize": 0x200,
                    "vaddr": rsrc_rva,
                    "rsize": FILE_ALIGN,
                    "rptr": rsrc_rptr,
                    "chars": 0x40000040,
                    "body": bytes(body),
                },
            ],
            data_dirs=[(0, 0), (0, 0), (rsrc_rva, 0x200)],
        )
        pe = win32_platform.parse_pe(pe_bytes)
        self.assertEqual(len(pe.resources), 1)
        self.assertEqual(pe.resources[0].rtype, "MYTYPE")
        self.assertEqual(pe.resources[0].rid, 1)

    def test_walk_tree(self):
        # Build a minimal 3-level resource tree:
        #   Type 16 (VERSION) → Name 1 → Lang 0x0409 → leaf.
        rsrc_rva = 0x3000
        rsrc_rptr = FILE_ALIGN * 3

        # Layout inside .rsrc (offsets relative to root):
        #   0x000: type dir header + 1 entry
        #   0x018: name dir header + 1 entry
        #   0x030: lang dir header + 1 entry
        #   0x048: leaf IMAGE_RESOURCE_DATA_ENTRY
        #   0x100: actual resource bytes (8 bytes)
        body = bytearray(0x110)
        # Root (type) dir
        struct.pack_into("<IIHHHH", body, 0x000, 0, 0, 0, 0, 0, 1)  # 1 id entry
        struct.pack_into("<II", body, 0x010, 16, 0x80000000 | 0x018)  # type=16, subdir at 0x018

        # Name dir
        struct.pack_into("<IIHHHH", body, 0x018, 0, 0, 0, 0, 0, 1)
        struct.pack_into("<II", body, 0x028, 1, 0x80000000 | 0x030)  # name=1, subdir at 0x030

        # Lang dir
        struct.pack_into("<IIHHHH", body, 0x030, 0, 0, 0, 0, 0, 1)
        struct.pack_into("<II", body, 0x040, 0x0409, 0x048)  # lang, leaf at 0x048

        # Leaf
        struct.pack_into("<IIII", body, 0x048, rsrc_rva + 0x100, 8, 0, 0)
        body[0x100 : 0x108] = b"\x01\x02\x03\x04\x05\x06\x07\x08"

        pe_bytes = _build_pe(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x10,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x10,
                },
                {
                    "name": b".rsrc",
                    "vsize": 0x110,
                    "vaddr": rsrc_rva,
                    "rsize": FILE_ALIGN,
                    "rptr": rsrc_rptr,
                    "chars": 0x40000040,
                    "body": bytes(body),
                },
            ],
            # Resource dir is index 2.
            data_dirs=[(0, 0), (0, 0), (rsrc_rva, 0x110)],
        )
        pe = win32_platform.parse_pe(pe_bytes)
        self.assertEqual(len(pe.resources), 1)
        r = pe.resources[0]
        self.assertEqual(r.rtype, 16)
        self.assertEqual(r.rid, 1)
        self.assertEqual(r.language, 0x0409)
        self.assertEqual(r.size, 8)


class PELoadConfigTest(unittest.TestCase):
    def test_pe32_cookie_only_no_safeseh(self):
        """LoadConfig with /GS but without /SAFESEH (SEHandlerTable == 0).
        Verify security_cookie_va is captured and safe_seh_handlers
        stays empty rather than reading garbage."""
        rdata_rva = 0x2000
        rdata_rptr = FILE_ALIGN * 2

        body = bytearray(0x80)
        struct.pack_into("<I", body, 0, 0x48)            # Size
        struct.pack_into("<I", body, 0x3C, IMAGE_BASE + rdata_rva + 0x60)  # cookie
        # 0x40 + 0x44 stay zero: no SafeSEH

        pe_bytes = _build_pe(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x10,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x10,
                },
                {
                    "name": b".rdata",
                    "vsize": 0x80,
                    "vaddr": rdata_rva,
                    "rsize": FILE_ALIGN,
                    "rptr": rdata_rptr,
                    "chars": 0x40000040,
                    "body": bytes(body),
                },
            ],
            data_dirs=[
                (0, 0), (0, 0), (0, 0), (0, 0), (0, 0), (0, 0),
                (0, 0), (0, 0), (0, 0), (0, 0),
                (rdata_rva, 0x48),
            ],
        )
        pe = win32_platform.parse_pe(pe_bytes)
        self.assertEqual(pe.security_cookie_va, IMAGE_BASE + rdata_rva + 0x60)
        self.assertEqual(pe.safe_seh_handlers, [])

    def test_pe32_security_cookie_and_safeseh(self):
        rdata_rva = 0x2000
        rdata_rptr = FILE_ALIGN * 2

        # IMAGE_LOAD_CONFIG_DIRECTORY32 minimal layout:
        # Offset 0x3C = SecurityCookie VA, 0x40 = SEHandlerTable VA,
        # 0x44 = SEHandlerCount.
        seh_table_off = rdata_rva + 0x50
        seh_table_va = IMAGE_BASE + seh_table_off
        lc_size = 0x48
        body = bytearray(0x100)
        struct.pack_into("<I", body, 0, lc_size)  # Size
        struct.pack_into("<I", body, 0x3C, IMAGE_BASE + rdata_rva + 0x60)  # SecurityCookie
        struct.pack_into("<I", body, 0x40, seh_table_va)  # SEHandlerTable
        struct.pack_into("<I", body, 0x44, 2)  # SEHandlerCount
        # SEH handler RVAs
        struct.pack_into("<II", body, 0x50, 0x1010, 0x1020)

        pe_bytes = _build_pe(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x100,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x100,
                },
                {
                    "name": b".rdata",
                    "vsize": 0x100,
                    "vaddr": rdata_rva,
                    "rsize": FILE_ALIGN,
                    "rptr": rdata_rptr,
                    "chars": 0x40000040,
                    "body": bytes(body),
                },
            ],
            data_dirs=[
                (0, 0), (0, 0), (0, 0), (0, 0), (0, 0), (0, 0),
                (0, 0), (0, 0), (0, 0), (0, 0),
                (rdata_rva, lc_size),
            ],
        )
        pe = win32_platform.parse_pe(pe_bytes)
        self.assertEqual(pe.security_cookie_va, IMAGE_BASE + rdata_rva + 0x60)
        self.assertEqual(pe.safe_seh_handlers, [0x1010, 0x1020])


class PECfgTest(unittest.TestCase):
    def test_pe32_plus_loadconfig_cookie_only(self):
        """An older PE32+ LoadConfig might only span 0x60 bytes
        (covering SecurityCookie) without the +0x80..+0x90 CFG fields.
        Parser must read the cookie and stop, not over-read."""
        rdata_rva = 0x2000
        rdata_rptr = FILE_ALIGN * 2
        # LoadConfig is exactly 0x60 bytes — cookie at +0x58 is included
        # but CFG fields at +0x80 are not.
        body = bytearray(0x60)
        struct.pack_into("<Q", body, 0x58, 0x140100000)

        pe_bytes = _build_pe_plus(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x10,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x10,
                },
                {
                    "name": b".rdata",
                    "vsize": 0x60,
                    "vaddr": rdata_rva,
                    "rsize": FILE_ALIGN,
                    "rptr": rdata_rptr,
                    "chars": 0x40000040,
                    "body": bytes(body),
                },
            ],
            data_dirs=[
                (0, 0), (0, 0), (0, 0), (0, 0), (0, 0), (0, 0),
                (0, 0), (0, 0), (0, 0), (0, 0),
                (rdata_rva, 0x60),
            ],
        )
        pe = win32_platform.parse_pe(pe_bytes)
        self.assertTrue(pe.is_pe32_plus)
        self.assertEqual(pe.security_cookie_va, 0x140100000)
        self.assertEqual(pe.cfg_function_rvas, [])
        self.assertEqual(pe.cfg_flags, 0)

    def test_pe32_cfg_table_with_extra_metadata_bytes(self):
        """The top nibble of GuardFlags encodes how many extra metadata
        bytes follow each CFG RVA in the table. Verify the parser
        strides by `4 + extra` so entries don't shift."""
        rdata_rva = 0x2000
        rdata_rptr = FILE_ALIGN * 2

        cfg_table_off = rdata_rva + 0x80
        cfg_table_va = IMAGE_BASE + cfg_table_off
        body = bytearray(0x200)
        struct.pack_into("<I", body, 0x54, cfg_table_va)
        struct.pack_into("<I", body, 0x58, 3)
        # GuardFlags top nibble = 2 → +2 bytes per entry → stride 6.
        struct.pack_into("<I", body, 0x5C, 0x20000000)
        # Three entries at stride 6: RVA + 2 bytes of metadata.
        for i, rva in enumerate([0x1000, 0x1100, 0x1200]):
            off = 0x80 + i * 6
            struct.pack_into("<I", body, off, rva)
            struct.pack_into("<H", body, off + 4, 0xBEEF)  # metadata

        pe_bytes = _build_pe(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x100,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x100,
                },
                {
                    "name": b".rdata",
                    "vsize": 0x200,
                    "vaddr": rdata_rva,
                    "rsize": FILE_ALIGN,
                    "rptr": rdata_rptr,
                    "chars": 0x40000040,
                    "body": bytes(body),
                },
            ],
            data_dirs=[
                (0, 0), (0, 0), (0, 0), (0, 0), (0, 0), (0, 0),
                (0, 0), (0, 0), (0, 0), (0, 0),
                (rdata_rva, 0x60),
            ],
        )
        pe = win32_platform.parse_pe(pe_bytes)
        self.assertEqual(pe.cfg_function_rvas, [0x1000, 0x1100, 0x1200])
        self.assertEqual(pe.cfg_flags, 0x20000000)

    def test_pe32_plus_guardcf_table(self):
        """PE32+ Load Config places GuardCFFunctionTable at +0x80, count
        at +0x88, flags at +0x90. Verify the 64-bit layout (PE32 fields
        are at +0x54/+0x58/+0x5C in the other test)."""
        rdata_rva = 0x2000
        rdata_rptr = FILE_ALIGN * 2

        cfg_table_off = rdata_rva + 0xA0
        cfg_table_va = 0x140000000 + cfg_table_off
        body = bytearray(0x200)
        # SecurityCookie at +0x58 (QWORD)
        struct.pack_into("<Q", body, 0x58, 0x140100000)
        # GuardCF fields
        struct.pack_into("<Q", body, 0x80, cfg_table_va)
        struct.pack_into("<Q", body, 0x88, 2)
        struct.pack_into("<I", body, 0x90, 0)
        # Two CFG RVAs
        struct.pack_into("<II", body, 0xA0, 0x1100, 0x1200)

        pe_bytes = _build_pe_plus(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x100,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x100,
                },
                {
                    "name": b".rdata",
                    "vsize": 0x200,
                    "vaddr": rdata_rva,
                    "rsize": FILE_ALIGN,
                    "rptr": rdata_rptr,
                    "chars": 0x40000040,
                    "body": bytes(body),
                },
            ],
            data_dirs=[
                (0, 0), (0, 0), (0, 0), (0, 0), (0, 0), (0, 0),
                (0, 0), (0, 0), (0, 0), (0, 0),
                (rdata_rva, 0x98),
            ],
        )
        pe = win32_platform.parse_pe(pe_bytes)
        self.assertTrue(pe.is_pe32_plus)
        self.assertEqual(pe.security_cookie_va, 0x140100000)
        self.assertEqual(pe.cfg_function_rvas, [0x1100, 0x1200])

    def test_pe32_guardcf_table(self):
        rdata_rva = 0x2000
        rdata_rptr = FILE_ALIGN * 2

        cfg_table_off = rdata_rva + 0x80
        cfg_table_va = IMAGE_BASE + cfg_table_off
        body = bytearray(0x100)
        # IMAGE_LOAD_CONFIG_DIRECTORY32: GuardCFFunctionTable +0x54,
        # GuardCFFunctionCount +0x58, GuardFlags +0x5C.
        struct.pack_into("<I", body, 0x54, cfg_table_va)
        struct.pack_into("<I", body, 0x58, 3)
        struct.pack_into("<I", body, 0x5C, 0)
        # Three CFG entries (stride = 4, no metadata bytes).
        struct.pack_into("<III", body, 0x80, 0x1010, 0x1020, 0x1030)

        pe_bytes = _build_pe(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x100,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x100,
                },
                {
                    "name": b".rdata",
                    "vsize": 0x100,
                    "vaddr": rdata_rva,
                    "rsize": FILE_ALIGN,
                    "rptr": rdata_rptr,
                    "chars": 0x40000040,
                    "body": bytes(body),
                },
            ],
            data_dirs=[
                (0, 0), (0, 0), (0, 0), (0, 0), (0, 0), (0, 0),
                (0, 0), (0, 0), (0, 0), (0, 0),
                (rdata_rva, 0x60),
            ],
        )
        pe = win32_platform.parse_pe(pe_bytes)
        self.assertEqual(pe.cfg_function_rvas, [0x1010, 0x1020, 0x1030])


class PEExceptionTableTest(unittest.TestCase):
    def test_runtime_functions(self):
        rdata_rva = 0x2000
        rdata_rptr = FILE_ALIGN * 2
        # Two RUNTIME_FUNCTION entries then a null terminator.
        body = struct.pack("<III", 0x1000, 0x1010, 0x3000)
        body += struct.pack("<III", 0x1020, 0x1040, 0x3010)
        body += b"\x00" * 12  # terminator
        pe_bytes = _build_pe(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x10,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x10,
                },
                {
                    "name": b".rdata",
                    "vsize": len(body),
                    "vaddr": rdata_rva,
                    "rsize": FILE_ALIGN,
                    "rptr": rdata_rptr,
                    "chars": 0x40000040,
                    "body": body,
                },
            ],
            data_dirs=[
                (0, 0), (0, 0), (0, 0), (rdata_rva, len(body)),
            ],
        )
        pe = win32_platform.parse_pe(pe_bytes)
        self.assertEqual(
            pe.runtime_functions,
            [(0x1000, 0x1010, 0x3000), (0x1020, 0x1040, 0x3010)],
        )


class PEBoundImportsTest(unittest.TestCase):
    def test_bound_import_with_forwarder_refs(self):
        """Bound-import descriptor lists module forwarder refs after
        itself in the same table. Verify they're collected."""
        rdata_rva = 0x2000
        rdata_rptr = FILE_ALIGN * 2
        bi_size = 8 * 4  # main descriptor + 2 forwarders + null
        body = bytearray(0x80)
        # Main descriptor: 2 forwarder refs follow.
        struct.pack_into("<IHH", body, 0, 0xDEADBEEF, bi_size, 2)
        # Two forwarder-ref entries (timestamp/name_off/0).
        struct.pack_into("<IHH", body, 8, 0xCAFEBABE, bi_size + 13, 0)
        struct.pack_into("<IHH", body, 16, 0xBADC0DE5, bi_size + 24, 0)
        # Null-terminator descriptor.
        struct.pack_into("<IHH", body, 24, 0, 0, 0)
        body[bi_size : bi_size + 13] = b"KERNEL32.dll\x00"
        body[bi_size + 13 : bi_size + 24] = b"USER32.dll\x00"
        body[bi_size + 24 : bi_size + 34] = b"GDI32.dll\x00"

        pe_bytes = _build_pe(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x10,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x10,
                },
                {
                    "name": b".rdata",
                    "vsize": 0x80,
                    "vaddr": rdata_rva,
                    "rsize": FILE_ALIGN,
                    "rptr": rdata_rptr,
                    "chars": 0x40000040,
                    "body": bytes(body),
                },
            ],
            data_dirs=[
                (0, 0), (0, 0), (0, 0), (0, 0), (0, 0), (0, 0),
                (0, 0), (0, 0), (0, 0), (0, 0), (0, 0),
                (rdata_rva, bi_size + 33),
            ],
        )
        pe = win32_platform.parse_pe(pe_bytes)
        self.assertEqual(len(pe.bound_imports), 1)
        self.assertEqual(pe.bound_imports[0].dll, "KERNEL32.dll")
        self.assertEqual(
            pe.bound_imports[0].forwarder_refs, ["USER32.dll", "GDI32.dll"]
        )

    def test_named_bound_import(self):
        # Bound-import table sits at .rdata RVA 0x2000. DLL name string sits
        # 0x18 bytes after the directory start.
        rdata_rva = 0x2000
        rdata_rptr = FILE_ALIGN * 2
        bi_size = 8 * 2  # one entry + null terminator
        name_off_in_dir = bi_size  # name starts right after both descriptors
        body = bytearray(0x80)
        # Descriptor: timestamp, name offset, # forwarders
        struct.pack_into("<IHH", body, 0, 0xDEADBEEF, name_off_in_dir, 0)
        # Null terminator descriptor
        struct.pack_into("<IHH", body, 8, 0, 0, 0)
        body[name_off_in_dir : name_off_in_dir + 12] = b"KERNEL32.dll\x00"

        pe_bytes = _build_pe(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x10,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x10,
                },
                {
                    "name": b".rdata",
                    "vsize": 0x80,
                    "vaddr": rdata_rva,
                    "rsize": FILE_ALIGN,
                    "rptr": rdata_rptr,
                    "chars": 0x40000040,
                    "body": bytes(body),
                },
            ],
            data_dirs=[
                (0, 0), (0, 0), (0, 0), (0, 0), (0, 0), (0, 0),
                (0, 0), (0, 0), (0, 0), (0, 0), (0, 0),
                (rdata_rva, bi_size + 16),
            ],
        )
        pe = win32_platform.parse_pe(pe_bytes)
        self.assertEqual(len(pe.bound_imports), 1)
        self.assertEqual(pe.bound_imports[0].dll, "KERNEL32.dll")
        self.assertEqual(pe.bound_imports[0].timestamp, 0xDEADBEEF)
        self.assertFalse(pe.bound_imports[0].forwarder_refs)


class PEVersionInfoTest(unittest.TestCase):
    """Build a synthetic VS_VERSIONINFO with one StringTable / one String
    pair and assert it decodes to the expected key/value."""

    def _vs_node(self, key: str, value: bytes, w_type: int, children: bytes = b"") -> bytes:
        key_utf16 = key.encode("utf-16-le") + b"\x00\x00"
        header_size = 6
        body_off = header_size + len(key_utf16)
        # Align body offset to dword
        pad_a = (-body_off) & 3
        value_off = body_off + pad_a
        value_padded = value
        pad_b = (-len(value_padded)) & 3
        children_off = value_off + len(value_padded) + pad_b
        total = children_off + len(children)
        # Pad total to dword as well so the next sibling starts aligned.
        pad_c = (-total) & 3
        # w_value_length depends on w_type:
        #   w_type==1 (text) → length in WCHARs (chars including NUL)
        #   w_type==0 (binary) → length in bytes
        if w_type == 1:
            w_value_length = len(value) // 2
        else:
            w_value_length = len(value)
        return (
            struct.pack("<HHH", total + pad_c, w_value_length, w_type)
            + key_utf16
            + b"\x00" * pad_a
            + value_padded
            + b"\x00" * pad_b
            + children
            + b"\x00" * pad_c
        )

    def test_string_table(self):
        # Build inner-most String entry: key "CompanyName", value "Acme Corp"
        company = self._vs_node(
            "CompanyName",
            "Acme Corp\x00".encode("utf-16-le"),
            w_type=1,
        )
        # StringTable wrapping that one String
        string_table = self._vs_node(
            "040904E4",
            b"",
            w_type=1,
            children=company,
        )
        string_file_info = self._vs_node(
            "StringFileInfo", b"", w_type=1, children=string_table
        )
        # Root VS_VERSION_INFO; for this test we keep its Value empty so
        # we don't have to populate the 52-byte VS_FIXEDFILEINFO.
        root = self._vs_node(
            "VS_VERSION_INFO",
            b"",
            w_type=0,
            children=string_file_info,
        )

        # Now wrap in a resource directory pointing at this blob.
        rsrc_rva = 0x3000
        rsrc_rptr = FILE_ALIGN * 3
        body = bytearray(0x600)
        # Root (type) dir
        struct.pack_into("<IIHHHH", body, 0x000, 0, 0, 0, 0, 0, 1)
        struct.pack_into("<II", body, 0x010, 16, 0x80000000 | 0x018)
        # Name dir
        struct.pack_into("<IIHHHH", body, 0x018, 0, 0, 0, 0, 0, 1)
        struct.pack_into("<II", body, 0x028, 1, 0x80000000 | 0x030)
        # Lang dir
        struct.pack_into("<IIHHHH", body, 0x030, 0, 0, 0, 0, 0, 1)
        struct.pack_into("<II", body, 0x040, 0x0409, 0x048)
        # Leaf entry → points at our root blob at +0x100
        struct.pack_into("<IIII", body, 0x048, rsrc_rva + 0x100, len(root), 0, 0)
        body[0x100 : 0x100 + len(root)] = root

        pe_bytes = _build_pe(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x10,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x10,
                },
                {
                    "name": b".rsrc",
                    "vsize": 0x600,
                    "vaddr": rsrc_rva,
                    "rsize": FILE_ALIGN * 2,
                    "rptr": rsrc_rptr,
                    "chars": 0x40000040,
                    "body": bytes(body),
                },
            ],
            data_dirs=[(0, 0), (0, 0), (rsrc_rva, 0x600)],
        )
        pe = win32_platform.parse_pe(pe_bytes)
        self.assertEqual(pe.version_info.get("CompanyName"), "Acme Corp")


class PEDelayImportsTest(unittest.TestCase):
    def test_v1_va_based_delay_import(self):
        """Pre-VS2008 / legacy MSVC emits IMAGE_DELAYLOAD_DESCRIPTOR with
        attrs=0 — its address fields are VAs (need ImageBase subtraction)
        rather than RVAs. Verify the parser handles both formats."""
        rdata_rva = 0x2000
        rdata_rptr = FILE_ALIGN * 2

        dll_name_va = IMAGE_BASE + rdata_rva + 0x60
        iat_va = IMAGE_BASE + rdata_rva + 0x40
        int_va = IMAGE_BASE + rdata_rva + 0x48
        ibn_rva = rdata_rva + 0x50

        body = bytearray(0x100)
        struct.pack_into(
            "<IIIIIIII", body, 0x00,
            0,                # attrs (v1: VA-based)
            dll_name_va,
            0,
            iat_va,
            int_va,
            0,
            0,
            0xCAFE,
        )
        struct.pack_into("<I", body, 0x48, ibn_rva)
        struct.pack_into("<I", body, 0x4C, 0)
        struct.pack_into("<H", body, 0x50, 0)
        body[0x52 : 0x52 + 9] = b"LegacyFn\x00"
        body[0x60 : 0x60 + 10] = b"OLDDLL.dll"

        pe_bytes = _build_pe(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x10,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x10,
                },
                {
                    "name": b".rdata",
                    "vsize": 0x100,
                    "vaddr": rdata_rva,
                    "rsize": FILE_ALIGN,
                    "rptr": rdata_rptr,
                    "chars": 0x40000040,
                    "body": bytes(body),
                },
            ],
            data_dirs=[
                (0, 0), (0, 0), (0, 0), (0, 0), (0, 0), (0, 0),
                (0, 0), (0, 0), (0, 0), (0, 0), (0, 0), (0, 0),
                (0, 0),
                (rdata_rva, 0x40),
            ],
        )
        pe = win32_platform.parse_pe(pe_bytes)
        self.assertEqual(len(pe.delay_imports), 1)
        self.assertEqual(pe.delay_imports[0].dll, "OLDDLL.dll")
        self.assertEqual(pe.delay_imports[0].name, "LegacyFn")

    def test_pe32_plus_delay_import(self):
        """PE32+ delay imports use 8-byte thunks; verify the 64-bit
        path. (The default tests use 4-byte PE32 thunks.)"""
        rdata_rva = 0x2000
        rdata_rptr = FILE_ALIGN * 2

        dll_name_rva = rdata_rva + 0x80
        iat_rva = rdata_rva + 0x40
        int_rva = rdata_rva + 0x50
        ibn_rva = rdata_rva + 0x70

        body = bytearray(0x100)
        struct.pack_into(
            "<IIIIIIII", body, 0x00,
            1, dll_name_rva, 0, iat_rva, int_rva, 0, 0, 0,
        )
        # ILT: one 8-byte entry pointing at IMAGE_IMPORT_BY_NAME, then NUL.
        struct.pack_into("<Q", body, 0x50, ibn_rva)
        struct.pack_into("<Q", body, 0x58, 0)
        # IMAGE_IMPORT_BY_NAME (hint + name).
        struct.pack_into("<H", body, 0x70, 0)
        body[0x72 : 0x72 + 11] = b"NtCreateFile\x00"[:11]
        body[0x80 : 0x80 + 11] = b"ntdll.dll\x00"

        pe_bytes = _build_pe_plus(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x10,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x10,
                },
                {
                    "name": b".rdata",
                    "vsize": 0x100,
                    "vaddr": rdata_rva,
                    "rsize": FILE_ALIGN,
                    "rptr": rdata_rptr,
                    "chars": 0x40000040,
                    "body": bytes(body),
                },
            ],
            data_dirs=[
                (0, 0), (0, 0), (0, 0), (0, 0), (0, 0), (0, 0),
                (0, 0), (0, 0), (0, 0), (0, 0), (0, 0), (0, 0),
                (0, 0),
                (rdata_rva, 0x40),
            ],
        )
        pe = win32_platform.parse_pe(pe_bytes)
        self.assertTrue(pe.is_pe32_plus)
        self.assertEqual(len(pe.delay_imports), 1)
        self.assertEqual(pe.delay_imports[0].dll, "ntdll.dll")
        self.assertEqual(pe.delay_imports[0].iat_rva, iat_rva)

    def test_v2_delay_import(self):
        rdata_rva = 0x2000
        rdata_rptr = FILE_ALIGN * 2

        # IMAGE_DELAYLOAD_DESCRIPTOR (v2 / RVA-based, attrs = 1):
        #   0x00 = attrs
        #   0x04 = dll name RVA
        #   0x08 = module handle RVA
        #   0x0C = IAT RVA
        #   0x10 = INT RVA
        # Then a NULL terminator (32 bytes of zeros).
        dll_name_rva = rdata_rva + 0x60
        iat_rva = rdata_rva + 0x40
        int_rva = rdata_rva + 0x48
        ibn_rva = rdata_rva + 0x50

        body = bytearray(0x100)
        struct.pack_into(
            "<IIIIIIII", body, 0x00,
            1, dll_name_rva, 0, iat_rva, int_rva, 0, 0, 0xCAFEBABE,
        )
        # INT table — one entry (named) + NULL terminator
        struct.pack_into("<I", body, 0x48, ibn_rva)
        struct.pack_into("<I", body, 0x4C, 0)
        # IMAGE_IMPORT_BY_NAME: hint + name
        struct.pack_into("<H", body, 0x50, 0)
        body[0x52 : 0x52 + 9] = b"D3DXLoad\x00"
        # DLL name
        body[0x60 : 0x60 + 10] = b"d3d8.dll\x00"

        pe_bytes = _build_pe(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x10,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x10,
                },
                {
                    "name": b".rdata",
                    "vsize": 0x100,
                    "vaddr": rdata_rva,
                    "rsize": FILE_ALIGN,
                    "rptr": rdata_rptr,
                    "chars": 0x40000040,
                    "body": bytes(body),
                },
            ],
            # Delay-import dir is index 13.
            data_dirs=[
                (0, 0), (0, 0), (0, 0), (0, 0), (0, 0), (0, 0),
                (0, 0), (0, 0), (0, 0), (0, 0), (0, 0), (0, 0),
                (0, 0),
                (rdata_rva, 0x40),
            ],
        )
        pe = win32_platform.parse_pe(pe_bytes)
        self.assertEqual(len(pe.delay_imports), 1)
        self.assertEqual(pe.delay_imports[0].dll, "d3d8.dll")
        self.assertEqual(pe.delay_imports[0].name, "D3DXLoad")
        self.assertEqual(pe.delay_imports[0].iat_rva, iat_rva)


class PEPlusImportTest(unittest.TestCase):
    def test_pe32_plus_imports(self):
        """PE32+ imports walk 8-byte thunks; the ordinal flag sits in the
        high bit of a QWORD, not a DWORD. Verify the 64-bit path."""
        rdata_rva = 0x2000
        rdata_rptr = FILE_ALIGN * 2

        ilt_rva = rdata_rva + 0x28
        iat_rva = rdata_rva + 0x40
        dll_name_rva = rdata_rva + 0x70
        ibn_rva = rdata_rva + 0x60

        body = bytearray(0x100)
        struct.pack_into(
            "<IIIII", body, 0x00,
            ilt_rva, 0, 0, dll_name_rva, iat_rva,
        )
        # ILT: 8-byte entry pointing at IMAGE_IMPORT_BY_NAME, then NUL.
        struct.pack_into("<Q", body, 0x28, ibn_rva)
        struct.pack_into("<Q", body, 0x30, 0)
        # IAT mirrors ILT
        struct.pack_into("<Q", body, 0x40, ibn_rva)
        struct.pack_into("<Q", body, 0x48, 0)
        # IMAGE_IMPORT_BY_NAME at 0x60: hint + name
        struct.pack_into("<H", body, 0x60, 0)
        body[0x62 : 0x62 + 11] = b"NtReadFile\x00"
        # DLL name at 0x70 (no overlap with IBN)
        body[0x70 : 0x70 + 10] = b"ntdll.dll\x00"

        pe_bytes = _build_pe_plus(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x10,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x10,
                },
                {
                    "name": b".rdata",
                    "vsize": 0x100,
                    "vaddr": rdata_rva,
                    "rsize": FILE_ALIGN,
                    "rptr": rdata_rptr,
                    "chars": 0x40000040,
                    "body": bytes(body),
                },
            ],
            data_dirs=[(0, 0), (rdata_rva, 0x28)],
        )
        pe = win32_platform.parse_pe(pe_bytes)
        self.assertTrue(pe.is_pe32_plus)
        self.assertEqual(len(pe.imports), 1)
        self.assertEqual(pe.imports[0].dll, "ntdll.dll")
        self.assertEqual(pe.imports[0].name, "NtReadFile")
        self.assertEqual(pe.imports[0].iat_rva, iat_rva)


class PEPlusOrdinalImportTest(unittest.TestCase):
    def test_pe32_plus_ordinal_import(self):
        """PE32+ ordinal-only imports set bit 63 of the 8-byte thunk
        (vs bit 31 on PE32). Verify the 64-bit ordinal-flag path."""
        rdata_rva = 0x2000
        rdata_rptr = FILE_ALIGN * 2

        ilt_rva = rdata_rva + 0x28
        iat_rva = rdata_rva + 0x40
        dll_name_rva = rdata_rva + 0x60

        body = bytearray(0x80)
        struct.pack_into(
            "<IIIII", body, 0x00,
            ilt_rva, 0, 0, dll_name_rva, iat_rva,
        )
        # ILT: 8-byte ordinal-only entry (bit 63 set, low 16 = ordinal 42)
        struct.pack_into("<Q", body, 0x28, (1 << 63) | 42)
        struct.pack_into("<Q", body, 0x30, 0)
        # IAT mirrors
        struct.pack_into("<Q", body, 0x40, (1 << 63) | 42)
        struct.pack_into("<Q", body, 0x48, 0)
        body[0x60 : 0x60 + 10] = b"WS2_32.dll"

        pe_bytes = _build_pe_plus(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x10,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x10,
                },
                {
                    "name": b".rdata",
                    "vsize": 0x80,
                    "vaddr": rdata_rva,
                    "rsize": FILE_ALIGN,
                    "rptr": rdata_rptr,
                    "chars": 0x40000040,
                    "body": bytes(body),
                },
            ],
            data_dirs=[(0, 0), (rdata_rva, 0x28)],
        )
        pe = win32_platform.parse_pe(pe_bytes)
        self.assertTrue(pe.is_pe32_plus)
        self.assertEqual(len(pe.imports), 1)
        self.assertEqual(pe.imports[0].dll, "WS2_32.dll")
        self.assertIsNone(pe.imports[0].name)
        self.assertEqual(pe.imports[0].ordinal, 42)


class PEImportIatZeroSkipTest(unittest.TestCase):
    def test_descriptor_with_zero_iat_is_skipped(self):
        """An IMAGE_IMPORT_DESCRIPTOR with iat_rva == 0 has no IAT slot
        VA to attach thunks to. parse_imports must skip such descriptors
        rather than emit bogus PEImport entries pointing at slot 0."""
        rdata_rva = 0x2000
        rdata_rptr = FILE_ALIGN * 2

        ilt_rva = rdata_rva + 0x28
        dll_name_rva = rdata_rva + 0x40

        body = bytearray(0x60)
        # Descriptor with iat_rva = 0 (malformed but encountered in
        # corrupt binaries).
        struct.pack_into(
            "<IIIII", body, 0x00,
            ilt_rva, 0, 0, dll_name_rva, 0,
        )
        struct.pack_into("<I", body, 0x28, 0)  # ILT terminator
        body[0x40 : 0x40 + 11] = b"BadDll.dll\x00"

        pe_bytes = _build_pe(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x10,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x10,
                },
                {
                    "name": b".rdata",
                    "vsize": 0x60,
                    "vaddr": rdata_rva,
                    "rsize": FILE_ALIGN,
                    "rptr": rdata_rptr,
                    "chars": 0x40000040,
                    "body": bytes(body),
                },
            ],
            data_dirs=[(0, 0), (rdata_rva, 20)],
        )
        pe = win32_platform.parse_pe(pe_bytes)
        # The descriptor is parsed (DLL name known) but no PEImport
        # entries are recorded since slot VAs would be meaningless.
        self.assertEqual(pe.imports, [])


class PEOrdinalImportTest(unittest.TestCase):
    def test_ordinal_import(self):
        rdata_rva = 0x2000
        rdata_rptr = FILE_ALIGN * 2

        ilt_rva = rdata_rva + 0x28
        iat_rva = rdata_rva + 0x30
        dll_name_rva = rdata_rva + 0x40

        body = bytearray(0x60)
        struct.pack_into(
            "<IIIII", body, 0x00,
            ilt_rva, 0, 0, dll_name_rva, iat_rva,
        )
        # Ordinal-only entry: high bit set, low 16 bits hold the ordinal.
        struct.pack_into("<I", body, 0x28, 0x80000000 | 17)
        struct.pack_into("<I", body, 0x2C, 0)  # ILT terminator
        struct.pack_into("<I", body, 0x30, 0x80000000 | 17)
        struct.pack_into("<I", body, 0x34, 0)
        body[0x40 : 0x40 + 11] = b"OTHER.dll\x00"

        pe_bytes = _build_pe(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x10,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x10,
                },
                {
                    "name": b".rdata",
                    "vsize": 0x60,
                    "vaddr": rdata_rva,
                    "rsize": FILE_ALIGN,
                    "rptr": rdata_rptr,
                    "chars": 0x40000040,
                    "body": bytes(body),
                },
            ],
            data_dirs=[(0, 0), (rdata_rva, 40)],
        )
        pe = win32_platform.parse_pe(pe_bytes)
        self.assertEqual(len(pe.imports), 1)
        self.assertIsNone(pe.imports[0].name)
        self.assertEqual(pe.imports[0].ordinal, 17)
        self.assertEqual(pe.imports[0].dll, "OTHER.dll")


class PERelocsTest(unittest.TestCase):
    def test_non_pointer_reloc_types_skipped(self):
        """Reloc types other than HIGHLOW (3) and DIR64 (10) — LOW (1),
        HIGH (2), HIGHADJ (4), and ABSOLUTE (0) padding — must NOT
        populate pe.pointer_rvas. They describe partial relocations or
        padding, not full pointers."""
        reloc_rva = 0x4000
        reloc_rptr = FILE_ALIGN * 3
        block = struct.pack("<II", 0x6000, 20) + struct.pack(
            "<HHHHHH",
            (1 << 12) | 0x010,    # LOW — skip
            (2 << 12) | 0x020,    # HIGH — skip
            (4 << 12) | 0x030,    # HIGHADJ — skip
            (0 << 12) | 0x040,    # ABSOLUTE padding — skip
            (3 << 12) | 0x050,    # HIGHLOW — accept
            0,                     # padding
        )

        pe_bytes = _build_pe(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x10,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x10,
                },
                {
                    "name": b".reloc",
                    "vsize": len(block),
                    "vaddr": reloc_rva,
                    "rsize": FILE_ALIGN,
                    "rptr": reloc_rptr,
                    "chars": 0x42000040,
                    "body": block,
                },
            ],
            data_dirs=[
                (0, 0), (0, 0), (0, 0), (0, 0), (0, 0),
                (reloc_rva, len(block)),
            ],
        )
        pe = win32_platform.parse_pe(pe_bytes)
        # Only the HIGHLOW entry should land in pointer_rvas.
        self.assertEqual(pe.pointer_rvas, {0x6050})

    def test_dir64_relocs(self):
        """PE32+ binaries emit IMAGE_REL_BASED_DIR64 (type 10) entries.
        Verify the parser accepts both HIGHLOW (type 3) and DIR64 (type 10)
        in the same block — both flag the same `pointer_rvas` set."""
        reloc_rva = 0x4000
        reloc_rptr = FILE_ALIGN * 3
        block = struct.pack("<II", 0x5000, 16) + struct.pack(
            "<HHHH",
            (10 << 12) | 0x008,    # DIR64
            (10 << 12) | 0x020,    # DIR64
            (3 << 12) | 0x040,     # HIGHLOW
            0,                      # padding entry — must be ignored
        )

        pe_bytes = _build_pe_plus(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x10,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x10,
                },
                {
                    "name": b".reloc",
                    "vsize": len(block),
                    "vaddr": reloc_rva,
                    "rsize": FILE_ALIGN,
                    "rptr": reloc_rptr,
                    "chars": 0x42000040,
                    "body": block,
                },
            ],
            data_dirs=[
                (0, 0), (0, 0), (0, 0), (0, 0), (0, 0),
                (reloc_rva, len(block)),
            ],
        )
        pe = win32_platform.parse_pe(pe_bytes)
        self.assertEqual(pe.pointer_rvas, {0x5008, 0x5020, 0x5040})

    def test_multi_block_relocs(self):
        """Two reloc blocks across different 4 KB pages should both be
        captured, with type-0 padding skipped."""
        reloc_rva = 0x4000
        reloc_rptr = FILE_ALIGN * 3
        block_a = struct.pack(
            "<II", 0x3000, 16
        ) + struct.pack(
            "<HHHH",
            (3 << 12) | 0x040,
            (3 << 12) | 0x050,
            (3 << 12) | 0x060,
            0,                           # padding
        )
        block_b = struct.pack(
            "<II", 0x5000, 12
        ) + struct.pack(
            "<HH",
            (3 << 12) | 0x100,
            (3 << 12) | 0x200,
        )
        body = block_a + block_b

        pe_bytes = _build_pe(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x10,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x10,
                },
                {
                    "name": b".reloc",
                    "vsize": len(body),
                    "vaddr": reloc_rva,
                    "rsize": FILE_ALIGN,
                    "rptr": reloc_rptr,
                    "chars": 0x42000040,
                    "body": body,
                },
            ],
            data_dirs=[(0, 0), (0, 0), (0, 0), (0, 0), (0, 0), (reloc_rva, len(body))],
        )
        pe = win32_platform.parse_pe(pe_bytes)
        self.assertEqual(
            pe.pointer_rvas,
            {0x3040, 0x3050, 0x3060, 0x5100, 0x5200},
        )

    def test_highlow_relocs(self):
        # Place a small .reloc block describing two HIGHLOW relocs on page
        # 0x3000, at offsets 0x010 and 0x020.
        reloc_rva = 0x4000
        reloc_rptr = FILE_ALIGN * 3
        block_size = 8 + 2 + 2 + 2 + 2  # header + 4 WORD entries
        block = struct.pack(
            "<II", 0x3000, block_size
        ) + struct.pack(
            "<HHHH",
            (3 << 12) | 0x010,
            (3 << 12) | 0x020,
            0,                       # padding entry (skipped)
            0,                       # padding entry (skipped)
        )
        body = block

        pe_bytes = _build_pe(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x10,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x10,
                },
                {
                    "name": b".reloc",
                    "vsize": len(body),
                    "vaddr": reloc_rva,
                    "rsize": FILE_ALIGN,
                    "rptr": reloc_rptr,
                    "chars": 0x42000040,
                    "body": body,
                },
            ],
            data_dirs=[(0, 0), (0, 0), (0, 0), (0, 0), (0, 0), (reloc_rva, len(body))],
        )
        pe = win32_platform.parse_pe(pe_bytes)
        self.assertEqual(pe.pointer_rvas, {0x3010, 0x3020})


class WideStringDetectionTest(unittest.TestCase):
    """Wide-string scanner returns the byte range past the WCHAR NUL."""

    def test_simple_utf16_string(self):
        from src.splat.segtypes.win32.data import _scan_wide_string, _decode_wide

        # "Hello\0" in UTF-16LE
        blob = b"H\x00e\x00l\x00l\x00o\x00\x00\x00"
        end = _scan_wide_string(blob, 0)
        self.assertEqual(end, 12)
        self.assertEqual(_decode_wide(blob[: end - 2]), "Hello")

    def test_too_short_rejected(self):
        from src.splat.segtypes.win32.data import _scan_wide_string

        # "Hi\0" — only 2 WCHARs, below WIDE_STRING_MIN_LEN=4.
        self.assertIsNone(_scan_wide_string(b"H\x00i\x00\x00\x00", 0))

    def test_misaligned_offset(self):
        from src.splat.segtypes.win32.data import _scan_wide_string

        # Odd start offsets aren't valid WCHAR positions.
        blob = b"\x00H\x00e\x00l\x00l\x00o\x00\x00\x00"
        self.assertIsNone(_scan_wide_string(blob, 1))

    def test_high_byte_nonzero_rejected(self):
        from src.splat.segtypes.win32.data import _scan_wide_string

        # If the WCHAR's high byte is nonzero (extended chars), our
        # cautious detector skips it to avoid false positives.
        blob = b"\xC3\x00\xA9\x00\xC3\x00\xA9\x00\x00\x00"  # "éé"
        self.assertIsNone(_scan_wide_string(blob, 0))


class Win32SegBssTest(unittest.TestCase):
    def test_reserved_size_resolution(self):
        """Win32SegBss.reserved_size resolves: explicit yaml bss_size
        wins over vram-end - vram-start arithmetic; zero when neither
        is available."""
        from src.splat.segtypes.win32.bss import Win32SegBss

        obj = Win32SegBss.__new__(Win32SegBss)

        # 1) Explicit bss_size in yaml wins.
        obj.yaml = {"bss_size": 0x1000}
        obj.vram_start = 0x10000000
        # vram_end is a @property derived from vram_start + size; ignore
        # via direct attribute override.
        self.assertEqual(obj.reserved_size, 0x1000)

        # 2) Without bss_size, fall back to vram_end - vram_start.
        # vram_end on the Segment base is a property — emulate by giving
        # obj.rom_start / rom_end so size resolves to a known value.
        obj.yaml = {}
        obj.rom_start = 0
        obj.rom_end = 0x500
        # vram_end = vram_start + (rom_end - rom_start) = 0x10000500
        self.assertEqual(obj.reserved_size, 0x500)

        # 3) Neither yaml nor a derivable vram_end → 0.
        obj.yaml = {}
        obj.rom_start = None
        obj.rom_end = None
        obj.vram_start = None
        self.assertEqual(obj.reserved_size, 0)


class Win32ExactEncodingInheritanceTest(unittest.TestCase):
    def test_inheritance_chain(self):
        """exact_encoding resolves in priority order:
        subsegment YAML > parent code-group YAML > class default."""
        from src.splat.segtypes.win32.text import Win32SegText
        from src.splat.segtypes.win32.data import Win32SegData

        for cls in (Win32SegText, Win32SegData):
            # Instantiate manually (bypass splat's segment factory).
            obj = cls.__new__(cls)
            obj.yaml = {}
            obj.parent = None
            self.assertFalse(obj.exact_encoding)  # class default

            obj.yaml = {"exact_encoding": True}
            self.assertTrue(obj.exact_encoding)  # per-subsegment override

            obj.yaml = {}
            # Use a simple namespace as parent — it just needs a .yaml attr.
            import types

            obj.parent = types.SimpleNamespace(yaml={"exact_encoding": True})
            self.assertTrue(obj.exact_encoding)  # inherited from parent

            obj.yaml = {"exact_encoding": False}
            self.assertFalse(
                obj.exact_encoding
            )  # subsegment value wins over parent


class CreateConfigRejectionTest(unittest.TestCase):
    def test_non_pe_file_falls_through_to_error(self):
        """create_config.main() with a file that's neither N64 / PSX /
        ELF / PE bytes must log.error → SystemExit, not crash silently
        partway through."""
        import tempfile
        from src.splat.scripts.create_config import main as create_config_main
        from pathlib import Path as _P

        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(b"random non-PE garbage data, neither MZ nor ELF")
            tmp = _P(f.name)
        try:
            with self.assertRaises(SystemExit):
                create_config_main(tmp, None)
        finally:
            tmp.unlink()


class Win32SegtypeAliasTest(unittest.TestCase):
    def test_asm_resolves_to_text(self):
        """`type: asm` in YAML must resolve to Win32SegAsm which inherits
        from Win32SegText — same behaviour as `type: text`, matching the
        conventional segtype name used by the other splat platforms."""
        from src.splat.segtypes.win32.asm import Win32SegAsm
        from src.splat.segtypes.win32.text import Win32SegText

        self.assertTrue(issubclass(Win32SegAsm, Win32SegText))
        # No fields overridden — pure alias.
        self.assertEqual(Win32SegAsm.__bases__, (Win32SegText,))


class CapstoneDisassemblerTest(unittest.TestCase):
    def test_known_types_includes_primitive_set(self):
        """CapstoneDisassembler.known_types returns the spimdisasm-mirror
        primitive vocabulary so symbol_addrs.txt `type:u32` /
        `type:asciz` entries get accepted by splat's check_valid_type."""
        from src.splat.disassembler.capstone_disassembler import (
            CapstoneDisassembler,
        )

        d = CapstoneDisassembler()
        kt = d.known_types()
        for t in ("u8", "u32", "s32", "f32", "char", "asciz"):
            self.assertIn(t, kt)

    def test_engine_lazy_creation_uses_pe_bitness(self):
        """get_engine() picks CS_MODE_32 / CS_MODE_64 from the parsed
        PE's is_pe32_plus flag — checks deferred-init path."""
        import capstone
        from src.splat.disassembler.capstone_disassembler import (
            CapstoneDisassembler,
        )

        d = CapstoneDisassembler()

        # Save / restore the global PE info so we don't bleed state.
        old_info = win32_platform.info
        try:
            # PE32 — should get 32-bit mode.
            win32_platform.info = win32_platform.PEInfo(is_pe32_plus=False)
            d._md = None  # force recreation
            md = d.get_engine()
            self.assertEqual(md.mode, capstone.CS_MODE_32)

            # PE32+ — should get 64-bit mode.
            win32_platform.info = win32_platform.PEInfo(is_pe32_plus=True)
            d._md = None
            md = d.get_engine()
            self.assertEqual(md.mode, capstone.CS_MODE_64)
        finally:
            win32_platform.info = old_info


class Win32SubsystemNamesTest(unittest.TestCase):
    def test_subsystem_table_coverage(self):
        """Subsystem ID → name mapping must cover the common values
        emitted by Windows linkers."""
        from src.splat.segtypes.win32.header import _SUBSYSTEMS

        expected = {
            1: "NATIVE",
            2: "WINDOWS_GUI",
            3: "WINDOWS_CUI",
            5: "OS2_CUI",
            7: "POSIX_CUI",
            10: "EFI_APPLICATION",
            14: "XBOX",
        }
        for sid, name in expected.items():
            self.assertEqual(_SUBSYSTEMS.get(sid), name, f"Subsystem {sid}")


class Win32ResourceTypeNamesTest(unittest.TestCase):
    def test_standard_resource_type_names(self):
        """RESOURCE_TYPE_NAMES covers all standard Win32 resource IDs
        (winuser.h RT_*) so the header summary renders them by name
        instead of as `TYPE_<n>`."""
        from src.splat.platforms.win32 import RESOURCE_TYPE_NAMES

        # Spot-check a representative slice from the standard set.
        expected = {
            1: "CURSOR",
            2: "BITMAP",
            3: "ICON",
            4: "MENU",
            5: "DIALOG",
            6: "STRING",
            14: "GROUP_ICON",
            16: "VERSION",
            24: "MANIFEST",
        }
        for rid, name in expected.items():
            self.assertEqual(
                RESOURCE_TYPE_NAMES.get(rid), name, f"RT id {rid}"
            )


class Win32LinkerVersionTest(unittest.TestCase):
    def test_linker_version_label_known_majors(self):
        """linker_version_label maps each MSVC major version to a
        recognizable product name; unknown majors fall back to a
        plain `linker vN.NN` rendering."""
        from src.splat.platforms.win32 import linker_version_label

        self.assertEqual(linker_version_label(6, 0), "MSVC 6.0")
        self.assertEqual(linker_version_label(14, 34), "MSVC 14.x / VS 2015-2022")
        self.assertEqual(linker_version_label(99, 5), "linker v99.05")


class Win32SegHeaderUtilsTest(unittest.TestCase):
    """Targeted tests for the small helpers in header.py — these wrap
    `_decode_flags` and the Subsystem table."""

    def test_decode_characteristics_flags(self):
        from src.splat.segtypes.win32.header import (
            _decode_flags, _FILE_CHARACTERISTICS, _DLL_CHARACTERISTICS,
        )

        self.assertEqual(_decode_flags(0, _FILE_CHARACTERISTICS), "(none)")
        # DLL | EXECUTABLE_IMAGE | 32BIT_MACHINE
        out = _decode_flags(0x2102, _FILE_CHARACTERISTICS)
        self.assertIn("EXECUTABLE_IMAGE", out)
        self.assertIn("32BIT_MACHINE", out)
        self.assertIn("DLL", out)
        # DllCharacteristics
        out = _decode_flags(0x0140, _DLL_CHARACTERISTICS)
        self.assertIn("DYNAMIC_BASE", out)
        self.assertIn("NX_COMPAT", out)


class PEEdgeCasesTest(unittest.TestCase):
    """Defensive parse tests for malformed inputs and unusual but valid PEs."""

    def test_read_cstr_truncation(self):
        """Strings with no NUL terminator get capped at _MAX_CSTR_LEN."""
        big_blob = b"A" * (win32_platform._MAX_CSTR_LEN + 100)
        result = win32_platform._read_cstr(big_blob, 0)
        self.assertEqual(len(result), win32_platform._MAX_CSTR_LEN)

    def test_read_cstr_past_end(self):
        """Out-of-bounds offsets return an empty string, not a crash."""
        self.assertEqual(win32_platform._read_cstr(b"", 0), "")
        self.assertEqual(win32_platform._read_cstr(b"ABC", 99), "")
        self.assertEqual(win32_platform._read_cstr(b"ABC", -1), "")

    def test_resolve_va_to_file_offset_out_of_range(self):
        """VA outside any section returns None."""
        pe_bytes = _build_pe(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x10,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x10,
                },
            ],
        )
        pe = win32_platform.parse_pe(pe_bytes)
        # VA way outside the loaded image.
        self.assertIsNone(pe.va_to_file_offset(0x7FFFFFFF))
        self.assertIsNone(pe.rva_to_file_offset(0x7FFFFFFF))

    def test_truncated_dos_header(self):
        """File shorter than the 64-byte DOS header must be rejected
        explicitly (not raise a struct.error in the parser)."""
        with self.assertRaises(SystemExit):
            win32_platform.parse_pe(b"MZ" + b"\x00" * 10)

    def test_generic_unsupported_machine_rejected(self):
        """Non-x86 / non-ARM machine codes (MIPS, PowerPC, Alpha, etc.)
        also hit the win32 init() rejection — generic message rather
        than the ARM-specific one."""
        # Machine = 0x0166 (R3000-LE) → not i386/amd64/arm64/arm32.
        coff_off = 0x40 + 4
        coff = struct.pack(
            "<HHIIIHH",
            0x0166, 1, 0x12345678, 0, 0, 0xE0, 0x010F,
        )
        opt = _opt_header_pe32(entry_rva=0x1000)
        sec = _section_header(
            b".text", 0x10, 0x1000, FILE_ALIGN, FILE_ALIGN, 0x60000020
        )
        header = DOS_STUB + b"PE\x00\x00" + coff + opt + sec
        blob = bytes(header).ljust(FILE_ALIGN * 2, b"\x00")
        # parse_pe still works (architecture-neutral).
        pe = win32_platform.parse_pe(blob)
        self.assertEqual(pe.machine, 0x0166)
        with self.assertRaises(SystemExit):
            win32_platform.init(blob)

    def test_arm64_machine_rejected_at_init(self):
        """ARM64 PE binaries parse cleanly through parse_pe (structures
        are architecture-neutral) but init() must reject them with an
        explicit message — the disassembler is x86-only."""
        # Hand-build a tiny PE32+ with Machine = 0xAA64 (ARM64).
        coff_off = 0x40 + 4
        coff = struct.pack(
            "<HHIIIHH",
            0xAA64, 1, 0x12345678, 0, 0, 0xF0, 0x002F,
        )
        opt = _opt_header_pe32_plus(entry_rva=0x1000)
        sec = _section_header(
            b".text", 0x10, 0x1000, FILE_ALIGN, FILE_ALIGN, 0x60000020
        )
        header = DOS_STUB + b"PE\x00\x00" + coff + opt + sec
        blob = bytes(header).ljust(FILE_ALIGN * 2, b"\x00")
        # parse_pe alone is OK — structures are arch-neutral.
        pe = win32_platform.parse_pe(blob)
        self.assertEqual(pe.machine, 0xAA64)
        # init() escalates to log.error → SystemExit because the
        # downstream x86 capstone backend can't disassemble ARM64.
        with self.assertRaises(SystemExit):
            win32_platform.init(blob)

    def test_section_table_truncated(self):
        """NumberOfSections * 40 must fit between the end of the optional
        header and EOF. Declaring 10 sections but only providing 2 must
        be caught explicitly."""
        coff_off = 0x40 + 4
        coff = struct.pack(
            "<HHIIIHH",
            0x014C, 10,                  # claim 10 sections
            0x12345678, 0, 0, 0xE0, 0x010F,
        )
        opt = _opt_header_pe32(entry_rva=0x1000)
        # Only enough space for 2 section headers — half of the declared.
        sec = b"\x00" * (40 * 2)
        header = DOS_STUB + b"PE\x00\x00" + coff + opt + sec
        # Truncate so the remaining 8 sections can't fit.
        header = header[: 0x40 + 4 + 20 + 0xE0 + 40 * 2]
        with self.assertRaises(SystemExit):
            win32_platform.parse_pe(header)

    def test_zero_optional_header_size(self):
        """SizeOfOptionalHeader == 0 means there's no optional header
        at all (technically valid only for COFF object files, not PE
        images). Parser must reject before attempting to read the
        2-byte magic field."""
        coff_off = 0x40 + 4
        coff = struct.pack(
            "<HHIIIHH",
            0x014C, 0, 0x12345678, 0, 0, 0, 0x010F,
        )
        header = DOS_STUB + b"PE\x00\x00" + coff
        header = header.ljust(FILE_ALIGN, b"\x00")
        with self.assertRaises(SystemExit):
            win32_platform.parse_pe(bytes(header))

    def test_sub_minimum_optional_header_size(self):
        """Optional header smaller than the per-format minimum (96 for
        PE32, 112 for PE32+) can't fit the data-directory offsets we
        expect to read. Parser must reject."""
        coff_off = 0x40 + 4
        # PE32 optional header but declared size 32 (less than the 96
        # required for windows-specific + data-directories).
        coff = struct.pack(
            "<HHIIIHH",
            0x014C, 0, 0x12345678, 0, 0, 32, 0x010F,
        )
        # First 32 bytes of a PE32 optional header (just standard fields).
        opt = struct.pack(
            "<HBBIIIIIII",
            0x010B, 6, 0,
            0x200, 0x200, 0,
            0x1000, 0x1000, 0x2000,
            0x400000,
        )
        assert len(opt) == 32
        header = DOS_STUB + b"PE\x00\x00" + coff + opt
        header = header.ljust(FILE_ALIGN, b"\x00")
        with self.assertRaises(SystemExit):
            win32_platform.parse_pe(bytes(header))

    def test_unknown_optional_header_magic(self):
        """Optional header magic must be 0x10B (PE32) or 0x20B (PE32+).
        Older formats like ROM image (0x107) or future values must be
        rejected before we try to read PE32-specific offsets."""
        coff_off = 0x40 + 4
        coff = struct.pack(
            "<HHIIIHH",
            0x014C, 1, 0x12345678, 0, 0, 0xE0, 0x010F,
        )
        # Build a valid-looking PE32 optional header then overwrite the
        # magic to 0x107 (ROM image, unsupported).
        opt = bytearray(_opt_header_pe32(entry_rva=0x1000))
        struct.pack_into("<H", opt, 0, 0x0107)
        sec = _section_header(
            b".text", 0x10, 0x1000, FILE_ALIGN, FILE_ALIGN, 0x60000020
        )
        header = DOS_STUB + b"PE\x00\x00" + coff + bytes(opt) + sec
        with self.assertRaises(SystemExit):
            win32_platform.parse_pe(
                bytes(header).ljust(FILE_ALIGN * 2, b"\x00")
            )

    def test_truncated_after_pe_signature(self):
        """File large enough to hold MZ + e_lfanew + 'PE\\0\\0' but not
        the trailing 20-byte COFF file header must be rejected before
        struct.unpack_from would walk past EOF."""
        dos = bytearray(64)
        dos[0:2] = b"MZ"
        dos[0x3C:0x40] = struct.pack("<I", 0x40)
        # 'PE\0\0' present but only ~8 trailing bytes — not enough for the
        # 20-byte IMAGE_FILE_HEADER that follows.
        blob = bytes(dos) + b"PE\x00\x00" + b"\x00" * 8
        with self.assertRaises(SystemExit):
            win32_platform.parse_pe(blob)

    def test_pe32_plus_amd64_magic_combination_accepted(self):
        """AMD64 Machine + PE32+ Magic 0x20B must be accepted. Pairs
        with the mismatch test — confirms the cross-validation only
        rejects genuine mismatches, not all PE32+ pairings."""
        pe_bytes = _build_pe_plus(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x10,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x10,
                },
            ],
        )
        pe = win32_platform.parse_pe(pe_bytes)
        self.assertEqual(pe.machine, 0x8664)
        self.assertTrue(pe.is_pe32_plus)
        self.assertEqual(pe.image_base, 0x140000000)

    def test_machine_magic_mismatch(self):
        """A PE file with i386 Machine but PE32+ optional header magic
        (or vice-versa) must be rejected — both fields encode pointer
        size and they must agree."""
        # i386 Machine + PE32+ magic.
        coff_off = 0x40 + 4
        coff = struct.pack(
            "<HHIIIHH",
            0x014C, 1, 0x12345678, 0, 0, 0xF0, 0x010F,
        )
        # PE32+ optional header (240 bytes) but Machine claims i386.
        opt = _opt_header_pe32_plus(entry_rva=0x1000)
        sec = _section_header(
            b".text", 0x10, 0x1000, FILE_ALIGN, FILE_ALIGN, 0x60000020
        )
        header = DOS_STUB + b"PE\x00\x00" + coff + opt + sec
        with self.assertRaises(SystemExit):
            win32_platform.parse_pe(bytes(header).ljust(FILE_ALIGN * 2, b"\x00"))

    def test_missing_pe_signature(self):
        """An MZ header pointing at non-PE bytes must be rejected."""
        # Valid DOS header pointing e_lfanew at 0x40, but the bytes there
        # are not "PE\0\0".
        dos = bytearray(64)
        dos[0:2] = b"MZ"
        dos[0x3C:0x40] = struct.pack("<I", 0x40)
        blob = bytes(dos) + b"NE\x00\x00" + b"\x00" * 100
        with self.assertRaises(SystemExit):
            win32_platform.parse_pe(blob)

    def test_coff_symbol_table_recorded(self):
        """PE binaries essentially never set PointerToSymbolTable
        + NumberOfSymbols (debug info goes in the external .pdb), but
        when they do, those fields surface on PEInfo for the header
        summary to flag."""
        coff_off = 0x40 + 4
        coff = struct.pack(
            "<HHIIIHH",
            0x014C, 1, 0x12345678,
            0x12345, 42,        # PointerToSymbolTable + NumberOfSymbols
            0xE0, 0x010F,
        )
        opt = _opt_header_pe32(entry_rva=0x1000)
        sec = _section_header(
            b".text", 0x10, 0x1000, FILE_ALIGN, FILE_ALIGN, 0x60000020
        )
        header = DOS_STUB + b"PE\x00\x00" + coff + opt + sec
        header = header.ljust(FILE_ALIGN, b"\x00")
        buf = bytearray(header) + b"\x90" * FILE_ALIGN
        pe = win32_platform.parse_pe(bytes(buf))
        self.assertEqual(pe.coff_symtab_ptr, 0x12345)
        self.assertEqual(pe.coff_num_symbols, 42)

    def test_zero_sections(self):
        """Synthetic PE with NumberOfSections=0 — parser should accept
        and downstream rva_to_file_offset should return None for any
        non-trivial RVA without crashing."""
        coff_off = 0x40 + 4
        coff = struct.pack(
            "<HHIIIHH",
            0x014C, 0, 0x12345678, 0, 0, 0xE0, 0x010F,
        )
        opt = _opt_header_pe32(entry_rva=0, data_dirs=())
        header = DOS_STUB + b"PE\x00\x00" + coff + opt
        header = header.ljust(FILE_ALIGN, b"\x00")
        pe = win32_platform.parse_pe(bytes(header))
        self.assertEqual(pe.num_sections, 0)
        self.assertEqual(len(pe.sections), 0)
        self.assertIsNone(pe.rva_to_file_offset(0x1000))

    def test_no_entrypoint(self):
        """Resource-only DLL has entry_point_rva == 0."""
        # We need to override the standard `_build_pe` entry_rva=0x1000
        # default. Bypass by constructing fields directly.
        pe_off = 0x40
        coff = struct.pack(
            "<HHIIIHH",
            0x014C, 1, 0x12345678, 0, 0, 0xE0,
            0x010F | 0x2000,  # add DLL flag
        )
        opt = _opt_header_pe32(entry_rva=0, data_dirs=())
        sec = _section_header(
            b".text", 0x10, 0x1000, FILE_ALIGN, FILE_ALIGN, 0x60000020
        )
        header = DOS_STUB + b"PE\x00\x00" + coff + opt + sec
        header = header.ljust(FILE_ALIGN, b"\x00")
        buf = bytearray(header) + b"\x90" * FILE_ALIGN
        pe = win32_platform.parse_pe(bytes(buf))
        self.assertEqual(pe.entry_point_rva, 0)
        # Should not crash later when consumers check entry_point_va.

    def test_sparse_data_directory_count(self):
        """An optional header can declare NumberOfRvaAndSizes < 16
        (rare, older MSVC). Parser should walk only the declared count
        and leave higher-index lookups defensive."""
        # We construct an optional header by hand with NumberOfRvaAndSizes=2
        # — only Export + Import slots are real; the parser must not try
        # to read Resource / Exception / etc.
        coff_off = 0x40 + 4
        size_of_opt_hdr = 96 + 16  # standard PE32 fields + 2 data dirs
        coff = struct.pack(
            "<HHIIIHH",
            0x014C, 1, 0x12345678, 0, 0, size_of_opt_hdr, 0x010F,
        )
        # Standard fields (28) + windows (68) — last field is
        # NumberOfRvaAndSizes which we set to 2.
        opt = struct.pack(
            "<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII",
            0x010B, 6, 0,
            0x200, 0x200, 0, 0x1000, 0x1000, 0x2000,
            0x400000, 0x1000, 0x200,
            4, 0, 0, 0, 4, 0,
            0, 0x4000, 0x200, 0,
            3, 0,
            0x100000, 0x1000, 0x100000, 0x1000,
            0, 2,                              # NumberOfRvaAndSizes = 2
        )
        # Just two directory entries (Export + Import, both empty).
        opt += struct.pack("<IIII", 0, 0, 0, 0)
        assert len(opt) == size_of_opt_hdr, (len(opt), size_of_opt_hdr)
        sec = _section_header(
            b".text", 0x10, 0x1000, FILE_ALIGN, FILE_ALIGN, 0x60000020
        )
        header = DOS_STUB + b"PE\x00\x00" + coff + opt + sec
        header = header.ljust(FILE_ALIGN, b"\x00")
        buf = bytearray(header) + b"\x90" * FILE_ALIGN
        pe = win32_platform.parse_pe(bytes(buf))
        # Only 2 data directories populated.
        self.assertEqual(len(pe.data_directories), 2)
        # All sub-parsers that need higher indices should no-op.
        self.assertFalse(pe.resources)
        self.assertFalse(pe.runtime_functions)
        self.assertFalse(pe.safe_seh_handlers)
        self.assertFalse(pe.cfg_function_rvas)
        self.assertFalse(pe.bound_imports)
        self.assertFalse(pe.delay_imports)

    def test_empty_data_directory_index(self):
        """Optional header listing fewer than 16 data dirs still parses."""
        # _build_pe always provides space for 16 entries; pass only one
        # (zeros) and verify the others come out empty.
        pe_bytes = _build_pe(
            sections=[
                {
                    "name": b".text",
                    "vsize": 0x10,
                    "vaddr": 0x1000,
                    "rsize": FILE_ALIGN,
                    "rptr": FILE_ALIGN,
                    "chars": 0x60000020,
                    "body": b"\x90" * 0x10,
                },
            ],
            data_dirs=[(0, 0)],
        )
        pe = win32_platform.parse_pe(pe_bytes)
        self.assertFalse(pe.exports)
        self.assertFalse(pe.imports)
        self.assertFalse(pe.resources)
        self.assertFalse(pe.runtime_functions)


if __name__ == "__main__":
    unittest.main()
