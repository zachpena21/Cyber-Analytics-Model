#!/usr/bin/env python3
"""Bounded, dependency-free PE section/CLR features and fixed import identities.

Layout reference: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
No samples are executed. Import identities come from the cached Docker extractor.
"""
from collections import Counter
import math
import re
import struct

VERSION = 1
SECTION_NAMES = ('pe_header_valid', 'section_table_valid', 'section_raw_bounds_errors',
                 'section_raw_overlap_pairs', 'section_executable_count', 'section_writable_count',
                 'section_wx_count', 'section_zero_raw_count', 'section_uninitialized_count',
                 'section_virtual_excess_fraction', 'section_max_log_virtual_raw_ratio',
                 'section_entropy_min', 'section_entropy_mean', 'section_entropy_max',
                 'section_entropy_raw_weighted', 'section_exec_entropy_mean',
                 'section_raw_bytes_to_file_ratio')
MANAGED_NAMES = ('clr_directory_present', 'clr_header_readable', 'clr_metadata_signature_valid',
                 'clr_metadata_size_to_file_ratio', 'clr_il_only', 'clr_requires_32bit',
                 'clr_prefers_32bit', 'clr_native_entrypoint', 'clr_strong_name_flag')
# Fixed vocabulary, specified before fitting; no label-driven token selection.
IMPORT_TOKENS = ('mscoree.dll', 'python-runtime.dll', 'vcruntime.dll', 'ucrtbase.dll',
                 'msvcrt.dll', 'kernel32.dll', 'kernelbase.dll', 'ntdll.dll', 'user32.dll',
                 'gdi32.dll', 'advapi32.dll', 'shell32.dll', 'ole32.dll', 'oleaut32.dll',
                 'ws2_32.dll', 'winhttp.dll', 'wininet.dll', 'crypt32.dll', 'bcrypt.dll',
                 'bcryptprimitives.dll', 'msedge_elf.dll', 'shlwapi.dll', 'version.dll')
IMPORT_NAMES = tuple('ordinary_import=' + name for name in IMPORT_TOKENS) + ('ordinary_import_api_ms_crt',)
BLOCKS = {'sections': SECTION_NAMES, 'imports': IMPORT_NAMES, 'managed': MANAGED_NAMES}
FEATURE_NAMES = SECTION_NAMES + IMPORT_NAMES + MANAGED_NAMES


def entropy(data):
    if not data:
        return 0.
    n = len(data)
    return -sum((count / n) * math.log2(count / n) for count in Counter(data).values())


def import_values(libraries):
    if not isinstance(libraries, str):
        raise ValueError('Docker ordinary libraries must be a string')
    tokens = {token.lower().replace('\\', '/').rsplit('/', 1)[-1] for token in libraries.split()}
    normalized = set()
    for token in tokens:
        if re.fullmatch(r'python\d+(?:_d)?\.dll', token):
            token = 'python-runtime.dll'
        elif re.fullmatch(r'vcruntime\d+(?:_\d+)?(?:d)?\.dll', token):
            token = 'vcruntime.dll'
        normalized.add(token)
    return [float(name in normalized) for name in IMPORT_TOKENS] + [float(any(
        name.startswith('api-ms-win-crt-') and name.endswith('.dll') for name in tokens))]


def extract(bytez, libraries):
    out = dict.fromkeys(FEATURE_NAMES, 0.)
    out.update(zip(IMPORT_NAMES, import_values(libraries)))
    status = 'invalid_pe_header'
    def finish():
        return dict(values=[float(out[name]) for name in FEATURE_NAMES], status=status)
    if len(bytez) < 64 or bytez[:2] != b'MZ':
        return finish()
    pe = struct.unpack_from('<I', bytez, 60)[0]
    if pe > len(bytez) - 24 or bytez[pe:pe + 4] != b'PE\0\0':
        return finish()
    count = struct.unpack_from('<H', bytez, pe + 6)[0]
    opt_size = struct.unpack_from('<H', bytez, pe + 20)[0]
    opt = pe + 24
    if opt_size < 2 or opt + opt_size > len(bytez):
        return finish()
    magic = struct.unpack_from('<H', bytez, opt)[0]
    if magic not in (0x10b, 0x20b):
        return finish()
    directory_start, number_offset = (96, 92) if magic == 0x10b else (112, 108)
    if opt_size < directory_start:
        return finish()
    out['pe_header_valid'] = 1.
    table = opt + opt_size
    status = 'invalid_section_table'
    # Bound traversal even for corrupted NumberOfSections.
    if count == 0 or count > 96 or table + count * 40 > len(bytez):
        return finish()
    out['section_table_valid'] = 1.
    sections, ranges, entropies, exec_entropies = [], [], [], []
    total_raw, virtual_excess, total_virtual = 0, 0, 0
    ratios = []
    for i in range(count):
        off = table + i * 40
        virtual, rva, raw, pointer = struct.unpack_from('<IIII', bytez, off + 8)
        flags = struct.unpack_from('<I', bytez, off + 36)[0]
        sections.append((rva, virtual, raw, pointer))
        executable, writable = bool(flags & 0x20000000), bool(flags & 0x80000000)
        out['section_executable_count'] += executable
        out['section_writable_count'] += writable
        out['section_wx_count'] += executable and writable
        out['section_zero_raw_count'] += raw == 0
        out['section_uninitialized_count'] += bool(flags & 0x80)
        if raw and (pointer == 0 or pointer > len(bytez) or raw > len(bytez) - pointer):
            out['section_raw_bounds_errors'] += 1
        data = bytez[pointer:min(pointer + raw, len(bytez))] if pointer and pointer < len(bytez) else b''
        if data:
            ranges.append((pointer, pointer + len(data)))
        ent = entropy(data)
        entropies.append(ent)
        if executable:
            exec_entropies.append(ent)
        total_raw += len(data)
        out['section_entropy_raw_weighted'] += ent * len(data)
        virtual_excess += max(virtual - raw, 0)
        total_virtual += virtual
        ratios.append(math.log1p(virtual / max(raw, 1)))
    out['section_raw_overlap_pairs'] = float(sum(max(a, c) < min(b, d)
        for i, (a, b) in enumerate(ranges) for c, d in ranges[i + 1:]))
    out['section_virtual_excess_fraction'] = virtual_excess / max(total_virtual, 1)
    out['section_max_log_virtual_raw_ratio'] = max(ratios)
    out['section_entropy_min'] = min(entropies)
    out['section_entropy_mean'] = sum(entropies) / count
    out['section_entropy_max'] = max(entropies)
    out['section_entropy_raw_weighted'] /= max(total_raw, 1)
    out['section_exec_entropy_mean'] = sum(exec_entropies) / max(len(exec_entropies), 1)
    out['section_raw_bytes_to_file_ratio'] = total_raw / len(bytez)
    status = 'parsed_with_raw_bounds_errors' if out['section_raw_bounds_errors'] else 'parsed'
    num_dirs = struct.unpack_from('<I', bytez, opt + number_offset)[0]
    available = min(num_dirs, (opt_size - directory_start) // 8)
    if available <= 14:
        return finish()
    clr_rva, clr_size = struct.unpack_from('<II', bytez, opt + directory_start + 14 * 8)
    out['clr_directory_present'] = float(clr_rva != 0 and clr_size != 0)
    if not out['clr_directory_present']:
        return finish()
    headers = struct.unpack_from('<I', bytez, opt + 60)[0]
    def map_rva(rva, size):
        if 0 <= rva < headers and size <= headers - rva and size <= len(bytez) - rva:
            return rva
        for start, virtual, raw, pointer in sections:
            delta = rva - start
            if 0 <= delta < max(virtual, raw) and size <= raw - delta:
                offset = pointer + delta
                if pointer and size <= len(bytez) - offset:
                    return offset
        return None
    clr = map_rva(clr_rva, 72) if clr_size >= 72 else None
    if clr is None or struct.unpack_from('<I', bytez, clr)[0] < 72:
        return finish()
    out['clr_header_readable'] = 1.
    metadata_rva, metadata_size, flags = struct.unpack_from('<III', bytez, clr + 8)
    out['clr_metadata_size_to_file_ratio'] = metadata_size / len(bytez)
    metadata = map_rva(metadata_rva, metadata_size) if metadata_size >= 4 else None
    out['clr_metadata_signature_valid'] = float(metadata is not None and bytez[metadata:metadata + 4] == b'BSJB')
    for name, mask in [('clr_il_only', 1), ('clr_requires_32bit', 2), ('clr_strong_name_flag', 8),
                       ('clr_native_entrypoint', 0x10), ('clr_prefers_32bit', 0x20000)]:
        out[name] = float(bool(flags & mask))
    return finish()
