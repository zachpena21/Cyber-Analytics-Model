"""Restore the frozen LIEF 0.11.5 text semantics on LIEF 0.13.2.

Upstream source: src/PE/Binary.cpp and src/PE/Parser.cpp at tags 0.11.5
and 0.13.2. Normal imports precede delay imports in imported_functions;
the old parser overwrote forwarded names with the export-name table.
"""
import struct


def legacy_text_features(binary, raw):
    libraries='';functions='';names=[]
    if binary.has_imports:
        libraries=' '.join(item.name for item in binary.imports)
        delayed=sum(1 for item in binary.delay_imports for entry in item.entries
                    if not entry.is_ordinal and entry.name)
        imported=list(binary.imported_functions)
        if delayed>len(imported):raise ValueError('Delay-import function count invalid')
        normal=imported[:len(imported)-delayed] if delayed else imported
        functions=' '.join(item.name for item in normal)
    if binary.has_exports:
        # Reconstruct the old named-export overwrite in ordinal order. This
        # also retains the old last-name-wins behavior for export aliases.
        pe=struct.unpack_from('<I',raw,0x3c)[0];optional=pe+24
        magic=struct.unpack_from('<H',raw,optional)[0]
        if magic not in (0x10b,0x20b):raise ValueError('Invalid PE optional header')
        directory=optional+(96 if magic==0x10b else 112)
        rva=struct.unpack_from('<I',raw,directory)[0]
        table=binary.rva_to_offset(rva)
        base=struct.unpack_from('<I',raw,table+16)[0]
        count=struct.unpack_from('<I',raw,table+24)[0]
        if count>1048576:raise ValueError('Export name table too large')
        name_table=binary.rva_to_offset(struct.unpack_from('<I',raw,table+32)[0])
        ordinal_table=binary.rva_to_offset(struct.unpack_from('<I',raw,table+36)[0])
        overrides={};corrupted=set()
        for i in range(count):
            ordinal=struct.unpack_from('<H',raw,ordinal_table+2*i)[0]+base
            offset=binary.rva_to_offset(struct.unpack_from('<I',raw,name_table+4*i)[0])
            if offset<0 or offset>=len(raw):raise ValueError('Export name offset out of bounds')
            end=raw.find(b'\0',offset)
            if end<0:raise ValueError('Unterminated export name')
            name_bytes=raw[offset:end]
            # LIEF 0.11.5 Parser.cpp: MAX_EXPORT_NAME_SIZE = 300. A
            # too-long named export marks its ordinal corrupted permanently,
            # including when a later alias supplies a shorter name.
            if len(name_bytes)>300:corrupted.add(ordinal)
            overrides[ordinal]=name_bytes.decode('utf-8')
        for entry in binary.get_export().entries:
            if entry.ordinal in corrupted:continue
            name=overrides.get(entry.ordinal,entry.name)
            if name:names.append(name)
    return dict(libraries=libraries,functions=functions,exports_list=' '.join(names),exports=len(names))


def install():
    import lief
    import defender.apps as apps
    from defender.models.attribute_extractor import PEAttributeExtractor
    if lief.__version__.split('-')[0]!='0.13.2':raise ValueError('Submission extractor requires LIEF 0.13.2')
    class SubmissionPEAttributeExtractor(PEAttributeExtractor):
        def extract(self):
            attributes=super().extract()
            attributes.update(legacy_text_features(self.lief_binary,self.bytez))
            return attributes
    apps.PEAttributeExtractor=SubmissionPEAttributeExtractor
