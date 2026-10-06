#!/usr/bin/env python3
"""Bounded static PE import/version metadata for acquisition diagnostics only."""
import struct

VERSION=1
VERSION_KEYS={'CompanyName','FileDescription','FileVersion','InternalName','OriginalFilename','ProductName','ProductVersion','LegalCopyright'}


def extract(data):
    result=dict(valid_pe=False,imports=[],imports_complete=False,version_strings={},version_resource_present=False,
                clr_metadata_valid=False,authenticode_directory_present=False,signature_verified=False,warnings=[])
    def u16(pos):return struct.unpack_from('<H',data,pos)[0]
    def u32(pos):return struct.unpack_from('<I',data,pos)[0]
    try:
        if len(data)<64 or data[:2]!=b'MZ':return result
        pe=u32(60)
        if pe>len(data)-24 or data[pe:pe+4]!=b'PE\0\0':return result
        count=u16(pe+6);opt_size=u16(pe+20);opt=pe+24
        if not 1<=count<=96 or opt+opt_size>len(data):return result
        magic=u16(opt);start,num=(96,92) if magic==0x10b else (112,108) if magic==0x20b else (0,0)
        if not start or opt_size<start:return result
        table=opt+opt_size
        if table+40*count>len(data):return result
        sections=[]
        for i in range(count):
            pos=table+i*40;virtual,rva,size,pointer=struct.unpack_from('<IIII',data,pos+8)
            sections.append((rva,size,pointer))
        def mapped(rva,size):
            if size<0:raise ValueError('Negative range')
            for base,raw,pointer in sections:
                offset=rva-base
                if 0<=offset and offset+size<=raw and pointer+offset+size<=len(data):return pointer+offset
            raise ValueError('Unmapped RVA/range')
        def directory(i):
            if i>=u32(opt+num) or start+(i+1)*8>opt_size:return (0,0)
            return struct.unpack_from('<II',data,opt+start+i*8)
        result.update(valid_pe=True,section_count=count,byte_size=len(data),machine=u16(pe+4))
        security=directory(4);result['authenticode_directory_present']=bool(security[0] and security[1])
        clr=directory(14)
        if clr[0] and clr[1]>=72:
            try:
                c=mapped(clr[0],72);md_rva,md_size=struct.unpack_from('<II',data,c+8)
                md=mapped(md_rva,md_size)
                result['clr_metadata_valid']=md_size>=4 and data[md:md+4]==b'BSJB'
            except ValueError as e:result['warnings'].append('CLR: '+str(e))
        imports=directory(1)
        try:
            if imports[0]:
                if imports[1]<20:raise ValueError('Short import directory')
                for i in range(min(imports[1]//20,512)):
                    pos=mapped(imports[0]+20*i,20);fields=struct.unpack_from('<IIIII',data,pos)
                    if not any(fields):break
                    name=mapped(fields[3],1);end=data.find(b'\0',name,min(name+256,len(data)))
                    if end<0:raise ValueError('Unterminated import name')
                    text=data[name:end].decode('ascii',errors='strict').lower()
                    if not text:raise ValueError('Empty import name')
                    result['imports'].append(text)
                else:raise ValueError('Import directory limit or missing terminator')
            result['imports_complete']=True
        except (ValueError,UnicodeError) as e:result['warnings'].append('Imports: '+str(e))
        result['imports']=sorted(set(result['imports']))
        resource=directory(2)
        if resource[0] and resource[1]:
            def resource_entries(offset):
                pos=mapped(resource[0]+offset,16);n=u16(pos+12)+u16(pos+14)
                if n>512 or offset+16+8*n>resource[1]:raise ValueError('Resource directory bounds')
                pos=mapped(resource[0]+offset+16,8*n)
                return [struct.unpack_from('<II',data,pos+8*i) for i in range(n)]
            def version_blob(blob):
                strings={}
                def walk(pos,end,depth):
                    if depth>8 or pos+6>end:return
                    length,value_length,kind=struct.unpack_from('<HHH',blob,pos)
                    limit=pos+length
                    if length<6 or limit>end:raise ValueError('Version block bounds')
                    cursor=pos+6;units=[]
                    while cursor+2<=limit:
                        unit=struct.unpack_from('<H',blob,cursor)[0];cursor+=2
                        if unit==0:break
                        units.append(unit)
                    else:raise ValueError('Unterminated version key')
                    key=b''.join(struct.pack('<H',v) for v in units).decode('utf-16-le',errors='replace')
                    cursor=(cursor+3)&~3;value_bytes=value_length*2 if kind==1 else value_length
                    if cursor+value_bytes>limit:raise ValueError('Version value bounds')
                    if key in VERSION_KEYS and kind==1:
                        value=blob[cursor:cursor+value_bytes].decode('utf-16-le',errors='replace').rstrip('\0')
                        strings.setdefault(key,[])
                        if value not in strings[key]:strings[key].append(value)
                    cursor=(cursor+value_bytes+3)&~3
                    while cursor+6<=limit:
                        child_length=struct.unpack_from('<H',blob,cursor)[0]
                        if child_length<6:break
                        walk(cursor,limit,depth+1);cursor=(cursor+child_length+3)&~3
                walk(0,len(blob),0);return strings
            try:
                targets=[value for name,value in resource_entries(0) if name==16]
                result['version_resource_present']=bool(targets)
                visited=set();blobs=[]
                def descend(value,depth):
                    if depth>4 or value in visited:raise ValueError('Resource traversal limit/cycle')
                    visited.add(value)
                    if value&0x80000000:
                        for _,child in resource_entries(value&0x7fffffff):descend(child,depth+1)
                    else:
                        if value+16>resource[1]:raise ValueError('Resource data entry bounds')
                        pos=mapped(resource[0]+value,16);rva,size=struct.unpack_from('<II',data,pos)
                        if size>1024*1024:raise ValueError('Version resource size limit')
                        pos=mapped(rva,size);blobs.append(data[pos:pos+size])
                for target in targets:descend(target,0)
                for blob in blobs:
                    for key,values in version_blob(blob).items():
                        result['version_strings'].setdefault(key,[])
                        result['version_strings'][key]=sorted(set(result['version_strings'][key]+values))
            except (ValueError,struct.error) as e:result['warnings'].append('Version: '+str(e))
    except (ValueError,struct.error) as e:result['warnings'].append(type(e).__name__+': '+str(e))
    return result
