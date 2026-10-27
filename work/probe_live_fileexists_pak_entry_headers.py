"""Read compact headers only for exact source-selected bundle filename hash matches."""

import hashlib
import json
from pathlib import Path
import struct
import sys

import probe_live_fileexists_pak_entries as prior
import probe_live_fileexists_pak_decode as decoder
from probe_live_fileexists_target import main


getters=prior.getters
SOURCE_CAPTURE=getters.ROOT/'work/evidence/live-package-pak-decode-bundle-20261006-private.json'
SOURCE_CAPTURE_SHA='7340f93dcfaaf12a54af1fd8093e42fee9f51deed1f43d44257b80f3eda1f9e2'
EXTRA_SPANS=prior.EXTRA_SPANS+((0x1246ac20,118),(0x12463a90,702))
verify_target=prior.verify_target
verify_previous_edges=prior.verify_previous_edges
verify_previous_continuations=prior.verify_previous_continuations
verify_previous_lookup=prior.verify_previous_lookup
verify_previous_lookup_body=prior.verify_previous_lookup_body
verify_previous_index_code=prior.verify_previous_index_code
verify_previous_hash_leaf=prior.verify_previous_hash_leaf


def code_pins():
    d=prior.prior.prior.pinned(SOURCE_CAPTURE,SOURCE_CAPTURE_SHA)
    return {0x1246ac20:bytes.fromhex(d['pak_helper_code']['DecodeEntryPrefix']['bytes']),
            0x12463a90:bytes.fromhex(d['pak_decode_code']['CompactEntryDecode']['bytes'])}


def load_source(path):
    if Path(path).resolve()!=SOURCE_CAPTURE.resolve():raise ValueError('fixed_compact_entry_source_required')
    d=prior.prior.prior.pinned(path,SOURCE_CAPTURE_SHA)
    if d['captured_bytes']!=6339 or d['native_pe_sha256']!=getters.SOURCE_PE:
        raise ValueError('compact_entry_source_chain_changed')
    decoder.verify_helpers({b['rva']:bytes.fromhex(b['bytes']) for b in d['pak_helper_code'].values()})
    return SOURCE_CAPTURE_SHA


def verify_original(path):
    return decoder.verify_original(path)


def check_data_read(address,size,base,module_size,used):
    return prior.check_data_read(address,size,base,module_size,used)


def compact_header_size(flags):
    method=(flags>>23)&0x3f
    return (4+(4 if flags&0x3f==0x3f else 0)+(4 if flags>>31 else 8)
            +(4 if flags&(1<<30) else 8)+((4 if flags&(1<<29) else 8) if method else 0))


def decode_primary_header(raw):
    flags=struct.unpack_from('<I',raw)[0]
    if len(raw)!=compact_header_size(flags):raise ValueError('compact_entry_primary_header_size_changed')
    pos=4;block_size=(flags&0x3f)<<11
    if flags&0x3f==0x3f:
        block_size=struct.unpack_from('<I',raw,pos)[0];pos+=4
    def integer(narrow):
        nonlocal pos
        size=4 if narrow else 8
        result=int.from_bytes(raw[pos:pos+size],'little');pos+=size
        return result
    offset=integer(flags>>31)
    unpacked=integer(flags&(1<<30))
    method=(flags>>23)&0x3f
    packed=integer(flags&(1<<29)) if method else unpacked
    return {'flags':hex(flags),'file_offset':offset,'compressed_size':packed,'uncompressed_size':unpacked,
            'compression_method_index':method,'encrypted':bool(flags&(1<<22)),
            'compression_block_count':(flags>>6)&0xffff,'compression_block_size':block_size}


def capture(read,query,base,module_size,*,source_digest,actual_created,expected_created):
    if source_digest!=SOURCE_CAPTURE_SHA:raise ValueError('pinned_compact_entry_source_required')
    pins=code_pins()
    def fresh(reader,image_base):
        for rva,size in EXTRA_SPANS[-2:]:
            if reader(image_base+rva,size)!=pins[rva]:raise ValueError('compact_entry_fresh_decoder_changed')
    report=prior.capture(read,query,base,module_size,source_digest=prior.SOURCE_CAPTURE_SHA,
                         actual_created=actual_created,expected_created=expected_created,after_code=fresh)
    used=report['additional_typed_bytes']+report['pak_header_typed_bytes']+report['pak_entry_typed_bytes'];extra=0
    def data(address,size):
        nonlocal used,extra
        check_data_read(address,size,base,module_size,used)
        region=query(address)
        if (region.get('state')!=0x1000 or region.get('protect',0)&0x101
                or not region['base']<=address<address+size<=region['base']+region['size']):
            raise ValueError('compact_entry_typed_range_unreadable')
        raw=read(address,size)
        if len(raw)!=size:raise ValueError('short_compact_entry_read')
        used+=size;extra+=size
        return raw
    paks={row['native_filename']:int(row['source_candidate_pointer'],16) for row in report['selected_pak_headers']}
    if len(paks)!=len(report['selected_pak_headers']):raise ValueError('compact_entry_package_filename_not_unique')
    rows=[]
    for row in report['pak_filename_queries']:
        match=row['exact_hash_match']
        if not match or not 0<=match['location_i32']<=0x7ffffffe:continue
        pointer=paks[row['native_pak_filename']];address=pointer+0x218
        header=data(address,16);buffer,count,capacity=struct.unpack('<Qii',header)
        location=match['location_i32']
        if not 0<=location<count<=capacity<=16777216 or location+4>count:
            raise ValueError('compact_entry_buffer_or_location_outside_bound')
        flags=data(buffer+location,4);size=compact_header_size(struct.unpack('<I',flags)[0])
        if location+size>count:raise ValueError('compact_entry_primary_header_exceeds_buffer')
        raw=flags+data(buffer+location+4,size-4)
        if data(address,16)!=header or data(buffer+location,size)!=raw:
            raise ValueError('compact_entry_buffer_or_header_changed')
        rows.append(dict(tab_id=row['tab_id'],role=row['role'],filename_candidate=row['filename_candidate'],
                         native_pak_filename=row['native_pak_filename'],location=location,
                         primary_header_hex=raw.hex(),**decode_primary_header(raw)))
    report.update(source_capture_sha256=source_digest,captured_bytes=report['captured_bytes']+820+extra,
                  compact_entry_typed_bytes=extra,compact_entry_headers=rows,
                  actual_archive_entry_resolved=False,actual_render_proven=False,
                  scope=report['scope']+'; compact header primary fields of exact hash matches only; no resource body or native calls')
    return report


if __name__=='__main__':
    try:
        main(continuation=16)
    except Exception as error:
        if '--output' in sys.argv:
            output=Path(sys.argv[sys.argv.index('--output')+1]).resolve()
            if output.parent==(getters.ROOT/'work/evidence').resolve():
                with output.with_suffix('.error.json').open('x',encoding='utf-8') as stream:
                    json.dump({'status':'failed','error_type':type(error).__name__,'error':str(error),
                               'native_called':False,'actual_archive_entry_resolved':False},stream,indent=2)
        raise
