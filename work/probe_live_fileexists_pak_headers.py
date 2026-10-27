"""Read filenames and mount prefixes only from four source-selected directory buckets."""

import hashlib
import json
from pathlib import Path
import struct
import sys

import probe_live_fileexists_directory_state as prior
import probe_live_fileexists_pak_lookup as lookup
from probe_live_fileexists_target import main
from probe_live_fileexists_receiver import canonical


getters = prior.getters
SOURCE_CAPTURE = getters.ROOT / 'work/evidence/live-package-fileexists-pak-lookup-bundle-20261005-private.json'
SOURCE_CAPTURE_SHA = '6370695f73ca0e99daee0b72308cf6408a9752f73c14a37edcfe660f2ff8e467'
EXTRA_SPANS = prior.EXTRA_SPANS + ((0x12467e5d, 73), (0x12467eb0, 312), (0x12467fe8, 718))
PINS = {0x12467e5d:(73,'9778bad98759c6c730ada0420c680b3c37fb196796c13e6fb033fb1cb6628099'),
        0x12467eb0:(312,'5bf7054b1754a7c7ff3b813f1d91a57b91163314638ba5cae7d8e46ee3c433f5'),
        0x12467fe8:(718,'71980d01b94924dfb7ee8775525ca3db46a5fa6f2755342b50bc7f8eaa950f11')}
verify_target = prior.verify_target
verify_previous_edges = prior.verify_previous_edges
verify_previous_continuations = prior.verify_previous_continuations
verify_previous_lookup = prior.verify_previous_lookup
verify_previous_lookup_body = prior.verify_previous_lookup_body
verify_previous_index_code = prior.verify_previous_index_code
verify_previous_hash_leaf = prior.verify_previous_hash_leaf


def verify_pak_code(blocks):
    if set(blocks) != set(PINS):
        raise ValueError('pak_headers_source_coordinates_changed')
    for rva,(size,sha) in PINS.items():
        if len(blocks[rva])!=size or hashlib.sha256(blocks[rva]).hexdigest()!=sha:
            raise ValueError('pak_headers_fresh_lookup_code_changed')
    body=blocks[0x12467fe8]
    for rva,raw in ((0x1246803a,'80bf4a02000000'), (0x12468118,'4883c118'), (0x124680ae,'488d9700010000')):
        off=rva-0x12467fe8
        if body[off:off+len(bytes.fromhex(raw))]!=bytes.fromhex(raw):
            raise ValueError('pak_headers_exact_field_instruction_changed')


def load_source(path):
    d=prior.pinned(path,SOURCE_CAPTURE_SHA)
    if d['captured_bytes']!=4390 or d['native_pe_sha256']!=getters.SOURCE_PE:
        raise ValueError('pak_headers_source_chain_changed')
    blocks={b['rva']:bytes.fromhex(b['bytes']) for b in d['pak_lookup_code'].values()}
    b=d['candidate_tail_code'];blocks[b['rva']]=bytes.fromhex(b['bytes'])
    verify_pak_code(blocks)
    prior.load_source(prior.SOURCE_CAPTURE)
    return SOURCE_CAPTURE_SHA


def verify_original(path):
    return lookup.verify_original(path)


def check_data_read(address,size,base,module_size,used):
    if not 0<size<=1024 or used+size>49152:
        raise ValueError('pak_headers_typed_read_budget_exceeded')
    canonical(address,1)
    canonical(address+size-1,1)
    if address<base+module_size and address+size>base:
        raise ValueError('pak_headers_data_read_in_module_refused')


def capture(read,query,base,module_size,*,source_digest,actual_created,expected_created,after_code=None):
    getters.local.verify_creation(actual_created,expected_created)
    if source_digest!=SOURCE_CAPTURE_SHA:
        raise ValueError('pinned_pak_headers_source_required')
    def fresh_code(reader,image_base):
        blocks={rva:reader(image_base+rva,size) for rva,(size,_) in PINS.items()}
        verify_pak_code(blocks)
        if after_code is not None:
            after_code(reader,image_base)
    report=prior.capture(read,query,base,module_size,source_digest=prior.SOURCE_CAPTURE_SHA,
                         actual_created=actual_created,expected_created=expected_created,after_accessor=fresh_code)
    used=report['additional_typed_bytes']
    extra=0
    def data(address,size):
        nonlocal used,extra
        check_data_read(address,size,base,module_size,used)
        region=query(address)
        if (region.get('state')!=0x1000 or region.get('protect',0)&(0x100|1)
                or not region['base']<=address<address+size<=region['base']+region['size']):
            raise ValueError('pak_headers_source_field_unreadable')
        raw=read(address,size)
        if len(raw)!=size:raise ValueError('short_pak_header_read')
        used+=size;extra+=size
        return raw
    def text(address):
        raw=data(address,16);pointer,count,capacity=struct.unpack('<Qii',raw)
        if not 0<=count<=512 or capacity<count:
            raise ValueError('pak_header_string_length_outside_bound')
        value=''
        if count:
            chars=data(pointer,count*2)
            if chars[-2:]!=b'\0\0':raise ValueError('pak_header_string_unterminated')
            value=chars[:-2].decode('utf-16le')
            if '\0' in value:raise ValueError('pak_header_string_embedded_null')
        if data(address,16)!=raw:raise ValueError('pak_header_string_changed')
        return value
    selected=sorted({int(rec['shared_record_pointer'],16) for row in report['directory_queries']
                     for rec in row['bucket_candidate_records']})
    if len(selected)>8:raise ValueError('pak_header_selected_candidate_budget_exceeded')
    rows=[]
    for pointer in selected:
        if not pointer:raise ValueError('pak_header_selected_candidate_null')
        name=text(pointer+0x18)
        mount=text(pointer+0x100)
        flag=data(pointer+0x24a,1)
        if data(pointer+0x24a,1)!=flag:raise ValueError('pak_header_lookup_mode_changed')
        rows.append({'source_candidate_pointer':hex(pointer),'native_filename':name,
                     'native_mount_prefix':mount,'filename_cache_enabled':flag!=b'\0'})
    report.update(source_capture_sha256=source_digest,captured_bytes=report['captured_bytes']+1103+extra,
                  pak_header_typed_bytes=extra,selected_pak_headers=rows,
                  actual_archive_entry_resolved=False,actual_render_proven=False,
                  scope=report['scope']+'; exact source-backed per-package filename/mount-prefix/cache flag only')
    return report


if __name__=='__main__':
    try:
        main(continuation=12)
    except Exception as error:
        if '--output' in sys.argv:
            output = Path(sys.argv[sys.argv.index('--output')+1]).resolve()
            evidence = (getters.ROOT / 'work/evidence').resolve()
            if output.parent == evidence:
                failure = output.with_suffix('.error.json')
                with failure.open('x', encoding='utf-8') as stream:
                    json.dump({'status':'failed', 'error_type':type(error).__name__,
                               'error':str(error), 'native_called':False,
                               'actual_archive_entry_resolved':False}, stream, indent=2)
        raise
