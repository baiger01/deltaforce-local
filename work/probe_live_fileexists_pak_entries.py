"""Query only twelve original bundle image filename hashes in source-selected packages."""

import hashlib
import json
from pathlib import Path
import struct
import sys

import probe_live_fileexists_pak_headers as prior
import probe_live_fileexists_pak_helpers as helpers
from probe_live_fileexists_target import main


getters=prior.getters
SOURCE_CAPTURE=getters.ROOT/'work/evidence/live-package-pak-helpers-bundle-20261006-private.json'
SOURCE_CAPTURE_SHA='a5b1e0fd2b01e99d70087c94ea8c75f55f4d7c4528e0cc698f9daa81871cb334'
LOOKUP_RVA,LOOKUP_SIZE=0xdb8360,194
LOOKUP_SHA='e756887b99923681698649ea1099e9a449ee4aede72a8bc916b875e23ecb2c8d'
EXTRA_SPANS=prior.EXTRA_SPANS+((LOOKUP_RVA,LOOKUP_SIZE),)
verify_target=prior.verify_target
verify_previous_edges=prior.verify_previous_edges
verify_previous_continuations=prior.verify_previous_continuations
verify_previous_lookup=prior.verify_previous_lookup
verify_previous_lookup_body=prior.verify_previous_lookup_body
verify_previous_index_code=prior.verify_previous_index_code
verify_previous_hash_leaf=prior.verify_previous_hash_leaf


def verify_map_code(raw):
    if len(raw)!=LOOKUP_SIZE or hashlib.sha256(raw).hexdigest()!=LOOKUP_SHA:
        raise ValueError('pak_entries_fresh_map_lookup_code_changed')
    for rva,expected in ((0xdb837a,'8b4108'),(0xdb8386,'3b4134'),(0xdb8399,'48634e48'),
                         (0xdb83bb,'8b1c9f'),(0xdb83e0,'48392cf8'),(0xdb83ef,'8b5cf810')):
        at=rva-LOOKUP_RVA
        if raw[at:at+len(bytes.fromhex(expected))]!=bytes.fromhex(expected):
            raise ValueError('pak_entries_exact_map_field_changed')


def load_source(path):
    d=prior.prior.pinned(path,SOURCE_CAPTURE_SHA)
    if d['captured_bytes']!=5364 or d['native_pe_sha256']!=getters.SOURCE_PE:
        raise ValueError('pak_entries_source_code_chain_changed')
    verify_map_code(bytes.fromhex(d['pak_helper_code']['FilenameMapLookup']['bytes']))
    prior.load_source(prior.SOURCE_CAPTURE)
    return SOURCE_CAPTURE_SHA


def verify_original(path):
    return helpers.verify_original(path)


def check_data_read(address,size,base,module_size,used):
    if used+size>131072:raise ValueError('pak_entries_typed_read_budget_exceeded')
    prior.check_data_read(address,size,base,module_size,0)


def capture(read,query,base,module_size,*,source_digest,actual_created,expected_created,after_code=None):
    if source_digest!=SOURCE_CAPTURE_SHA:raise ValueError('pinned_pak_entries_source_required')
    def fresh(reader,image_base):
        verify_map_code(reader(image_base+LOOKUP_RVA,LOOKUP_SIZE))
        if after_code is not None:
            after_code(reader,image_base)
    report=prior.capture(read,query,base,module_size,source_digest=prior.SOURCE_CAPTURE_SHA,
                         actual_created=actual_created,expected_created=expected_created,after_code=fresh)
    used=report['additional_typed_bytes']+report['pak_header_typed_bytes'];extra=0
    def data(address,size):
        nonlocal used,extra
        check_data_read(address,size,base,module_size,used)
        region=query(address)
        if (region.get('state')!=0x1000 or region.get('protect',0)&0x101
                or not region['base']<=address<address+size<=region['base']+region['size']):
            raise ValueError('pak_entries_typed_range_unreadable')
        raw=read(address,size)
        if len(raw)!=size:raise ValueError('short_pak_entry_read')
        used+=size;extra+=size
        return raw
    headers={int(row['source_candidate_pointer'],16):row for row in report['selected_pak_headers']}
    fields=((0,8,'records'),(8,4,'sparse_count'),(0x34,4,'free_count'),(0x40,8,'hash_data'),(0x48,4,'hash_count'))
    results=[]
    for directory in report['directory_queries']:
        for candidate in directory['bucket_candidate_records']:
            pointer=int(candidate['shared_record_pointer'],16);pak=headers[pointer]
            if not pak['filename_cache_enabled']:
                raise ValueError('pak_entries_selected_package_requires_other_index')
            index=pointer+0x1c8
            def state():
                return {name:int.from_bytes(data(index+off,size),'little') for off,size,name in fields}
            initial=state();count=initial['sparse_count'];hash_count=initial['hash_count']
            if (not 0<=initial['free_count']<=count<=16777216 or hash_count>16777216
                    or count!=initial['free_count'] and (not hash_count or hash_count&(hash_count-1))):
                raise ValueError('pak_entries_hash_index_shape_invalid')
            for image in directory['source_images']:
                hashed=prior.prior.native_directory_hash(image['filename'])
                head=-1;bucket=None
                if count!=initial['free_count']:
                    bucket=((hashed&0xffffffff)+23*(hashed>>32))&(hash_count-1)
                    table=initial['hash_data'] or index+0x38
                    head=struct.unpack('<i',data(table+bucket*4,4))[0]
                seen=set();match=None
                while head!=-1:
                    if not 0<=head<count or head in seen or len(seen)>=64:
                        raise ValueError('pak_entries_hash_chain_invalid_or_outside_bound')
                    seen.add(head)
                    record=data(initial['records']+head*24,24)
                    key=struct.unpack_from('<Q',record)[0]
                    if key==hashed:
                        match={'record_index':head,'location_i32':struct.unpack_from('<i',record,8)[0],
                               'location_raw':record[8:16].hex()}
                        break
                    head=struct.unpack_from('<i',record,16)[0]
                if state()!=initial or data(pointer+0x24a,1)!=b'\x01':
                    raise ValueError('pak_entries_selected_index_changed')
                results.append({'tab_id':image['tab_id'],'role':image['role'],'filename_candidate':image['filename'],
                                'native_pak_filename':pak['native_filename'],'priority':candidate['priority'],
                                'filename_hash':hex(hashed),'hash_bucket':bucket,'visited_record_count':len(seen),
                                'exact_hash_match':match})
    report.update(source_capture_sha256=source_digest,captured_bytes=report['captured_bytes']+194+extra,
                  pak_entry_typed_bytes=extra,pak_filename_queries=results,
                  filename_normalization_observed=False,actual_archive_entry_resolved=False,
                  native_FileExists_result_observed=False,actual_render_proven=False,
                  scope=report['scope']+'; exact source 24-byte record/hash chains for twelve original filename candidates only')
    return report


if __name__=='__main__':
    try:
        main(continuation=14)
    except Exception as error:
        if '--output' in sys.argv:
            output=Path(sys.argv[sys.argv.index('--output')+1]).resolve()
            if output.parent==(getters.ROOT/'work/evidence').resolve():
                with output.with_suffix('.error.json').open('x',encoding='utf-8') as stream:
                    json.dump({'status':'failed','error_type':type(error).__name__,'error':str(error),
                               'native_called':False,'actual_archive_entry_resolved':False},stream,indent=2)
        raise
