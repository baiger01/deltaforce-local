"""Read source-selected compact entry decoder and its return segment."""

import hashlib
import struct

import probe_live_fileexists_pak_helpers as prior
from probe_live_fileexists_directory_state import pinned
from probe_live_fileexists_target import main


getters=prior.getters
SOURCE_CAPTURE=getters.ROOT/'work/evidence/live-package-pak-helpers-bundle-20261006-private.json'
SOURCE_CAPTURE_SHA='a5b1e0fd2b01e99d70087c94ea8c75f55f4d7c4528e0cc698f9daa81871cb334'
EXTRA_SPANS=((0x1246ad70,273),(0x12463a90,702))
METADATA=(
 ('return_pdata',511491360,'70ad461281ae461280ef801c','bcad48edd91a40cd4e6100bc169d38ea65b4ba871b82b3c1825019e69134208c'),
 ('return_unwind',478208896,'2100000020ac461296ac46122cef801c','34945582032a0037546c92e1e0fcef5f904b55baf3718beebad53a877cd045fa'),
 ('decode_pdata',511489884,'903a46124e3d461258f1801c','29e34f6ac016053349768791eacebce034ebff3b5ff5ed8c698f849e1cc7e89d'),
 ('decode_unwind',478209368,'01c10a00c1d40d0013320ff00de00bc00970086007500630','2e7e760772b4a6b66e01160b59cd2abb6fdc690650ceb30fbbc82b851c1b3989'),
)
DISK=((306619248,273,'97fe0b3df02f6948540b1ccd74a858de61bdefa641a8d31d85f7c5064bb9ada1'),
      (306589840,702,'139adbbb36f1a8052ba99409ab8799fd88a993ce30d096c1ecc6f567de0f40f2'))
verify_target=prior.verify_target
verify_previous_edges=prior.verify_previous_edges
verify_previous_continuations=prior.verify_previous_continuations
verify_previous_lookup=prior.verify_previous_lookup
verify_previous_lookup_body=prior.verify_previous_lookup_body
verify_previous_index_code=prior.verify_previous_index_code
verify_previous_hash_leaf=prior.verify_previous_hash_leaf
verify_previous_candidate=prior.verify_previous_candidate
verify_previous_candidate_tail=prior.verify_previous_candidate_tail
verify_previous_pak_lookup=prior.verify_previous_pak_lookup


def verify_helpers(blocks):
    hashes=('e756887b99923681698649ea1099e9a449ee4aede72a8bc916b875e23ecb2c8d',
            '8e590289dd89025ec69aa439166a87f9d31b39c976786d49614c80035ca52f03',
            'cb5f587aba56b38f44a4752cb1c583c48f47223455ac6239e88bd1002526a331')
    for (rva,size),sha in zip(prior.EXTRA_SPANS,hashes):
        if len(blocks[rva])!=size or hashlib.sha256(blocks[rva]).hexdigest()!=sha:
            raise ValueError('pak_decode_fresh_parent_helpers_changed')
    raw=blocks[0x1246ac20];off=0x1246ac8c-0x1246ac20
    if raw[off]!=0xe8 or 0x1246ac8c+5+struct.unpack_from('<i',raw,off+1)[0]!=0x12463a90:
        raise ValueError('pak_decode_exact_unpacker_call_changed')
    off=0x1246ac5e-0x1246ac20
    if raw[off:off+2]!=b'\x0f\x84' or 0x1246ac5e+6+struct.unpack_from('<i',raw,off+2)[0]!=0x1246ae63:
        raise ValueError('pak_decode_exact_null_output_return_changed')


def load_source(path):
    d=pinned(path,SOURCE_CAPTURE_SHA)
    if d['captured_bytes']!=5364 or d['native_pe_sha256']!=getters.SOURCE_PE:
        raise ValueError('pak_decode_source_chain_changed')
    verify_helpers({b['rva']:bytes.fromhex(b['bytes']) for b in d['pak_helper_code'].values()})
    return SOURCE_CAPTURE_SHA


def verify_original(path):
    result=prior.verify_original(path)
    with open(path,'rb') as stream:
        for name,off,raw,sha in METADATA:
            stream.seek(off);observed=stream.read(len(bytes.fromhex(raw)))
            if observed.hex()!=raw or hashlib.sha256(observed).hexdigest()!=sha:
                raise ValueError('pak_decode_original_metadata_changed_'+name)
        for off,size,sha in DISK:
            stream.seek(off)
            if hashlib.sha256(stream.read(size)).hexdigest()!=sha:
                raise ValueError('pak_decode_original_disk_changed')
    result['pak_decode']={'fixed_spans':EXTRA_SPANS,'metadata':METADATA}
    return result


def capture(read,query,base,module_size,*,source_digest,actual_created,expected_created):
    if source_digest!=SOURCE_CAPTURE_SHA:raise ValueError('pinned_pak_decode_source_required')
    report=prior.capture(read,query,base,module_size,source_digest=prior.SOURCE_CAPTURE_SHA,
                         actual_created=actual_created,expected_created=expected_created)
    verify_helpers({b['rva']:bytes.fromhex(b['bytes']) for b in report['pak_helper_code'].values()})
    blocks={}
    for name,(rva,size) in zip(('DecodeEntryReturn','CompactEntryDecode'),EXTRA_SPANS):
        raw=read(base+rva,size)
        if len(raw)!=size:raise ValueError('short_pak_decode_code_read')
        blocks[name]={'rva':rva,'size':size,'bytes':raw.hex(),'sha256':hashlib.sha256(raw).hexdigest(),
                      'pdata_segment_complete':True,'function_complete':name=='CompactEntryDecode'}
    report.update(source_capture_sha256=source_digest,captured_bytes=6339,pak_decode_code=blocks,
                  scope=report['scope']+'; compact decoder and null-output return code only; no entry data or native calls')
    return report


if __name__=='__main__':
    main(continuation=15)
