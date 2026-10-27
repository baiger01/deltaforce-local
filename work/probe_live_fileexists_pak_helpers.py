"""Read three exact direct callees of the original per-package file lookup."""

import hashlib
import struct

import probe_live_fileexists_pak_lookup as prior
from probe_live_fileexists_directory_state import pinned
from probe_live_fileexists_target import main


getters = prior.getters
SOURCE_CAPTURE = getters.ROOT / 'work/evidence/live-package-fileexists-pak-lookup-bundle-20261005-private.json'
SOURCE_CAPTURE_SHA = '6370695f73ca0e99daee0b72308cf6408a9752f73c14a37edcfe660f2ff8e467'
EXTRA_SPANS = ((0xdb8360,194),(0x10b2b9b0,662),(0x1246ac20,118))
METADATA = (
    ('map_pdata',499278696,'6083db002284db00b0cfdc1b','b950474ad7d41766ca8b6cf55079b559b44288bb5200e0b85cb48073c910d072'),
    ('map_unwind',467452848,'011a0a001a7409001a6408001a5407001a3406001a3216e0','780cbbac1b8df5d91e9d421abc3303b30637edabdc69b366a8c6ec4c57dbb372'),
    ('normalize_pdata',510290616,'b0b9b21046bcb2101086e71b','d936530217a1d2794e4f88ec41fbbdfaeecbc8e71d5213fd4ad75c850f7c6128'),
    ('normalize_unwind',468154896,'011c0a001ce413001c7412001c6411001c3410001cd21550','f0b82a38dddd16e8f921dcbaab0f0fcdaabacd73c349fc894e63a6271b3e6eac'),
    ('decoder_pdata',511491312,'20ac461296ac46122cef801c','f4c3403f1b54b18c40536bb81ebaa0fe72e08ea0acade350a393b779f157ae73'),
    ('decoder_unwind',478208812,'192107001301120007f005700460033002500000ec929714','f9a38cacf51ade9435efd7c5e5c6c0a03de4d9e0a28056dfa9990d63a17bc096'),
)
DISK = ((14383456,194,'73c6f94ccf29eee20872d4d00f678f38d19835856f0795c9db64a362f93a6261'),
        (280145840,662,'9a436e90e15bfbf6d151290d2e11192306613cbc59f55a5975b20b16538719ee'),
        (306618912,118,'108e4d8d0e2dea3389305ba7bc3324547e84669d06d9eb3198c84516b416f7d0'))
verify_target = prior.verify_target
verify_previous_edges = prior.verify_previous_edges
verify_previous_continuations = prior.verify_previous_continuations
verify_previous_lookup = prior.verify_previous_lookup
verify_previous_lookup_body = prior.verify_previous_lookup_body
verify_previous_index_code = prior.verify_previous_index_code
verify_previous_hash_leaf = prior.verify_previous_hash_leaf
verify_previous_candidate = prior.verify_previous_candidate
verify_previous_candidate_tail = prior.verify_previous_candidate_tail


def verify_previous_pak_lookup(blocks):
    hashes = ('5bf7054b1754a7c7ff3b813f1d91a57b91163314638ba5cae7d8e46ee3c433f5',
              '71980d01b94924dfb7ee8775525ca3db46a5fa6f2755342b50bc7f8eaa950f11')
    for (rva,size),sha in zip(prior.EXTRA_SPANS,hashes):
        if len(blocks[rva])!=size or hashlib.sha256(blocks[rva]).hexdigest()!=sha:
            raise ValueError('pak_helpers_fresh_parent_code_changed')
    body=blocks[0x12467fe8]
    for site,target in ((0x1246805a,0xdb8360),(0x124680ed,0x1246ac20)):
        off=site-0x12467fe8
        if body[off]!=0xe8 or site+5+struct.unpack_from('<i',body,off+1)[0]!=target:
            raise ValueError('pak_helpers_exact_direct_callee_changed')
    entry=blocks[0x12467eb0]
    off=0x12467fc4-0x12467eb0
    if entry[off]!=0xe8 or 0x12467fc4+5+struct.unpack_from('<i',entry,off+1)[0]!=0x10b2b9b0:
        raise ValueError('pak_helpers_exact_normalizer_call_changed')


def load_source(path):
    d=pinned(path,SOURCE_CAPTURE_SHA)
    if d['captured_bytes']!=4390 or d['native_pe_sha256']!=getters.SOURCE_PE:
        raise ValueError('pak_helpers_source_chain_changed')
    verify_previous_pak_lookup({b['rva']:bytes.fromhex(b['bytes']) for b in d['pak_lookup_code'].values()})
    return SOURCE_CAPTURE_SHA


def verify_original(path):
    result=prior.verify_original(path)
    with open(path,'rb') as stream:
        for name,off,raw,sha in METADATA:
            stream.seek(off);observed=stream.read(len(bytes.fromhex(raw)))
            if observed.hex()!=raw or hashlib.sha256(observed).hexdigest()!=sha:
                raise ValueError('pak_helpers_original_metadata_changed_'+name)
        for off,size,sha in DISK:
            stream.seek(off)
            if hashlib.sha256(stream.read(size)).hexdigest()!=sha:
                raise ValueError('pak_helpers_original_disk_changed')
    result['pak_helpers']={'fixed_spans':EXTRA_SPANS,'metadata':METADATA}
    return result


def capture(read,query,base,module_size,*,source_digest,actual_created,expected_created):
    getters.local.verify_creation(actual_created,expected_created)
    if source_digest!=SOURCE_CAPTURE_SHA:
        raise ValueError('pinned_pak_helpers_source_required')
    report=prior.capture(read,query,base,module_size,source_digest=prior.SOURCE_CAPTURE_SHA,
                         actual_created=actual_created,expected_created=expected_created)
    verify_previous_pak_lookup({b['rva']:bytes.fromhex(b['bytes']) for b in report['pak_lookup_code'].values()})
    blocks={}
    for name,(rva,size) in zip(('FilenameMapLookup','NormalizeFilename','DecodeEntryPrefix'),EXTRA_SPANS):
        raw=read(base+rva,size)
        if len(raw)!=size:raise ValueError('short_pak_helper_code_read')
        blocks[name]={'rva':rva,'size':size,'bytes':raw.hex(),'sha256':hashlib.sha256(raw).hexdigest(),
                      'pdata_segment_complete':True,'function_complete':name!='DecodeEntryPrefix'}
    report.update(source_capture_sha256=source_digest,captured_bytes=5364,pak_helper_code=blocks,
                  scope=report['scope']+'; three exact direct helper code spans only; no new heap fields or native calls')
    return report


if __name__=='__main__':
    main(continuation=13)
