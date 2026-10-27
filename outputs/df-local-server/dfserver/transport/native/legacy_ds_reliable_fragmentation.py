"""Bounded outgoing ordinary Actor-content fragments; no export splitting.

Native SendBunch 1286ca40 / partial receive 12867e10 are fully compared in
work/research_updated_transport_79fb7b10.json (d127c9b551192ba1a126f3b5f5e2c90f9a9a6a0e6d4ff806b6d037941fb73e92).
Actor hardcoded name 102 is separately qualified by the updated transport-profile
report. The 64-bit outer routing reserve is a conservative local send budget,
not an observation of a native connection's overhead field.
"""
from dataclasses import replace

from dfserver.transport.native.legacy_ds_bit_archive import MAX_BITS
from dfserver.transport.native.legacy_ds_wire_codec import (
    ChannelName, WireBunch, WirePacket, encode_observed_application)

NATIVE_RESERVED_BUNCH_BITS = 562
LOCAL_ROUTING_RESERVE_BITS = 64
MAX_CONTENT_FRAGMENTS = 32
MAX_ASSEMBLED_CONTENT_BITS = MAX_BITS


def packet_fits(bunch, max_packet_bytes):
    """The existing one-history-word sender profile, preserved for small data."""
    encode_observed_application(WirePacket(16383,16383,(0xffffffff,),False,0,None,
        (bunch,),0),max_packet_bytes=max_packet_bytes,received_by_server=False)


def fragment_content_bunch(bunch, *, max_packet_bytes):
    if (type(max_packet_bytes) is not int or not 1<=max_packet_bytes<=1492 or
            type(bunch) is not WireBunch or bunch.reliable is not True or
            any(getattr(bunch,name) is not False for name in ('open','close','flag4',
                'connection_flag','package_exports','must_be_mapped','partial','partial_initial','partial_final')) or
            bunch.channel_name not in (ChannelName(hardcoded_index=102),ChannelName(text='Actor')) or
            type(bunch.channel_index) is not int or not 1<=bunch.channel_index<=0xffffffff or
            type(bunch.channel_sequence) is not int or not 0<=bunch.channel_sequence<1024 or
            type(bunch.payload_bits) is not int or not 1<=bunch.payload_bits<=MAX_ASSEMBLED_CONTENT_BITS or
            type(bunch.payload) is not bytes or len(bunch.payload)!=(bunch.payload_bits+7)//8 or
            bunch.payload_bits%8 and bunch.payload[-1]>>(bunch.payload_bits%8)):
        raise ValueError('Only bounded ordinary reliable Actor content can be fragmented')
    try:
        packet_fits(bunch,max_packet_bytes)
        return (bunch,)
    except ValueError:
        pass
    piece_bits=((max_packet_bytes*8-LOCAL_ROUTING_RESERVE_BITS-NATIVE_RESERVED_BUNCH_BITS)//8)*8
    if piece_bits<8:
        raise ValueError('Packet budget cannot hold a byte-aligned ordinary fragment')
    count=(bunch.payload_bits+piece_bits-1)//piece_bits
    if count>MAX_CONTENT_FRAGMENTS:
        raise ValueError('Logical content exceeds the local fragment-count bound')
    pieces=[]
    for index in range(count):
        start=index*piece_bits
        bits=min(piece_bits,bunch.payload_bits-start)
        piece=replace(bunch,payload=bunch.payload[start//8:(start+bits+7)//8],payload_bits=bits,
            partial=True,partial_initial=index==0,partial_final=index==count-1,
            channel_sequence=(bunch.channel_sequence+index)&1023,
            header_start_bit=None,payload_start_bit=None)
        # Check the largest supported header too; the normal sender uses one word.
        encoded=encode_observed_application(WirePacket(16383,16383,(0xffffffff,)*8,
            True,255,255,(piece,),0),max_packet_bytes=max_packet_bytes,received_by_server=False)
        if len(encoded)*8+LOCAL_ROUTING_RESERVE_BITS>max_packet_bytes*8:
            raise ValueError('Fragment plus local routing reserve exceeds packet budget')
        pieces.append(piece)
    return tuple(pieces)
