"""Logical content stages over individually receipted ordinary wire fragments."""
from dataclasses import replace
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from dfserver.replication.legacy_ds_actor_content import (
    ActorContentBlock, ResolvedStableSubobjectProfile, read_actor_content_blocks)
from dfserver.replication.legacy_ds_default_subobject import DefaultSubobjectUpdate
from dfserver.transport.native.legacy_ds_bit_archive import BitReader
from dfserver.transport.native.legacy_ds_decoded_bunch import (
    DecodedBunch, DecodedBunchReceiver, RELIABLE, PARTIAL, INITIAL, FINAL)
from dfserver.transport.native.legacy_ds_handshake_probe import PendingChallenge
from dfserver.transport.native.legacy_ds_wire_codec import encode_observed_application, decode_observed_application
from tests import test_legacy_ds_actor_delivery as delivery_fixture
from tests.test_legacy_ds_actor_delivery import actor_fields, decode
from tests.test_legacy_ds_control_probe import COOKIE, PEER
from tests.test_legacy_ds_pc_startup_rpc import PROFILE as STARTUP, rpc


def content(bits):
    raw=bytearray((i*37+11)&255 for i in range((bits+7)//8))
    if bits%8:raw[-1]&=(1<<(bits%8))-1
    return ActorContentBlock(True,bytes(raw),bits)


def assemble(packets,seed):
    receiver=DecodedBunchReceiver(in_reliable=seed,opened=True,max_assembly_bytes=8192)
    ready=[]
    for packet in packets:
        bunch=packet.bunches[0]
        absolute=receiver.in_reliable+((bunch.channel_sequence-receiver.in_reliable+512)%1024)-512
        flags=sum(mask for key,mask in (('reliable',RELIABLE),('partial',PARTIAL),
            ('partial_initial',INITIAL),('partial_final',FINAL)) if getattr(bunch,key))
        result=receiver.receive(DecodedBunch(absolute,packet.sequence,flags,bunch.payload,bunch.payload_bits))
        if result.error:raise AssertionError(result.error)
        ready.extend(result.ready)
    return ready


class ContentFragmentationTests(unittest.TestCase):
    def setUp(self):
        self.fixture=delivery_fixture.ActorDeliveryTests();self.fixture.setUp()
        self.connection=self.fixture.connection
        self.ticket=self.fixture.ticket
        self.generation=None

    def state(self):
        return self.connection.control_peers[PEER]

    def sent(self,replies,now):
        if self.generation is not None:
            for peer,event,body in replies:
                self.assertTrue(self.connection._note_actual_application_send(peer,body,
                    generation=self.generation,ticket=self.ticket,
                    transport=self.connection.peers[PEER],sent_at=now))
        return [decode_observed_application(body,max_packet_bytes=self.connection.max_packet_bytes,
            received_by_server=False) for peer,event,body in replies]

    def ack(self,ack,history=(1,),*,now=.2,bunches=()):
        transport=self.connection.peers[PEER]
        packet=replace(self.fixture.template,sequence=(transport.in_sequence+1)&16383,
            acknowledged_sequence=ack,history=history,bunches=bunches)
        raw=b'opaque!!'+encode_observed_application(packet,max_packet_bytes=self.connection.max_packet_bytes,
            received_by_server=True)
        result=self.connection.handle(raw,PEER,now,verified_generation=self.generation)
        return result,raw

    def queue(self,plans,*,channels=((2,4),),seed=1022):
        self.state().initial_actor_sequence=seed
        try:
            self.connection.queue_actor_opens(PEER,tuple(actor_fields(channel_index=c,actor_guid=g)
                for c,g in channels),post_open_actor_contents=plans)
        except ValueError as error:
            self.fail('The production content planner still rejects a packet-sized fragment group: '+str(error))
        opens=self.sent(self.connection.poll(.1),.1)
        self.ack(opens[-1].sequence,((1<<len(opens))-1,),now=.15)
        return opens

    def test_exact8240_and16670_bit_bodies_reassemble_and_preserve_sequence_wrap(self):
        for bits in (8240,16670):
            with self.subTest(bits=bits):
                self.setUp();block=content(bits)
                self.queue((dict(channel_index=2,actor_guid=4,content_blocks=(block,)),))
                packets=self.sent(self.connection.poll(.3),.3)
                self.assertGreater(len(packets),1)
                self.assertEqual([p.bunches[0].channel_sequence for p in packets],
                    [(1023+i)&1023 for i in range(len(packets))])
                self.assertTrue(all(not p.bunches[0].package_exports for p in packets))
                bodies=assemble(packets,1022)
                self.assertEqual(len(bodies),1)
                self.assertEqual(read_actor_content_blocks(BitReader(bodies[0].payload,
                    bit_count=bodies[0].payload_bits)),(block,))

    def test_lost_middle_and_reordered_duplicate_acks_do_not_release_logical_stages(self):
        first,tail=content(16670),content(3)
        self.queue((dict(channel_index=2,actor_guid=4,content_blocks=(first,),continuations=((tail,),)),
            dict(channel_index=3,actor_guid=6,content_blocks=(tail,),after_content_stages=((2,0),))),
            channels=((2,4),(3,6)))
        packets=self.sent(self.connection.poll(.3),.3)
        self.assertEqual(len(packets),3)
        # Native reliable receive queues the early final piece and ignores its
        # duplicate while waiting for the missing middle reliable sequence.
        assembled=assemble((packets[0],packets[2],packets[2],packets[1]),1022)
        self.assertEqual(len(assembled),1)
        self.assertEqual(read_actor_content_blocks(BitReader(assembled[0].payload,
            bit_count=assembled[0].payload_bits)),(first,))
        self.ack(packets[-1].sequence,(5,),now=.35)
        self.assertFalse(self.state().actor_contents[2].delivered)
        self.assertEqual(self.connection.poll(.4),[])
        retry=self.sent(self.connection.poll(.9),.9)
        self.assertEqual(len(retry),1)
        self.assertEqual(retry[0].bunches[0],packets[1].bunches[0])
        _,raw=self.ack(retry[0].sequence,now=.95)
        before=self.connection.summary()['post_open_actor_content_delivery_acks']
        self.assertEqual(self.connection.handle(raw,PEER,1)[0],'application_sequence_rejected')
        self.assertEqual(self.connection.summary()['post_open_actor_content_delivery_acks'],before)
        released=self.sent(self.connection.poll(1.1),1.1)
        self.assertEqual({p.bunches[0].channel_index for p in released},{2,3})
        own=next(p for p in released if p.bunches[0].channel_index==2)
        self.assertEqual(own.bunches[0].channel_sequence,(packets[-1].bunches[0].channel_sequence+1)&1023)

    def test_large_component_has_unfragmented_export_ack_barrier_then_body_fragments(self):
        block=content(16670)
        try:update=DefaultSubobjectUpdate(4,22,'InventoryManager','a'*64,block.payload,block.payload_bit_count)
        except ValueError as error:self.fail('Large component values are still limited to one packet: '+str(error))
        self.queue((dict(channel_index=2,actor_guid=4,content_blocks=(content(0),),default_subobject=update),))
        export=self.sent(self.connection.poll(.3),.3)
        self.assertEqual(len(export),1)
        self.assertTrue(export[0].bunches[0].package_exports)
        self.assertFalse(export[0].bunches[0].partial)
        self.assertFalse(self.state().actor_contents[2].delivered)
        self.assertEqual(self.connection.poll(.4),[])
        self.ack(export[0].sequence,now=.45)
        body=self.sent(self.connection.poll(.5),.5)
        self.assertEqual(len(body),3)
        self.assertTrue(all(not p.bunches[0].package_exports for p in body))
        assembled=assemble(body,export[0].bunches[0].channel_sequence)
        blocks=read_actor_content_blocks(BitReader(assembled[0].payload,bit_count=assembled[0].payload_bits),
            allow_resolved_stable_subobjects=True,
            resolved_stable_subobject_profile=ResolvedStableSubobjectProfile(4,(4,),(22,),
                'normal_client',True,True,True))
        self.assertEqual((blocks[-1].payload,blocks[-1].payload_bit_count),(block.payload,16670))
        self.ack(body[-1].sequence,(7,),now=.55)
        self.assertTrue(self.state().actor_contents[2].delivered)
        self.assertEqual(self.connection.summary()['post_open_actor_content_delivery_acks'],1)

    def test_local_stage_needs_actual_full_send_receipts_for_every_fragment(self):
        self.generation=PendingChallenge(1.,COOKIE,0.,echoed=True,verified_at=0.,last_valid_activity_at=0.)
        self.connection._local_stage_generation_for_peer=lambda peer,state,transport:self.generation
        self.queue((dict(channel_index=2,actor_guid=4,content_blocks=(content(16670),)),))
        prepared=self.connection.poll(.3)
        packets=[decode(body) for peer,event,body in prepared]
        self.ack(packets[-1].sequence,(7,),now=.35)
        self.assertFalse(self.state().actor_contents[2].delivered)
        self.sent(prepared,.4)
        self.ack(packets[-1].sequence,(5,),now=.45)
        self.assertFalse(self.state().actor_contents[2].delivered)
        self.ack(packets[-1].sequence,(7,),now=.5)
        self.assertTrue(self.state().actor_contents[2].delivered)
        item=self.state().actor_contents[2]
        self.assertTrue(self.connection._content_stage_receipted(PEER,self.state(),
            self.connection.peers[PEER],item))

    def test_ready_rpc_uses_last_reserved_sequence_and_waits_for_all_fragments(self):
        self.queue((dict(channel_index=2,actor_guid=4,content_blocks=(content(16670),)),))
        self.connection.set_pc_startup_profile(PEER,2,4,STARTUP)
        fragments=self.sent(self.connection.poll(.3),.3)
        seed=self.state().hello_sequence
        self.ack(fragments[-1].sequence,(0,),now=.35,
            bunches=(rpc(seed,79),rpc((seed+1)&1023,141,False)))
        self.assertIsNone(self.state().pc_ready_ack)
        self.assertFalse(any('pc_ready_ack' in event for peer,event,body in self.connection.poll(.4)))
        self.ack(fragments[-1].sequence,(7,),now=.45)
        self.ack(fragments[-1].sequence,(0,),now=.46,
            bunches=(rpc(seed,79),rpc((seed+1)&1023,141,False)))
        self.assertIsNotNone(self.state().pc_ready_ack)
        self.assertEqual(self.state().pc_ready_ack.bunch.channel_sequence,
                         (fragments[-1].bunches[0].channel_sequence+1)&1023)
        self.assertEqual(sum('pc_ready_ack' in event for peer,event,body in self.connection.poll(.5)),1)

    def test_actual_two_gun_inventory_builder_and_recipe_bodies_reach_fragment_delivery(self):
        root=Path(__file__).resolve().parents[3]
        snapshot_path=root/'work/evidence/map-system-audit-20261018/carried-snapshot-offline.json'
        if not snapshot_path.is_file():self.skipTest('Historical private structured two-gun fixture unavailable')
        sys.path.insert(0,str(root/'work'))
        import portable_map_inventory as adapter
        import portable_map_inventory_content as inventory
        import modular_weapon_recipe_codec as recipe
        import portable_modular_weapon_recipe as recipe_plan
        from dfserver.replication.legacy_ds_inventory_gun import GunInventoryItem
        snapshot=json.loads(snapshot_path.read_bytes())
        projection=adapter.build(snapshot,value_fields=(0,)*7,owner_player_id=123)
        guns=tuple(e for e in projection.items if type(e.item) is GunInventoryItem)
        self.assertEqual(len(guns),2)
        # The normal grouping policy stays one gun per stage. This fixture puts
        # both original gun records in one valid delta to exercise a large body.
        with patch.object(inventory,'_item_groups',return_value=(guns,)):
            try:groups=inventory.build(snapshot,pawn_guid=4,component_guid=22,
                value_fields=(0,)*7,owner_player_id=123).groups
            except ValueError as error:self.fail('Inventory builder still enforces one-packet body size: '+str(error))
        update=groups[1][0]
        self.assertGreater(update.payload_bit_count,8192)
        self.connection.max_packet_bytes=512
        self.queue((dict(channel_index=2,actor_guid=4,content_blocks=(content(0),),default_subobject=update),))
        export=self.sent(self.connection.poll(.3),.3)
        self.ack(export[0].sequence,now=.35)
        packets=self.sent(self.connection.poll(.4),.4)
        self.assertGreater(len(packets),1)
        bodies=assemble(packets,export[0].bunches[0].channel_sequence)
        blocks=read_actor_content_blocks(BitReader(bodies[0].payload,bit_count=bodies[0].payload_bits),
            allow_resolved_stable_subobjects=True,resolved_stable_subobject_profile=
                ResolvedStableSubobjectProfile(4,(4,),(22,),'normal_client',True,True,True))
        self.assertEqual(blocks[-1].payload,update.payload)
        self.assertEqual(blocks[-1].payload_bit_count,update.payload_bit_count)
        for gun in guns:
            block=recipe.encode(recipe.project(gun.item.description))
            try:parts=recipe_plan._packet_preflight(block,512)
            except ValueError as error:self.fail('Recipe builder still requires one packet: '+str(error))
            self.assertGreater(len(parts),1)
            parsed=[decode_observed_application(part,max_packet_bytes=512,received_by_server=False) for part in parts]
            assembled=assemble(parsed,1022)
            self.assertEqual(read_actor_content_blocks(BitReader(assembled[0].payload,
                bit_count=assembled[0].payload_bits)),(block,))

    def test_fragment_policy_is_sealed_and_clones_own_their_piece_state(self):
        self.queue((dict(channel_index=2,actor_guid=4,content_blocks=(content(16670),)),))
        original=self.state()
        cloned=self.connection._clone(original)
        cloned.actor_contents[2].fragments[0].delivered=True
        self.assertFalse(original.actor_contents[2].fragments[0].delivered)
        original.actor_contents[2].fragments[0].actor_guid=999
        self.assertEqual(self.connection.poll(.3),[])

    def test_oversized_exports_and_total_wire_budget_fail_before_stage_publication(self):
        updates=tuple(DefaultSubobjectUpdate(4,22+2*i,'Name'+str(i)+'x'*250,'a'*64,b'\x01',1)
                      for i in range(8))
        plans=(dict(channel_index=2,actor_guid=4,content_blocks=(content(0),),default_subobjects=updates),)
        before=self.state()
        with self.assertRaises(ValueError):
            self.connection.queue_actor_opens(PEER,(actor_fields(channel_index=2,actor_guid=4),),
                post_open_actor_contents=plans)
        self.assertIs(self.state(),before)
        large=content(16670)
        plans=tuple(dict(channel_index=channel,actor_guid=guid,content_blocks=(large,),
            continuations=tuple((large,) for _ in range(tails)))
            for channel,guid,tails in ((2,4,63),(3,6,31)))
        with self.assertRaisesRegex(ValueError,'wire-fragment'):
            self.connection.queue_actor_opens(PEER,
                tuple(actor_fields(channel_index=c,actor_guid=g) for c,g in ((2,4),(3,6))),
                post_open_actor_contents=plans)
        self.assertIs(self.state(),before)
        self.assertEqual(self.state().actor_contents,{})


if __name__=='__main__':unittest.main()
