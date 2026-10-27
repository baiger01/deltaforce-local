"""Pure callback fixtures for current cached CDO/interface observations."""
import struct
import unittest
from unittest.mock import patch

from native_metadata_objects import ObjectRecord
import updated_template_metadata as template


PATHS = {
    'BP_DFMPlayerController_C': '/Game/BluePrints/Characters/BP_DFMPlayerController.BP_DFMPlayerController_C',
    'BP_DFMCharacter_C': '/Game/BluePrints/Characters/BP_DFMCharacter.BP_DFMCharacter_C',
    'BP_GameState_PVPVE_C': '/Game/BluePrints/GameModes/TestGame/BP_GameState_PVPVE.BP_GameState_PVPVE_C',
    'BP_SOLPlayerState_C': '/Game/BluePrints/GameModes/TestGame/BP_SOLPlayerState.BP_SOLPlayerState_C',
}


class Fixture:
    base = 0x140000000
    klass = 0x600010000
    cdo = 0x600020000
    parent = 0x600030000
    meta = 0x600040000
    outer = 0x600050000
    interface = 0x600060000
    entries = 0x600070000
    chain = 0x600080000

    def __init__(self, name='BP_DFMCharacter_C', *, adjustment=0xa80):
        self.data, self.nodes, self.calls = {}, {}, []
        self.after_read = None
        path = PATHS[name]
        self.add(self.meta, 'Class', '/Script/CoreUObject.Class', self.meta)
        self.add(self.outer, path.split('.')[0], path.split('.')[0], self.meta)
        self.add(self.parent, 'Object', '/Script/CoreUObject.Object', self.meta)
        self.add(self.klass, name, path, self.meta, self.outer)
        self.add(self.cdo, 'Default__'+name, path.split('.')[0]+'.Default__'+name,
                 self.klass, self.outer)
        self.add(self.interface, 'NetRepActorInterface', '/Script/GPGameplay.NetRepActorInterface', self.meta)
        for at in (self.klass,self.parent,self.meta,self.interface):
            self.write(at+0x48, struct.pack('<Q', self.parent if at==self.klass else 0))
            self.write(at+0x200, struct.pack('<Qii',0,0,0))
        self.write(self.klass+0x140, struct.pack('<Q',self.cdo))
        self.write(self.cdo+0x18, struct.pack('<I',0x31))
        self.table = self.base+0x15000000
        self.secondary_table = self.base+0x15001000
        self.write(self.cdo,struct.pack('<Q',self.table))
        self.write(self.table+0x3d8,struct.pack('<Q',self.base+0xd5f3d0))
        self.write(self.base+0x1d59de88,struct.pack('<Q',self.base+0xd968f0))
        self.write(self.base+0x1de5c888,struct.pack('<Q',self.interface))
        self.write(self.interface+0xd4,struct.pack('<I',(1<<14)|(1<<7)))
        self.write(self.interface+0x30,struct.pack('<Qi',self.chain,0))
        self.write(self.chain,struct.pack('<Q',self.interface+0x30))
        self.adjustment = adjustment
        self.write(self.cdo+adjustment,struct.pack('<Q',self.secondary_table))
        self.write(self.secondary_table+0x10,struct.pack('<Q',self.base+0x4e19500))
        if name=='BP_DFMCharacter_C':
            self.set_entries(self.klass,[(self.interface,adjustment,0)])
        self.backend = self.read

    def add(self, address, name, path, klass, outer=0):
        self.nodes[address] = dict(name=name,path=path,index=len(self.nodes)+1,serial=7)
        self.write(address+8,struct.pack('<Q',klass))
        self.write(address+0x10,struct.pack('<Q',outer))

    def set_entries(self, klass, values, *, address=None):
        at = self.entries if address is None else address
        self.write(klass+0x200,struct.pack('<Qii',at,len(values),len(values)))
        self.write(at,b''.join(struct.pack('<QiB3x',*v) for v in values))

    def write(self,address,data):
        self.data.update((address+i,b) for i,b in enumerate(data))

    def read(self,address,size):
        self.calls.append((address,size))
        raw=bytes(self.data[address+i] for i in range(size))
        if self.after_read:
            self.after_read(address,size)
        return raw

    def record(self,address):
        row=self.nodes[address]
        return ObjectRecord(row['index'],address,row['serial'])

    def name(self,address):
        return self.nodes[address]['name']

    def path(self,address):
        return self.nodes[address]['path']


class TemplateMetadataTests(unittest.TestCase):
    def observe(self,fixture):
        self.assertIsNotNone(template,'The callback-only template observer is not implemented')
        return template.observe_template_metadata(fixture,fixture.klass)

    def test_cached_pawn_observes_actual_adjustment_and_targets_without_approval(self):
        f=Fixture(adjustment=0xa80)
        row=self.observe(f)
        self.assertEqual(row['cdo']['status'],'observed')
        self.assertEqual(row['cdo']['name'],'Default__BP_DFMCharacter_C')
        self.assertEqual(row['cdo']['actor_channel_open_hook']['target_rva'],0xd5f3d0)
        self.assertEqual(row['net_rep_actor_interface']['pointer_adjustment'],0xa80)
        self.assertEqual(row['net_rep_actor_interface']['method']['target_rva'],0x4e19500)
        self.assertFalse(row['net_rep_actor_interface']['method']['target_approved'])
        self.assertTrue(row['identities_and_fields_rechecked'])
        self.assertFalse(row['native_function_called'])
        self.assertNotIn('address',row['cdo'])
        self.assertNotIn((f.base+0x4e19500,8),f.calls)
        self.assertEqual({at for at,size in f.calls if f.cdo<=at<f.cdo+0x10000},
                         {f.cdo,f.cdo+8,f.cdo+0x10,f.cdo+0x18,f.cdo+0xa80})

    def test_only_four_exact_current_class_paths_are_supported(self):
        for name in PATHS:
            with self.subTest(name=name):
                row=self.observe(Fixture(name))
                self.assertEqual(row['class']['path'],PATHS[name])
        f=Fixture()
        f.nodes[f.klass]['path']='/Game/Other.BP_DFMCharacter_C'
        with self.assertRaisesRegex(ValueError,'exact|supported'):
            self.observe(f)

    def test_null_cached_cdo_is_explicitly_unavailable_without_default_scan(self):
        f=Fixture()
        f.write(f.klass+0x140,bytes(8))
        row=self.observe(f)
        self.assertEqual(row['cdo']['status'],'not_available')
        self.assertEqual(row['net_rep_actor_interface']['status'],'not_available')
        self.assertNotIn((f.cdo,8),f.calls)

    def test_null_existing_interface_singleton_does_not_invoke_getter(self):
        f=Fixture()
        f.write(f.base+0x1de5c888,bytes(8))
        row=self.observe(f)
        self.assertEqual(row['cdo']['status'],'observed')
        self.assertEqual(row['net_rep_actor_interface']['status'],'not_available')
        self.assertNotIn((f.cdo+f.adjustment,8),f.calls)

    def test_wrong_cdo_class_name_outer_and_wrong_metaclass_fail_closed(self):
        mutations=[lambda f:f.write(f.cdo+8,struct.pack('<Q',f.parent)),
                   lambda f:f.nodes[f.cdo].update(name='Default__Other'),
                   lambda f:f.write(f.cdo+0x10,struct.pack('<Q',f.parent)),
                   lambda f:f.nodes[f.meta].update(name='Function',path='/Script/CoreUObject.Function')]
        for change in mutations:
            with self.subTest(change=change):
                f=Fixture();change(f)
                with self.assertRaises(ValueError):self.observe(f)

    def test_array_count_capacity_null_data_and_total_bounds_fail_closed(self):
        for header in [(0,1,1),(0,-1,0),(0,2,1),(0x600070000,0,129)]:
            with self.subTest(header=header):
                fixture=Fixture();fixture.write(fixture.klass+0x200,struct.pack('<Qii',*header))
                with self.assertRaisesRegex(ValueError,'array|bound|capacity'):self.observe(fixture)
        fixture=Fixture()
        fixture.set_entries(fixture.klass,[(fixture.interface,fixture.adjustment,1)]*128)
        fixture.set_entries(fixture.parent,[(fixture.interface,fixture.adjustment,1)],address=fixture.entries+0x2000)
        with self.assertRaisesRegex(ValueError,'total|bound'):self.observe(fixture)

    def test_script_interface_is_recorded_without_native_pointer_dereference(self):
        f=Fixture();f.set_entries(f.klass,[(f.interface,f.adjustment,1)])
        row=self.observe(f)
        self.assertEqual(row['ancestors'][0]['interfaces'][0]['implemented_by_script_byte'],1)
        self.assertEqual(row['net_rep_actor_interface']['status'],'not_available')
        self.assertNotIn((f.cdo+f.adjustment,8),f.calls)

    def test_multiple_native_matches_are_ambiguous(self):
        f=Fixture();f.set_entries(f.parent,[(f.interface,f.adjustment,0)],address=f.entries+0x2000)
        with self.assertRaisesRegex(ValueError,'ambiguous'):self.observe(f)

    def test_signed_native_adjustment_is_preserved(self):
        f=Fixture(adjustment=-16)
        self.assertEqual(self.observe(f)['net_rep_actor_interface']['pointer_adjustment'],-16)

    def test_accessor_and_method_pointer_boundaries_fail_closed(self):
        for at,value in [('accessor',0),('table',0),('method',0x140000000+536408064),('secondary',0)]:
            with self.subTest(pointer=at):
                f=Fixture()
                address={'accessor':f.base+0x1d59de88,'table':f.cdo,
                         'method':f.table+0x3d8,'secondary':f.cdo+f.adjustment}[at]
                f.write(address,struct.pack('<Q',value))
                with self.assertRaises(ValueError):self.observe(f)

    def test_different_inside_image_method_is_observed_and_unapproved(self):
        f=Fixture();f.write(f.table+0x3d8,struct.pack('<Q',f.base+0x123456))
        hook=self.observe(f)['cdo']['actor_channel_open_hook']
        self.assertEqual(hook['target_rva'],0x123456)
        self.assertFalse(hook['target_approved'])

    def test_class_chain_and_interface_chain_cycles_or_depth_fail_closed(self):
        f=Fixture();f.write(f.parent+0x48,struct.pack('<Q',f.klass))
        with self.assertRaisesRegex(ValueError,'cycle'):self.observe(f)
        f=Fixture();f.write(f.interface+0x38,struct.pack('<i',64))
        with self.assertRaisesRegex(ValueError,'depth|bound'):self.observe(f)

    def test_changes_after_read_callbacks_are_not_published(self):
        for kind in ('serial','path','cdo_pointer','vtable_target','entries'):
            with self.subTest(kind=kind):
                f=Fixture();changed=False
                def mutate(at,size):
                    nonlocal changed
                    if changed or at!=f.secondary_table+0x10:return
                    changed=True
                    if kind=='serial':f.nodes[f.klass]['serial']+=1
                    elif kind=='path':f.nodes[f.cdo]['path']+='Changed'
                    elif kind=='cdo_pointer':f.write(f.klass+0x140,bytes(8))
                    elif kind=='vtable_target':f.write(f.table+0x3d8,struct.pack('<Q',f.base+0x123456))
                    else:f.write(f.entries+8,struct.pack('<i',123))
                f.after_read=mutate
                with self.assertRaisesRegex(ValueError,'changed'):self.observe(f)

    def test_proof_pin_failure_occurs_before_backend_access(self):
        f=Fixture()
        self.assertIsNotNone(template,'The callback-only template observer is not implemented')
        with patch.object(template,'PROOF_SHA256','0'*64):
            with self.assertRaisesRegex(ValueError,'proof'):self.observe(f)
        self.assertEqual(f.calls,[])

    def test_repeated_capture_is_stable_and_source_pins_are_scoped(self):
        f=Fixture();first=self.observe(f);second=self.observe(f)
        self.assertEqual(first['cdo'],second['cdo'])
        self.assertEqual(set(first['source_pins']),{
            'work/evidence/updated-template-metadata-79fb7b10.json','work/updated_template_metadata.py'})

    def test_native_inheritance_match_uses_requested_depth_and_pointer_identity(self):
        f=Fixture()
        derived,chain=f.interface+0x20000,f.chain+0x20000
        f.add(derived,'DerivedInterface','/Script/Fixture.DerivedInterface',f.meta)
        f.write(derived+0x30,struct.pack('<Qi',chain,2))
        f.write(f.interface+0x38,struct.pack('<i',1))
        f.write(chain,struct.pack('<QQQ',0,f.interface+0x30,0))
        f.set_entries(f.klass,[(derived,f.adjustment,0)])
        self.assertEqual(self.observe(f)['net_rep_actor_interface']['path'],'/Script/Fixture.DerivedInterface')
        f.write(chain+8,struct.pack('<Q',derived+0x30))
        self.assertEqual(self.observe(f)['net_rep_actor_interface']['status'],'not_available')

    def test_exact64_class_ancestors_pass_and65_are_rejected(self):
        for count in (64,65):
            with self.subTest(count=count):
                f=Fixture();previous=f.klass
                for index in range(count-2):
                    at=0x610000000+index*0x1000
                    f.add(at,'Ancestor'+str(index),'/Script/Fixture.Ancestor'+str(index),f.meta)
                    f.write(at+0x200,struct.pack('<Qii',0,0,0))
                    f.write(previous+0x48,struct.pack('<Q',at));previous=at
                f.write(previous+0x48,struct.pack('<Q',f.parent))
                if count==64:self.assertEqual(len(self.observe(f)['ancestors']),64)
                else:
                    with self.assertRaisesRegex(ValueError,'bound'):self.observe(f)

    def test_truncated_backend_and_direct_read_budget_fail_closed(self):
        f=Fixture();original=f.backend
        f.backend=lambda at,size:original(at,size)[:-1]
        with self.assertRaisesRegex(ValueError,'Incomplete'):self.observe(f)
        f=Fixture()
        with patch.object(template,'MAX_DIRECT_READ_CALLS',4):
            with self.assertRaisesRegex(ValueError,'budget'):self.observe(f)

    def test_interface_chain_cannot_read_unqualified_image_globals(self):
        f=Fixture();f.write(f.interface+0x30,struct.pack('<Q',f.base+0x1000))
        with self.assertRaisesRegex(ValueError,'global'):self.observe(f)
        self.assertNotIn((f.base+0x1000,8),f.calls)
        f=Fixture();f.write(f.interface+0x30,struct.pack('<Q',f.base-4))
        with self.assertRaisesRegex(ValueError,'global'):self.observe(f)
        self.assertNotIn((f.base-4,8),f.calls)

    def test_supplied_backend_replacement_during_callback_is_rejected(self):
        f=Fixture()
        def replace_backend(at,size):
            if at==f.secondary_table+0x10:
                f.backend=lambda address,count:f.read(address,count)
        f.after_read=replace_backend
        with self.assertRaisesRegex(ValueError,'changed'):self.observe(f)

    def test_zero_registry_serials_are_observed_without_weak_key_allocation(self):
        f=Fixture();f.nodes[f.klass]['serial']=f.nodes[f.cdo]['serial']=0
        row=self.observe(f)
        self.assertEqual(row['class']['serial'],0)
        self.assertEqual(row['cdo']['serial'],0)


if __name__=='__main__':
    unittest.main()
