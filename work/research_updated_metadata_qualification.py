"""Seal the static and synthetic metadata research into an auditable summary."""
import json
from pathlib import Path

from research_updated_metadata_roots import ROOT, PINS, sha


def main():
    reports, report_pins = {}, []
    for name in ['static', 'emulation']:
        path = ROOT/f'work/evidence/updated-metadata-roots-79fb7b10-{name}.json'
        raw = path.read_bytes()
        reports[name] = json.loads(raw)
        report_pins.append(dict(path=path.relative_to(ROOT).as_posix(), sha256=sha(raw)))
    static, emulation = reports['static'], reports['emulation']
    script = ROOT/'work/research_updated_metadata_roots.py'
    if sha(script.read_bytes()) != static['source_code_sha256']:
        raise ValueError('Static comparison source changed after evidence was generated')
    script = ROOT/'work/research_updated_metadata_emulation.py'
    if sha(script.read_bytes()) != emulation['script_sha256']:
        raise ValueError('Emulation source changed after evidence was generated')
    for name, pin in emulation['pure_helper_source_pins'].items():
        if sha((ROOT/'work'/name).read_bytes()) != pin:
            raise ValueError('Pure helper changed after emulation')
    if (len(static['function_comparisons']) != 21 or len(static['jump_tables']) != 4
            or len(static['binding_witnesses']) != 11 or len(static['semantic_witnesses']) != 24
            or any(not row['all_non_reference_instruction_bytes_identical']
                   for row in static['function_comparisons'])
            or [x['cases'] for x in emulation['names']] != [4092, 4092]
            or [x['cases']+x['boundary_cases'] for x in emulation['divisors']] != [48008, 48008]
            or emulation['paths']['cases'] != 48):
        raise ValueError('Metadata qualification scope/verification changed')
    result = dict(kind='updated_metadata_code_root_qualification_summary',
        shipping_sha256=PINS['new'][2], historical_comparison_shipping_sha256=PINS['old'][2],
        evidence_reports=report_pins, bindings=static['bindings'],
        proof_scope=dict(offline_only=True, game_launched=False, process_accessed=False,
            process_memory_written=False, native_getter_called=False,
            production_reader_modified=False, production_build_guard_bypassed=False,
            runtime_metadata_recovered=False, native_protocol_compatibility_verified=False,
            static_function_comparisons=21, full_jump_tables=4,
            names_cases_per_build=4092, divisor_cases_per_build=48008,
            path_control_flow_cases=48, path_external_string_helpers='explicit synthetic ABI stubs'),
        unchanged_native_rules={
            'object_registry': dict(count_offset='0x14', chunks_offset='0x20', entry_bytes=24,
                pointer_offset=0, flags_offset=8, serial_offset='0x14', excluded_flags='0x30000000',
                object_index_offset='0x24', object_class_offset=8, outer_offset='0x10',
                object_name_token_offset='0x1c', pointer_decoder='native callback if nonzero; pure reader must reject'),
            'chunk_arithmetic': dict(outer_default='outside 1..10: signed IDIV by 0x10000',
                outer_1_to_10='select the corresponding one of 10 u32 inner-selector cells',
                formulas='native_metadata_objects._chunk_divisor; all non-reference bytes and full tables match',
                parameter='u32; formulas depend on low six bits',
                zero_divisor='inner4, inner>20, or a formula yielding zero; reject in pure reader',
                valid_python_domain='nonnegative signed-int32 object index; count bounds still required'),
            'name_pool': dict(block_pointer_array_offset=8, slots=8192, block_bytes='0x80000',
                id_block='u32_id >> 18', id_offset='(u32_id & 0x3ffff)*2',
                header='u16', length='header>>6', wide='header&1', payload_offset=2,
                max_length_units=1023, field_rep0_name_token_offset='0x28',
                initialization='native constructs if byte is zero; pure reader must reject uninitialized pool'),
            'characters': dict(key='native_metadata_names._key; nine dispatch cases verified for all valid lengths',
                first_raw_unit_zero='transform returns without modifying payload',
                ascii='XOR every byte', wide='XOR only UTF16-unit indexes 0,2,4,...',
                zero_number_ToString_narrow_high_bytes='U+003F fallback',
                append_narrow_high_bytes='sign-extend signed byte into UTF16 unit',
                suffix='underscore plus signed-int32 decimal of u32(number-1)'),
            'paths': dict(outer_first=True, null_object='None',
                class_test='Outer.Class and Outer.Outer.Class compared against PackageClass singleton',
                separator='colon only if Outer.Class!=PackageClass and Outer.Outer.Class==PackageClass; otherwise dot',
                native_stop_outer_variant=True, pure_reader_support='only null stop-Outer; local bound32 and identity rechecks'),
        },
        limitations=[
            'No new-build runtime registry/header/pool values, pointer-decoder nullness, initialized pool, selected classes, reflection descriptor schemas, or replication layout accepted by a client have been observed.',
            'The name-pool constructor comparison covers its first143 bytes only; block-array size and first block allocation are proved, not the entire15247-byte constructor.',
            'Path emulation interprets complete native recursion/separators and Package getter fast path, with synthetic external FString append/data callbacks; it does not prove allocator behavior or native acceptance.',
            'Pre-existing pure object_path delegates object_name/resolve_name, whose zero-number narrow high-byte handling is ToString fallback U+003F. Native GetPath always calls TokenAppend->EntryAppend, which sign-extends those bytes even for number0. ASCII decoded names agree; arbitrary high-byte narrow names do not have an exact pure path formatting guarantee.',
            'Entry header low bits other than wide-bit, pool allocator cursors, runtime synchronization guarantees and non-null pointer decoder callback internals remain unqualified.',
            'Generic string allocation, security cookie and diagnostic/profiling dependencies were recorded as exact reference pairs but not all recursively qualified. No claim of full executable or protocol equivalence is made.',
        ],
        source_pins=[dict(path=f'work/{name}', sha256=sha((ROOT/'work'/name).read_bytes())) for name in [
            'research_updated_metadata_roots.py', 'research_updated_metadata_emulation.py',
            'research_updated_metadata_qualification.py', 'native_metadata_objects.py',
            'native_metadata_names.py', 'native_metadata_paths.py']],
        verification_commands=['python work/research_updated_metadata_roots.py --static',
            'python work/research_updated_metadata_emulation.py',
            'python work/research_updated_metadata_qualification.py'])
    output = ROOT/'work/evidence/updated-metadata-roots-79fb7b10-qualified.json'
    output.write_text(json.dumps(result, indent=2)+'\n', encoding='utf-8')
    print(json.dumps(dict(output=output.relative_to(ROOT).as_posix(), sha256=sha(output.read_bytes()),
                         bindings=result['bindings'])))


if __name__ == '__main__':
    main()
