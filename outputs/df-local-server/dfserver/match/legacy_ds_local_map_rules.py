"""Explicit local map policy over source-pinned candidates and real item IDs.

This produces server world state, not native Actor replication or inventory
grants. Its probabilities, selections and pool bindings are local policy.
"""
import base64
import copy
import hashlib
import json
import math
import re

SOURCES_SHA256 = '5e004e675466585ba760633e1edb5e294c2546675e54f5fff5f750a7054aafaa'
MAX_QUANTITY_PER_SLOT = 10000
MAX_ROLLS_PER_OBJECT = 64
MAX_TOTAL_QUANTITY = 1000000
MAX_WEIGHT = 1000000000
MASK64 = (1 << 64)-1


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _json(raw):
    if type(raw) is not bytes or not 0 < len(raw) <= 32*1024*1024:
        raise ValueError('Bounded explicit JSON bytes are required')
    def pairs(entries):
        result = {}
        for key, value in entries:
            if key in result:
                raise ValueError('Duplicate JSON key: '+key)
            result[key] = value
        return result
    def invalid(value):
        raise ValueError('Non-finite JSON number: '+value)
    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)
    except (UnicodeError, RecursionError) as error:
        raise ValueError('Invalid bounded JSON document') from error


def _keys(value, required, label):
    if type(value) is not dict or set(value) != set(required):
        raise ValueError('Explicit '+label+' fields are required: '+', '.join(sorted(required)))


def _integer(value, low, high, label):
    if type(value) is not int or not low <= value <= high:
        raise ValueError(label+' is outside its integer bounds')
    return value


def _probability(value):
    if type(value) not in (int, float) or not 0 <= value <= 1 or not math.isfinite(value):
        raise ValueError('Appearance probability must be finite and within0..1')
    return value


def load_rule_sources(raw):
    if type(raw) is not bytes or _sha(raw) != SOURCES_SHA256:
        raise ValueError('The pinned client-derived map rule sources are required')
    return _json(raw)


class _ReplayRandom:
    """Local SHA256 counter stream v1; independent of the spawn allocator RNG."""
    def __init__(self, seed):
        _integer(seed, 0, MASK64, 'Seed')
        self.prefix = b'DF-local-map-rules-v1\0'+seed.to_bytes(8, 'little')
        self.draw_count = 0

    def next(self):
        block = hashlib.sha256(self.prefix+self.draw_count.to_bytes(8, 'little')).digest()
        self.draw_count += 1
        return int.from_bytes(block[:8], 'little')

    def below(self, exclusive):
        limit = (1 << 64)-((1 << 64) % exclusive)
        while True:
            value = self.next()
            if value < limit:
                return value % exclusive

    def appears(self, probability):
        if probability in (0, 1):
            return bool(probability)
        numerator, denominator = probability.as_integer_ratio()
        return self.next() < numerator*(1 << 64)//denominator

    def weighted(self, entries):
        draw = self.below(sum(weight for _, weight in entries))
        for value, weight in entries:
            if draw < weight:
                return value
            draw -= weight
        raise AssertionError('Unreachable weighted interval')

    def choose(self, entries, count):
        remaining, result = list(entries), []
        for _ in range(count):
            selected = self.weighted(remaining)
            result.append(selected)
            remaining = [(value, weight) for value, weight in remaining if value != selected]
        return result


def _candidate_weights(entries, id_field, allowed):
    if type(entries) is not list or not 1 <= len(entries) <= len(allowed):
        raise ValueError('A nonempty bounded source candidate list is required')
    result, seen = [], set()
    for entry in entries:
        _keys(entry, (id_field, 'weight'), 'candidate')
        identity = entry[id_field]
        if type(identity) is not int or identity not in allowed or identity in seen:
            raise ValueError('Unknown or duplicate source candidate')
        seen.add(identity)
        result.append((identity, _integer(entry['weight'], 1, MAX_WEIGHT, 'Weight')))
    return result


def _pools(config, sources, catalog):
    if type(config) is not dict or not 1 <= len(config) <= 64:
        raise ValueError('One to64 explicit local drop pools are required')
    result = {}
    for name, definition in config.items():
        if type(name) is not str or not re.fullmatch('[A-Za-z][A-Za-z0-9_]{0,63}', name):
            raise ValueError('A bounded local pool name is required')
        if type(definition) is dict and set(definition) == {'source_blueprint_pool'}:
            pool_id = definition['source_blueprint_pool']
            if type(pool_id) is not str or pool_id not in sources['blueprint_drop_pools']:
                raise ValueError('Unknown BlueprintPlunderDropPool row')
            source_pool = sources['blueprint_drop_pools'][pool_id]
            entries = source_pool['items']
            provenance = dict(source_pool_id=pool_id, source=copy.deepcopy(source_pool['source']))
        else:
            _keys(definition, ('items',), 'custom pool')
            entries, provenance = definition['items'], dict(source_pool_id=None, source=None)
        if type(entries) is not list or not 1 <= len(entries) <= 4096:
            raise ValueError('An empty or oversized item pool is unsupported')
        weights, seen = [], set()
        for entry in entries:
            _keys(entry, ('item_id', 'weight'), 'pool item')
            item = entry['item_id']
            if (type(item) is not str or not re.fullmatch('[1-9][0-9]{0,19}', item) or
                    item not in catalog['rows'] or item in seen or catalog['rows'][item]['id'] != item):
                raise ValueError('A unique real GameItem ID is required')
            seen.add(item)
            weights.append((item, _integer(entry['weight'], 1, MAX_WEIGHT, 'Item weight')))
        result[name] = dict(weights=weights, provenance=provenance)
    return result


def _drop(config, pools):
    _keys(config, ('pool', 'rolls', 'quantity'), 'drop')
    if type(config['pool']) is not str or config['pool'] not in pools:
        raise ValueError('The selected local drop pool does not exist')
    _integer(config['rolls'], 0, MAX_ROLLS_PER_OBJECT, 'Drop rolls')
    quantity = config['quantity']
    _keys(quantity, ('min', 'max'), 'quantity')
    _integer(quantity['min'], 1, MAX_QUANTITY_PER_SLOT, 'Minimum quantity')
    _integer(quantity['max'], quantity['min'], MAX_QUANTITY_PER_SLOT, 'Maximum quantity')


def simulate_local_map_rules(sources_raw, item_catalog_raw, config_raw, *, seed):
    """Return replayable local world state from explicit bytes and uint64 seed.

    Selections use weighted sampling without replacement. Drop slots sample
    with replacement. Quantity is an aggregate world-state unit count; native
    stack splitting, pickup interaction and persistence are separate work.
    """
    sources = load_rule_sources(sources_raw)
    if type(item_catalog_raw) is not bytes or _sha(item_catalog_raw) != sources['item_catalog']['sha256']:
        raise ValueError('The source-pinned GameItem catalog is required')
    catalog, config = _json(item_catalog_raw), _json(config_raw)
    _keys(config, ('kind', 'map_id', 'pools', 'mandel', 'high_value'), 'local rule config')
    if config['kind'] != 'explicit_local_map_rules_v1' or type(config['map_id']) is not int or config['map_id'] != 2201:
        raise ValueError('Only the source-qualified local Dam rule config is supported')
    pools = _pools(config['pools'], sources, catalog)
    generators = {g['generator_id']: g for g in sources['mandel_generators']}
    points = {p['source_index']: p for p in sources['high_value_points']}
    events = sorted({p['event_id'] for p in points.values()})
    mandel, high = config['mandel'], config['high_value']
    _keys(mandel, ('appearance_probability', 'selection_count', 'candidate_weights', 'drop',
                  'occurrence_event_id', 'absence_event_id'), 'Mandel rule')
    _keys(high, ('appearance_probability', 'selection_count', 'event_weights', 'points_per_event', 'drop'), 'high-value rule')
    for key, state in (('occurrence_event_id', 'MandelBrickOccur'), ('absence_event_id', 'MandelBrickNotOccur')):
        identity = mandel[key]
        if (type(identity) is not int or str(identity) not in sources['mandel_intro_events'] or
                sources['mandel_intro_events'][str(identity)]['event_id'] != identity or
                sources['mandel_intro_events'][str(identity)]['state'] != 'ESOLEventState::'+state):
            raise ValueError('The configured Mandel event must have its actual source ID and matching state')
    m_weights = _candidate_weights(mandel['candidate_weights'], 'generator_id', generators)
    h_weights = _candidate_weights(high['event_weights'], 'event_id', events)
    for family, weights in ((mandel, m_weights), (high, h_weights)):
        _probability(family['appearance_probability'])
        _integer(family['selection_count'], 0, len(weights), 'Selection count')
        _drop(family['drop'], pools)
    _integer(high['points_per_event'], 1, 4, 'Points per event')
    maximum_units = sum(f['selection_count']*multiplicity*f['drop']['rolls']*f['drop']['quantity']['max']
                        for f, multiplicity in ((mandel, 1), (high, high['points_per_event'])))
    if maximum_units > MAX_TOTAL_QUANTITY:
        raise ValueError('The configured room quantity exceeds its bounded world-state budget')
    random, objects = _ReplayRandom(seed), []

    def slots(drop):
        pool, result = pools[drop['pool']], []
        for index in range(drop['rolls']):
            item_id = random.weighted(pool['weights'])
            quantity = drop['quantity']
            amount = quantity['min']+random.below(quantity['max']-quantity['min']+1)
            item = catalog['rows'][item_id]
            result.append(dict(local_slot_index=index, item_id=item_id, quantity=amount,
                item_source=dict(table=catalog['source_table'], row=item_id,
                    serialized_uexp_offset=item['serialized_uexp_offset']),
                source_max_stack_count=item['max_stack_count'], native_stack_split_applied=False))
        return result

    def object_state(kind, key, candidate, drop):
        value = copy.deepcopy(candidate)
        value.update(kind=kind, local_state_key=key, active=True, activation_policy='explicit_local_config',
                     drop_pool=drop['pool'], drop_pool_source=copy.deepcopy(pools[drop['pool']]['provenance']),
                     drop_pool_binding_is_official=False, drop_slots=slots(drop),
                     coordinate_basis='source_DataTable_DS_coordinate', runtime_actor_resolved=False,
                     native_world_placement_verified=False)
        return value

    if random.appears(mandel['appearance_probability']):
        for identity in random.choose(m_weights, mandel['selection_count']):
            objects.append(object_state('mandel_generator', 'mandel:'+str(identity), generators[identity], mandel['drop']))
    selected_high_events = []
    if random.appears(high['appearance_probability']):
        selected_high_events = random.choose(h_weights, high['selection_count'])
        for event in selected_high_events:
            candidates = [(i, 1) for i, point in points.items() if point['event_id'] == event]
            for index in random.choose(candidates, high['points_per_event']):
                objects.append(object_state('high_value_point', 'high_value:'+str(index), points[index], high['drop']))
    generator_ids = [o['generator_id'] for o in objects if o['kind'] == 'mandel_generator']
    mandel_event_id = mandel['occurrence_event_id'] if generator_ids else mandel['absence_event_id']
    event_source = copy.deepcopy(sources['mandel_intro_events'][str(mandel_event_id)])
    event_source.update(binding_origin='explicit_local_policy', target_local_map_id=2201,
                        official_target_map_binding_recovered=False)
    iris_event_ids = selected_high_events+[mandel_event_id]
    return dict(kind='local_map_rule_world_state_v1', map_id=2201, seed=seed,
        rng_algorithm='local_sha256_counter_uint64_rejection_v1', rng_draw_count=random.draw_count,
        config_sha256=_sha(config_raw), sources_sha256=_sha(sources_raw),
        config_snapshot_base64=base64.b64encode(config_raw).decode('ascii'),
        item_catalog_sha256=_sha(item_catalog_raw), source_files=copy.deepcopy(sources['source_files']),
        world_objects=objects, local_rule_policy_applied=True,
        selected_high_value_event_ids=selected_high_events,
        high_value_preview_candidates=[copy.deepcopy(p) for p in points.values()
                                       if p['event_id'] in selected_high_events],
        high_value_preview_candidates_are_active_instances=False,
        business_activation_bindings_complete=True, business_activation_binding_origin='explicit_local_policy',
        official_business_activation_binding_recovered=False,
        selected_mandel_generator_ids=generator_ids, mandel_business_event_ids=[mandel_event_id],
        mandel_event_source=event_source, iris_event_ids=iris_event_ids,
        quantity_semantics='aggregate_server_world_state_units_before_native_stack_splitting',
        appearance_semantics='one_bernoulli_per_family_then_weighted_without_replacement',
        high_value_point_selection='explicit_local_equal_weights_within_selected_source_event',
        official_drop_policy_recovered=False, official_pool_binding_recovered=False,
        native_interaction_verified=False, native_replication_implemented=False,
        inventory_grants_applied=False, playable_map_verified=False)
