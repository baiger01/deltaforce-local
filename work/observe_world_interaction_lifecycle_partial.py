"""Retain bounded typed array failure facts without enlarging the original scope.

This calls the frozen reader in its own observer process. Only original named
array scopes are wrapped. Failure headers are diagnostic data, never Actor or
replication bindings. No process is opened until observe is explicitly called.
"""
from datetime import datetime,timezone
import hashlib
from pathlib import Path
import struct
import threading

import observe_world_interaction_lifecycle as original

_LOCK=threading.Lock()


def source_pins():
    pins=original.sources()
    path=Path(__file__).resolve()
    pins['work/observe_world_interaction_lifecycle_partial.py']=hashlib.sha256(path.read_bytes()).hexdigest()
    return pins


def describe_failure(raw,stride,limit,context,recheck):
    safe=dict(status='refused_array_header',scope=context,original_limit=limit,stride=stride,
        bound_increased=False,array_elements_read=False,usable_as_replication_binding=False)
    try:
        if type(raw) is not bytes or len(raw)!=16 or not callable(recheck):
            raise ValueError('The exact original header and final recheck are required')
        recheck()
        data,count,capacity=struct.unpack('<Qii',raw)
        return dict(safe,raw_header_hex=raw.hex(),count=count,capacity=capacity,
            data_pointer_nonnull=bool(data),typed_identity_fields_roots_and_process_rechecked=True)
    except (ValueError,OSError) as error:
        return dict(safe,status='refused_final_recheck',reason=str(error),
            typed_identity_fields_roots_and_process_rechecked=False)


def observe(game_root,trial_report):
    """Same owned identity, fields and bounds; returns partial diagnostics on refusal."""
    pins=source_pins()
    if not _LOCK.acquire(blocking=False):
        raise ValueError('One isolated world observer per Python worker is required')
    contexts,issues,roots=[],[],{}
    old_array=original.array_header
    old_reference=original.Fields.reference_array
    old_value=original.Fields.value
    old_discover=original.discover_roots

    def discover(*args,**kwargs):
        result=old_discover(*args,**kwargs)
        roots.update(kwargs.get('_binding_identity_sink',{}))
        return result

    def scoped(fields,pointer,klass,name,call):
        before=fields.identity(pointer,'Object')
        path=original.object_path(fields.session.read,fields.base,pointer)
        field=fields.one(klass,name)
        def recheck():
            fields.facts.finish()
            if (fields.identity(pointer,'Object')!=before or
                    original.object_path(fields.session.read,fields.base,pointer)!=path):
                raise ValueError('The typed array owner identity or path changed')
            observation=getattr(fields.identity,'__self__',None)
            if not isinstance(observation,original.BindingObservation):
                raise ValueError('The original bounded identity observation is unavailable')
            observation.finish()
            if not callable(roots.get('recheck_roots')):
                raise ValueError('The original owned root final checks are unavailable')
            roots['recheck_roots']()
            backend=getattr(fields.session.backend,'__self__',None)
            if not isinstance(backend,original.Win32MetadataReader):
                raise ValueError('The owned read-only process identity backend is unavailable')
            backend.verify_identity()
            if backend.find_module()!=fields.base or source_pins()!=pins:
                raise ValueError('The original module or source identity changed')
        contexts.append((dict(field_name=name,field=field,owner_identity=before,owner_path=path),recheck))
        try:
            return call()
        finally:
            contexts.pop()

    def reference_array(fields,pointer,klass,name,expected_class):
        return scoped(fields,pointer,klass,name,
            lambda:old_reference(fields,pointer,klass,name,expected_class))

    def value(fields,pointer,klass,name):
        return scoped(fields,pointer,klass,name,lambda:old_value(fields,pointer,klass,name))

    def array(raw,stride,limit=512):
        try:
            return old_array(raw,stride,limit)
        except ValueError:
            if len(issues)>=16:
                raise RuntimeError('The original array diagnostic count exceeds its local bound')
            if contexts:
                context,recheck=contexts[-1]
                issues.append(describe_failure(raw,stride,limit,context,recheck))
            else:
                issues.append(dict(status='unattributed_original_array_refusal',stride=stride,
                    original_limit=limit,bound_increased=False,raw_values_published=False,
                    usable_as_replication_binding=False))
            raise

    try:
        original.array_header=array
        original.Fields.reference_array=reference_array
        original.Fields.value=value
        original.discover_roots=discover
        try:
            result=original.observe(game_root,trial_report)
        except (ValueError,OSError,RuntimeError) as error:
            result=dict(kind='owned_current_world_interaction_partial_array_diagnostics',status='partial',
                reason=str(error),error_type=type(error).__name__,process_memory_written=False,
                native_methods_invoked=False,native_layouts_constructed=False,packets_sent=False,
                code_sampled=False,historical_process_pointers_reused=False)
        result.update(array_failure_diagnostics=issues,source_pins=pins,
            observed_at_utc=datetime.now(timezone.utc).isoformat(),
            original_array_bounds_unchanged=True,partial_values_are_not_replication_bindings=True)
        return result
    finally:
        original.array_header=old_array
        original.Fields.reference_array=old_reference
        original.Fields.value=old_value
        original.discover_roots=old_discover
        _LOCK.release()
