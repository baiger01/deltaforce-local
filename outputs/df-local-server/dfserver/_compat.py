"""Keep historical imports bound to the canonical implementation module."""
from importlib import import_module
import sys


def alias_module(legacy_name, canonical_name):
    implementation = import_module(canonical_name)
    sys.modules[legacy_name] = implementation
    return implementation
