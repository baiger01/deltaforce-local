"""Compatibility entry point; edit dfserver.entry.http_api instead."""
from dfserver._compat import alias_module
alias_module(__name__, "dfserver.entry.http_api")
