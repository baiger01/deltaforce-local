"""Compatibility entry point; edit dfserver.transport.gcp.gcp_framing instead."""
from dfserver._compat import alias_module
alias_module(__name__, "dfserver.transport.gcp.gcp_framing")
