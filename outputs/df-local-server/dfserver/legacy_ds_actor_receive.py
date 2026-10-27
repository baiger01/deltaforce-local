"""Compatibility entry point; edit dfserver.replication.legacy_ds_actor_receive instead."""
from dfserver._compat import alias_module
alias_module(__name__, "dfserver.replication.legacy_ds_actor_receive")
