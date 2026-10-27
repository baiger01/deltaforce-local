"""Compatibility entry point; edit dfserver.diagnostics.connection_probe instead."""
if __name__ == "__main__":
    from dfserver.diagnostics.connection_probe import main
    raise SystemExit(main())
else:
    from dfserver._compat import alias_module
    alias_module(__name__, "dfserver.diagnostics.connection_probe")
