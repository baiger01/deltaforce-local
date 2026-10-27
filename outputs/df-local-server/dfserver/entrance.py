"""Compatibility entry point; edit dfserver.entry.entrance instead."""
if __name__ == "__main__":
    from dfserver.entry.entrance import main
    raise SystemExit(main())
else:
    from dfserver._compat import alias_module
    alias_module(__name__, "dfserver.entry.entrance")
