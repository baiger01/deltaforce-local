"""Compatibility entry point; edit dfserver.account.accounts instead."""
if __name__ == "__main__":
    from dfserver.account.accounts import main
    raise SystemExit(main())
else:
    from dfserver._compat import alias_module
    alias_module(__name__, "dfserver.account.accounts")
