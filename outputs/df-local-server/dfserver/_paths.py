"""Stable resource locations shared by all server implementation packages."""
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parent
SERVER_ROOT = PACKAGE_ROOT.parent
PROJECT_ROOT = SERVER_ROOT.parent.parent
PROTOCOL_ROOT = SERVER_ROOT / 'protocol'
CONFIG_ROOT = SERVER_ROOT / 'config'
WEB_ROOT = PACKAGE_ROOT / 'web'
