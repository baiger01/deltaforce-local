"""Resolve the installed game and test shadow without machine-specific defaults.

Layout after extracting the transfer bundle::

    parent/
      deltaforce-local/   # this project
      game/               # same-version installed game, or a directory junction
      shadow/             # independently created local test client

Environment variables and command-line overrides may point elsewhere. Relative
overrides are always interpreted relative to the project, not the shell's cwd.
"""

from pathlib import Path
import os


PROJECT_ROOT = Path(__file__).resolve().parent.parent


def project_path(value: str | Path | None, default: Path) -> Path:
    candidate = Path(value) if value else default
    if not candidate.is_absolute():
        candidate = PROJECT_ROOT / candidate
    return candidate.resolve()


def game_paths(source: str | Path | None = None,
               shadow: str | Path | None = None) -> tuple[Path, Path]:
    installed = project_path(source or os.environ.get("DF_LOCAL_SOURCE_GAME"),
                      PROJECT_ROOT.parent / "game")
    independent = project_path(shadow or os.environ.get("DF_LOCAL_SHADOW_GAME"),
                        PROJECT_ROOT.parent / "shadow")
    if independent == installed or independent.is_relative_to(installed) or installed.is_relative_to(independent):
        raise ValueError("The installed game and test shadow must be separate directory trees")
    return installed, independent
