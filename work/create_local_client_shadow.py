"""Create a user-writable test tree without duplicating the game's large assets.

The shadow uses hard links for immutable game files on the same volume. Saved
data and the SDK that the local test swaps are independent files. This script
never changes or removes a file from the installed client.
"""
from pathlib import Path
import os
import shutil
from local_game_paths import game_paths


SOURCE, TARGET = game_paths()
WORKSPACE = TARGET.parent
SDK_RELATIVE = Path('DeltaForce/Binaries/ThirdParty/WeGame/Win64/rail_api64.dll')
COPY_SUFFIXES = {'.ini', '.json', '.log', '.txt', '.xml', '.cfg', '.conf'}


def main():
    if not TARGET.is_relative_to(WORKSPACE) or TARGET == WORKSPACE:
        raise ValueError('Shadow target is outside the intended workspace')
    if TARGET == SOURCE or TARGET.is_relative_to(SOURCE) or SOURCE.is_relative_to(TARGET):
        raise ValueError('Shadow target and source client must be separate directory trees')
    if SOURCE.drive.lower() != TARGET.drive.lower():
        raise ValueError('Hard links require a same-volume shadow target')
    if not SOURCE.is_dir():
        raise FileNotFoundError(SOURCE)
    if TARGET.exists() and not TARGET.is_dir():
        raise ValueError('The shadow target is not a directory')
    target_files = copied = linked = 0
    TARGET.mkdir(parents=True, exist_ok=True)
    for base, dirs, files in os.walk(SOURCE):
        source_dir = Path(base)
        relative_dir = source_dir.relative_to(SOURCE)
        # Keep logs, caches, and user settings private to the test client.
        dirs[:] = [name for name in dirs if not (relative_dir == Path('DeltaForce')
                                                 and name.lower() == 'saved')]
        destination_dir = TARGET / relative_dir
        destination_dir.mkdir(parents=True, exist_ok=True)
        for name in files:
            original = source_dir / name
            relative = relative_dir / name
            destination = TARGET / relative
            if not original.is_file():
                continue
            target_files += 1
            copy = relative == SDK_RELATIVE or original.suffix.lower() in COPY_SUFFIXES
            if destination.exists():
                if copy:
                    if destination.stat().st_size != original.stat().st_size:
                        raise ValueError(f'Existing copied file differs in size: {destination}')
                elif not os.path.samefile(original, destination):
                    raise ValueError(f'Existing hard link differs: {destination}')
                continue
            if copy:
                shutil.copy2(original, destination)
                copied += 1
            else:
                os.link(original, destination)
                linked += 1
    print(f'shadow={TARGET} files={target_files} newly_linked={linked} newly_copied={copied}',
          flush=True)


if __name__ == '__main__':
    main()
