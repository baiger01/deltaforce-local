"""Launch the canonical runtime with an explicit client-build profile."""
import argparse
import hashlib
from pathlib import Path
import subprocess
import sys

from local_game_paths import game_paths

ROOT = Path(__file__).resolve().parent.parent
PROFILE = ROOT / 'outputs/df-local-server/protocol/portable-map-spawn/profile-carried-inventory.json'
HISTORICAL_CLIENT = '4254fbe66585f260f1f9dbfc5e302887842552e7baed8939e023160a5e250be0'
CURRENT_CLIENT = '79fb7b105170141ed863331d36833a73062e66bf5291b2364fe3a64c18336203'


def client_build(shadow):
    executable = shadow/'DeltaForce/Binaries/Win64/DeltaForceClient-Win64-Shipping.exe'
    with executable.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def command(*, observation_seconds=1800, native_username=None, source_game=None, shadow_game=None):
    source, shadow = game_paths(source_game, shadow_game)
    if type(observation_seconds) is not int or not 30 <= observation_seconds <= 1800:
        raise ValueError('Observation seconds must be in 30..1800')
    result = [sys.executable, '-B', str(ROOT / 'work/run_native_elevated_trial.py'),
              '--entry', 'shipping', '--source-game', str(source), '--shadow-game', str(shadow),
              '--game-root', str(shadow), '--wire-identity-probe', '--wire-auth-response-probe',
              '--wire-auth-identity-probe', '--wire-ready-probe', '--wire-ready-identity-probe',
              '--wire-business-login-probe', '--wire-business-bootstrap-probe',
              '--game-server-probe', '--ds-handshake-probe', '--ds-packet-ack-probe',
              '--ds-control-probe', '--ds-map-id', '2201',
              '--ds-join-after-ready', '--disable-device-seamless', '--disable-dynamic-address-switch',
              '--enable-sol-map-entry-loading', '--observation-seconds', str(observation_seconds),
              '--precreate-game-nick']
    build = client_build(shadow)
    if build == HISTORICAL_CLIENT:
        result.extend(('--replication-metadata-export', '--bootstrap-template-observation',
                       '--portable-map-bootstrap', str(PROFILE)))
    elif build == CURRENT_CLIENT:
        result.extend(('--updated-client-transport-observation', '--updated-minimum-actor-bootstrap',
            '--ds-control-profile', str(ROOT/'outputs/df-local-server/protocol/native_ds_control_profile_79fb7b10.json')))
    else:
        raise ValueError('Unsupported client build: ' + build)
    if native_username:
        result.extend(('--native-username', native_username))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--observation-seconds', type=int, default=1800)
    parser.add_argument('--native-username')
    parser.add_argument('--source-game', type=Path)
    parser.add_argument('--shadow-game', type=Path)
    args = parser.parse_args()
    return subprocess.call(command(observation_seconds=args.observation_seconds,
                                   native_username=args.native_username,
                                   source_game=args.source_game, shadow_game=args.shadow_game), cwd=ROOT)


if __name__ == '__main__':
    raise SystemExit(main())
