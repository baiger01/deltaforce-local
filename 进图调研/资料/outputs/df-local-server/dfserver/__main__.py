import argparse
from pathlib import Path

from .core import Backend
from .http_api import create_server
from .protobuf_codec import ProtobufCodec


def main():
    root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description="Local persistent backend; original game gateway remains unverified")
    parser.add_argument("--port",type=int,default=8877)
    parser.add_argument("--game-port",type=int,default=65010)
    parser.add_argument("--database",type=Path,default=root/"data/local.sqlite3")
    parser.add_argument("--definitions",type=Path,default=root/"definitions.json")
    arguments = parser.parse_args()
    backend = Backend(arguments.database,arguments.definitions)
    codec = ProtobufCodec(root/"protocol/recovered_telemetry.pb")
    server = create_server(backend,codec,port=arguments.port,game_port=arguments.game_port)
    print(f"Local backend listening at http://127.0.0.1:{server.server_port}",flush=True)
    print("Original game client compatibility: NOT VERIFIED; game gateway disabled",flush=True)
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
