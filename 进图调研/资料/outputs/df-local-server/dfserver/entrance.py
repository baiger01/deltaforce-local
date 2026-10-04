"""Open the independent local front end, starting our backend if needed."""
import argparse
import json
from pathlib import Path
import sys
from urllib.error import HTTPError, URLError
from urllib.request import urlopen
import webbrowser

from .core import Backend
from .http_api import create_server
from .protobuf_codec import ProtobufCodec


def service_state(port):
    try:
        with urlopen(f"http://127.0.0.1:{port}/healthz", timeout=1) as response:
            value = json.load(response)
        if value.get("service") != "persistent_local_backend":
            return "foreign"
        return "ready" if value.get("local_frontend_version") == 1 else "old"
    except HTTPError:
        return "foreign"
    except (ValueError, AttributeError):
        return "foreign"
    except (URLError, OSError):
        return "absent"


def main():
    parser = argparse.ArgumentParser(description="Open the independent local account, warehouse and quest entrance")
    parser.add_argument("--port", type=int, default=8877)
    parser.add_argument("--no-browser", action="store_true", help="Check/start the service without opening a browser")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")
    root = Path(__file__).resolve().parent.parent
    if sys.stdout is None or sys.stderr is None:
        (root/"data").mkdir(exist_ok=True)
        log = (root/"data/entrance-server.log").open("a",encoding="utf-8",buffering=1)
        sys.stdout = sys.stderr = log
    status = service_state(args.port)
    if status == "old":
        print("An older local service is running on this port. Close its server window and reopen this entrance.")
        return 2
    if status == "foreign":
        print("This port belongs to another service. Choose another port with --port.")
        return 2
    server = None
    if status == "absent":
        backend = Backend(root/"data/local.sqlite3",root/"definitions.json")
        codec = ProtobufCodec(root/"protocol/recovered_telemetry.pb")
        try:
            server = create_server(backend,codec,port=args.port)
        except OSError:
            # Another copy may have completed startup after our health check.
            if service_state(args.port) != "ready":
                print("Local service could not bind this port. See data/entrance-server.log.")
                return 1
    url = f"http://127.0.0.1:{args.port}/"
    print("Local entrance ready: " + url)
    print("Independent local accounts; original game-client connection is not yet available.")
    if not args.no_browser and not webbrowser.open(url):
        print("Open the address above in your browser.")
    if server is not None:
        try:
            server.serve_forever(poll_interval=.25)
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
