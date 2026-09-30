"""Capture logged lobby gateways or exact TCP flows of this installed client.

Run manually as Administrator; this tool never requests elevation, changes
client memory, redirects traffic, installs a driver, or sends game requests.
Windows Pktmon is used and only this tool's filters are removed afterwards.
"""
from pathlib import Path
import argparse, ctypes, ipaddress, json, os, re, socket, struct, subprocess, time
from ctypes import wintypes
from urllib.parse import urlsplit

PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_ROOT = PROJECT_ROOT.parent / 'game'

def command_output(data):
    # Pktmon can emit UTF-8 while the surrounding Chinese cmd session uses
    # CP936. Do not decode its bytes with Python's locale default first.
    if data.startswith((b'\xff\xfe',b'\xfe\xff')):
        return data.decode('utf-16',errors='replace')
    try:
        return data.decode('utf-8-sig')
    except UnicodeDecodeError:
        return data.decode('mbcs' if os.name=='nt' else 'cp936',errors='replace')

def run(args, check=True):
    result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT)
    result.stdout=command_output(result.stdout)
    if check and result.returncode:
        raise RuntimeError(f'{args[1]} failed (exit {result.returncode}): {result.stdout.strip()}')
    return result

def lobby_endpoints(game_root):
    raw = (game_root/'DeltaForce/Saved/Logs/DeltaForce.log').read_bytes()
    text = bytes(v ^ 0x5c for v in raw.removeprefix(b'\xef\xbb\xbf')).decode('utf-8', errors='replace')
    endpoints = set()
    for line in text.splitlines():
        if 'MakeConnectInfo' not in line or 'selectedUrl' not in line:
            continue
        match = re.search(r'tcp://[^\s,]+', line)
        if not match:
            continue
        parsed = urlsplit(match[0])
        if not parsed.hostname or not parsed.port:
            continue
        try:
            for address in socket.getaddrinfo(parsed.hostname, parsed.port, socket.AF_INET, socket.SOCK_STREAM):
                ip = ipaddress.ip_address(address[4][0])
                if not ip.is_loopback and not ip.is_unspecified:
                    endpoints.add((str(ip), parsed.port))
        except socket.gaierror:
            continue
    return sorted(endpoints)

def tcp_connections():
    api = ctypes.WinDLL('iphlpapi', use_last_error=True).GetExtendedTcpTable
    api.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.ULONG), wintypes.BOOL,
                    wintypes.ULONG, ctypes.c_int, wintypes.ULONG]
    api.restype = wintypes.DWORD
    size = wintypes.ULONG()
    rc = api(None, ctypes.byref(size), False, 2, 5, 0)
    if rc not in (0, 122):
        raise OSError(rc, 'GetExtendedTcpTable size query')
    for _ in range(3):
        buffer = ctypes.create_string_buffer(size.value)
        rc = api(buffer, ctypes.byref(size), False, 2, 5, 0)
        if rc == 122:
            continue
        if rc:
            raise OSError(rc, 'GetExtendedTcpTable')
        data = buffer.raw
        count = struct.unpack_from('<I', data)[0]
        if 4 + count*24 > len(data):
            raise ValueError('Truncated TCP owner table')
        rows = []
        for index in range(count):
            state, local, local_port, remote, remote_port, pid = struct.unpack_from('<6I', data, 4+index*24)
            rows.append({'state':state,'pid':pid,
                         'local_ip':socket.inet_ntoa(struct.pack('<I',local)),
                         'local_port':socket.ntohs(local_port & 65535),
                         'remote_ip':socket.inet_ntoa(struct.pack('<I',remote)),
                         'remote_port':socket.ntohs(remote_port & 65535)})
        return rows
    raise RuntimeError('TCP table changed repeatedly')

def process_path(pid):
    api = ctypes.WinDLL('kernel32', use_last_error=True)
    api.OpenProcess.argtypes = [wintypes.DWORD,wintypes.BOOL,wintypes.DWORD]
    api.OpenProcess.restype = wintypes.HANDLE
    api.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE,wintypes.DWORD,wintypes.LPWSTR,ctypes.POINTER(wintypes.DWORD)]
    api.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = api.OpenProcess(0x1000,False,pid)  # Query path only; no VM access.
    if not handle:
        return None
    try:
        size=wintypes.DWORD(32768); name=ctypes.create_unicode_buffer(size.value)
        return Path(name.value) if api.QueryFullProcessImageNameW(handle,0,name,ctypes.byref(size)) else None
    finally:
        api.CloseHandle(handle)

def verified_live_endpoints(game_root,endpoints,states=(5,)):
    expected = str(game_root/'DeltaForce/Binaries/Win64/DeltaForceClient-Win64-Shipping.exe').replace('\\','/').lower()
    rows=tcp_connections(); verified={}
    # The client uses HTTPDNS; its current peer can differ from OS DNS results.
    # A nonstandard port recorded as a lobby gateway is accepted only when the
    # connection belongs to this exact installed executable. Shared web ports
    # still require an exact endpoint match.
    gateway_ports={port for _,port in endpoints if port>=1024 and port not in (8080,8443,8888)}
    def matches(row):
        peer=(row['remote_ip'],row['remote_port'])
        ip=ipaddress.ip_address(row['remote_ip'])
        return (not ip.is_loopback and not ip.is_unspecified and
                (peer in endpoints or row['remote_port'] in gateway_ports))
    for row in rows:
        if row['state'] not in states or not matches(row):
            continue
        if row['pid'] not in verified:
            path=process_path(row['pid'])
            verified[row['pid']]=bool(path and str(path).replace('\\','/').lower()==expected)
    return sorted({(r['remote_ip'],r['remote_port']) for r in rows
                   if r['state'] in states and verified.get(r['pid']) and matches(r)})

def ensure_pktmon_idle(status):
    if re.search(r'(?i)not\s+(?:currently\s+)?running|not\s+started|\bstopped\b|未(?:在)?运行|尚未运行|没有运行|未启动|已停止',status):
        return
    # A running session or an unfamiliar localized response must not be
    # stopped or have its global capture filters changed.
    raise RuntimeError('Pktmon is active or its status was not recognized. It was left untouched. Status: '+status.strip())

def process_exists(pid):
    # Enumerate IDs through the native process snapshot, without VM access.
    class Entry(ctypes.Structure):
        _fields_=[('dwSize',wintypes.DWORD),('cntUsage',wintypes.DWORD),
                  ('th32ProcessID',wintypes.DWORD),('th32DefaultHeapID',ctypes.c_size_t),
                  ('th32ModuleID',wintypes.DWORD),('cntThreads',wintypes.DWORD),
                  ('th32ParentProcessID',wintypes.DWORD),('pcPriClassBase',wintypes.LONG),
                  ('dwFlags',wintypes.DWORD),('szExeFile',wintypes.WCHAR*260)]
    api=ctypes.WinDLL('kernel32',use_last_error=True)
    api.CreateToolhelp32Snapshot.argtypes=[wintypes.DWORD,wintypes.DWORD]
    api.CreateToolhelp32Snapshot.restype=wintypes.HANDLE
    api.Process32FirstW.argtypes=[wintypes.HANDLE,ctypes.POINTER(Entry)]
    api.Process32NextW.argtypes=[wintypes.HANDLE,ctypes.POINTER(Entry)]
    api.CloseHandle.argtypes=[wintypes.HANDLE]
    handle=api.CreateToolhelp32Snapshot(2,0)
    if handle==ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        row=Entry();row.dwSize=ctypes.sizeof(row)
        has_row=api.Process32FirstW(handle,ctypes.byref(row))
        while has_row:
            if row.th32ProcessID==pid:return True
            has_row=api.Process32NextW(handle,ctypes.byref(row))
        if ctypes.get_last_error()!=18:
            raise ctypes.WinError(ctypes.get_last_error())
        return False
    finally:
        api.CloseHandle(handle)

def stale_capture_session(status,filters,output,pid_exists=process_exists):
    match=re.search(r'(?im)^\s*(?:日志文件|Log\s+file)\s*:\s*(.+\.etl)\s*$',status)
    if not match:
        raise RuntimeError('Active capture ownership could not be verified; it was left untouched.')
    etl=Path(match[1].strip()).resolve()
    filename=re.fullmatch(r'\d{8}-\d{6}-([1-9]\d*)\.etl',etl.name)
    if etl.parent!=Path(output).resolve() or not filename or not etl.is_file():
        raise RuntimeError('Active capture file is outside this tool\'s verified capture directory; it was left untouched.')
    pid=int(filename[1])
    names=re.findall(r'(?m)^\s*\d+\s+(\S+)',filters)
    if not names or any(not re.fullmatch(r'DFLocal_'+str(pid)+r'_\d+',name) for name in names):
        raise RuntimeError('Active capture has foreign or unrecognized filters; it was left untouched.')
    if pid_exists(pid):
        raise RuntimeError('The original capture helper is still running. Let its countdown finish; no capture was stopped.')
    return etl,names,pid

def recover_stale_capture(pktmon,status,output):
    filters=run([pktmon,'filter','list']).stdout
    etl,names,pid=stale_capture_session(status,filters,output)
    # Re-check immediately before stopping, so a concurrent change fails closed.
    latest=run([pktmon,'status']).stdout
    latest_filters=run([pktmon,'filter','list']).stdout
    if stale_capture_session(latest,latest_filters,output)!=(etl,names,pid):
        raise RuntimeError('Capture ownership changed during recovery; it was left untouched.')
    metadata={'capture_mode':'recovered_interrupted_capture','original_helper_pid':pid,
              'original_helper_running':False,'game_modified':False,
              'capture_export_succeeded':False,'pcapng':str(etl.with_suffix('.pcapng'))}
    record=etl.with_suffix('.json')
    record.write_text(json.dumps(metadata,indent=2),encoding='utf-8')
    run([pktmon,'stop'])
    ensure_pktmon_idle(run([pktmon,'status']).stdout)
    metadata['pktmon_stop_confirmed']=True
    for name in reversed(names):run([pktmon,'filter','remove',name])
    metadata['scoped_filters_removed']=len(names)
    record.write_text(json.dumps(metadata,indent=2),encoding='utf-8')
    run([pktmon,'etl2pcap',str(etl),'--out',str(etl.with_suffix('.pcapng'))])
    metadata['capture_export_succeeded']=True
    record.write_text(json.dumps(metadata,indent=2),encoding='utf-8')
    print('Recovered the interrupted capture and exported its packets. No new capture was started.',flush=True)
    return metadata

def verified_client_tcp_flows(game_root):
    expected=str(game_root/'DeltaForce/Binaries/Win64/DeltaForceClient-Win64-Shipping.exe').replace('\\','/').lower()
    rows=tcp_connections(); verified={}; flows=set()
    for row in rows:
        if row['state']!=5 or not row['remote_port']:
            continue
        if row['pid'] not in verified:
            path=process_path(row['pid'])
            verified[row['pid']]=bool(path and str(path).replace('\\','/').lower()==expected)
        if verified[row['pid']]:
            flows.add((row['local_ip'],row['local_port'],row['remote_ip'],row['remote_port']))
    return sorted(flows)

def captured_gateway_endpoints(output):
    # Seed a relaunch capture from the actual observed GCP peer, rather than
    # relying solely on OS DNS when the game uses a different resolver.
    try:
        from tools.analyze_capture import captured_packets, tcp_payload, MAX_CAPTURE
    except ModuleNotFoundError:
        from analyze_capture import captured_packets, tcp_payload, MAX_CAPTURE
    from dfserver.gcp_framing import decode_prefix
    candidates=sorted(Path(output).glob('*.pcapng'),key=lambda path:path.stat().st_mtime,reverse=True)[:5]
    for path in candidates:
        if path.stat().st_size>MAX_CAPTURE:
            continue
        found=set()
        for link,packet,truncated in captured_packets(path.read_bytes()):
            parsed=tcp_payload(link,packet)
            if not parsed:
                continue
            key,seq,body=parsed
            if 65010 not in (key[1],key[3]) or not body.startswith(b'\x33\x66'):
                continue
            try:
                decoded=decode_prefix(body)
            except ValueError:
                continue
            if decoded is None or decoded[0].command not in (0x1001,0x1002,0x4013,0x4023,0x9001):
                continue
            address=key[0] if key[1]==65010 else key[2]
            ip=ipaddress.ip_address(address)
            if not ip.is_loopback and not ip.is_unspecified:
                found.add((str(ip),65010))
        if found:
            return sorted(found)
    return []

def capture(game_root,output,seconds,discover_only=False,include_login=False,client_connections=False,use_capture_gateways=False,recover_stale=False,lobby_port_only=False):
    if os.name != 'nt':
        raise RuntimeError('This capture helper needs Windows')
    if lobby_port_only and (not include_login or client_connections or use_capture_gateways):
        raise ValueError('Lobby port capture requires --include-login and cannot be combined with the other capture scope modes')
    skip_endpoints=client_connections or lobby_port_only
    endpoints=[] if skip_endpoints else lobby_endpoints(game_root)
    if use_capture_gateways and (not include_login or client_connections):
        raise ValueError('Capture gateway seeds require --include-login and cannot be combined with --client-connections')
    seeded=captured_gateway_endpoints(output) if use_capture_gateways else []
    endpoints=sorted(set(endpoints)|set(seeded))
    live=[] if skip_endpoints else verified_live_endpoints(game_root,endpoints)
    observed=[] if skip_endpoints else verified_live_endpoints(game_root,endpoints,states=(3,4,5,8))
    client_flows=verified_client_tcp_flows(game_root) if client_connections else []
    metadata={'configured_gateway_endpoints':len(endpoints),'previously_captured_gcp_gateway_endpoints':len(seeded),
              'verified_live_gateway_endpoints':len(live),
              'observed_client_gateway_peers':len(observed),
              'peer_match_rule':'Exact configured peer, or installed-client TCP peer on a nonstandard logged gateway port',
              'capture_mode':'configured_gateways_before_login' if include_login else 'verified_live_gateways'}
    if client_connections:
        metadata.update({'capture_mode':'installed_client_tcp_connections',
                         'verified_client_tcp_flows':len(client_flows),
                         'verified_client_loopback_flows':sum(ipaddress.ip_address(f[2]).is_loopback for f in client_flows)})
    if lobby_port_only:
        metadata.update({'capture_mode':'lobby_gateway_port_before_login',
                         'capture_port':65010,'peer_match_rule':'TCP source or destination port 65010; no fixed IP address filter'})
    if discover_only:
        return metadata
    if not live and not include_login and not client_connections:
        raise RuntimeError('No live lobby connection matched this client. Enter the lobby through WeGame first.')
    selected=sorted(set(endpoints)|set(observed)) if include_login else live
    if client_connections:
        selected=client_flows
    if lobby_port_only:
        selected=[(None,65010)]
    if not selected and client_connections:
        raise RuntimeError('No active IPv4 TCP connections belonging to this installed game client were found. Keep the game running.')
    if not selected:
        raise RuntimeError('No gateway endpoints were found in this installed client log.')
    if len(selected)>32:
        raise RuntimeError('Too many capture filters for this Windows Pktmon version; no filters were changed.')
    if not ctypes.windll.shell32.IsUserAnAdmin():
        raise RuntimeError('Windows Pktmon requires Administrator. Right-click the capture .cmd launcher and choose Run as administrator.')
    system_root = os.environ.get('SystemRoot')
    if not system_root:
        raise RuntimeError('Windows SystemRoot is unavailable')
    pktmon=str(Path(system_root)/'System32/pktmon.exe')
    output=output.resolve(); output.mkdir(parents=True,exist_ok=True)
    status=run([pktmon,'status']).stdout
    (output/'last-preflight.json').write_text(json.dumps({'pktmon_status':status},ensure_ascii=False,indent=2),encoding='utf-8')
    try:
        ensure_pktmon_idle(status)
    except RuntimeError:
        if recover_stale:
            return recover_stale_capture(pktmon,status,output)
        raise
    filters=run([pktmon,'filter','list']).stdout
    if re.search(r'(?m)^\s*[1-9][0-9]*\s+',filters) or re.search(r'\b(?:TCP|UDP|IPv4|IPv6)\b',filters):
        raise RuntimeError('Existing Pktmon filters were found. They were left untouched; use a separate capture session.')
    if not 1 <= seconds <= 300:
        raise ValueError('Capture duration must be 1..300 seconds')
    stamp=time.strftime('%Y%m%d-%H%M%S')+'-'+str(os.getpid())
    etl=output/(stamp+'.etl'); pcap=output/(stamp+'.pcapng')
    metadata.update({'original_helper_pid':os.getpid(),'pcapng':str(pcap),
                     'requested_capture_seconds':seconds,'capture_filter_count':len(selected),
                     'game_modified':False,'capture_export_succeeded':False})
    record=output/(stamp+'.json')
    record.write_text(json.dumps(metadata,indent=2),encoding='utf-8')
    added=[]; started=False; stopped=True
    try:
        for index,peer in enumerate(selected):
            name=f'DFLocal_{os.getpid()}_{index}'
            if client_connections:
                local_ip,local_port,remote_ip,remote_port=peer
                ips=[remote_ip] if remote_ip==local_ip else [remote_ip,local_ip]
                run([pktmon,'filter','add',name,'-i',*ips,'-p',str(local_port),str(remote_port),'-t','TCP'])
            else:
                ip,port=peer
                address_args=['-i',ip] if ip is not None else []
                run([pktmon,'filter','add',name,*address_args,'-p',str(port),'-t','TCP'])
            added.append(name)
        run([pktmon,'start','--capture','--comp','all' if client_connections else 'nics','--pkt-size','0',
             '--file-name',str(etl),'--file-size','64','--log-mode','circular'])
        started=True
        scope='TCP port 65010 filter' if lobby_port_only else ('verified installed-client TCP flows' if client_connections else ('configured lobby gateways' if include_login else 'verified live lobby gateways'))
        print(f'Capturing {len(added)} {scope} for {seconds} seconds.',flush=True)
        print('Keep this window open until the capture is exported. Ctrl+C ends it early and saves the packets.',flush=True)
        if include_login and not client_connections:
            print('Now launch the game normally through WeGame and enter the lobby.',flush=True)
        print('In the game: open warehouse, move one item, then open the tasks page.',flush=True)
        for remaining in range(seconds,0,-1):
            if remaining % 10 == 0: print(f'{remaining} seconds remaining',flush=True)
            time.sleep(1)
    except KeyboardInterrupt:
        print('Ending capture early and exporting recorded packets.',flush=True)
    finally:
        if started:
            result=run([pktmon,'stop'],check=False)
            if result.returncode:
                stopped=False
                print('Pktmon stop failed. Scoped filters were retained; run pktmon stop as Administrator.',flush=True)
        if stopped:
            for name in reversed(added):
                run([pktmon,'filter','remove',name],check=False)
    if not stopped:
        raise RuntimeError('Capture stop was not confirmed. The ETL and this capture\'s filters were preserved.')
    if started:
        run([pktmon,'etl2pcap',str(etl),'--out',str(pcap)])
        metadata['capture_export_succeeded']=True
        record.write_text(json.dumps(metadata,indent=2),encoding='utf-8')
    return metadata

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--game-root',type=Path,default=Path(os.environ.get('DF_LOCAL_SOURCE_GAME', DEFAULT_ROOT)))
    parser.add_argument('--output',type=Path,default=Path(__file__).resolve().parents[1]/'data/captures')
    parser.add_argument('--seconds',type=int,default=60)
    parser.add_argument('--discover-only',action='store_true')
    parser.add_argument('--include-login',action='store_true',
                        help='Start before the game, filtering gateway endpoints from its existing log')
    parser.add_argument('--client-connections',action='store_true',
                        help='Capture exact current game TCP flows, including loopback proxy connections, across the networking stack')
    parser.add_argument('--use-capture-gateways',action='store_true',
                        help='For a login capture, include actual GCP gateway peers from a previous local capture')
    parser.add_argument('--recover-stale',action='store_true',
                        help='Recover this tool\'s interrupted capture only when its original process has exited; then return without starting another capture')
    parser.add_argument('--lobby-port-only',action='store_true',
                        help='Before login, capture TCP port 65010 regardless of changing gateway IP addresses')
    args=parser.parse_args()
    if not args.game_root.is_absolute():
        args.game_root = PROJECT_ROOT / args.game_root
    args.game_root = args.game_root.resolve()
    try:
        print(json.dumps(capture(args.game_root,args.output,args.seconds,args.discover_only,args.include_login,args.client_connections,args.use_capture_gateways,args.recover_stale,args.lobby_port_only),ensure_ascii=False,indent=2))
    except (OSError,RuntimeError,ValueError) as exc:
        parser.exit(1,str(exc)+'\n')

if __name__=='__main__':main()
