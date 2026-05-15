import json
import sys
import hashlib
from elftools.elf.elffile import ELFFile
from pathlib import Path

#Fast path

KNOWN_GOOD_PATHS = ["/usr/bin/ls", "/usr/bin/cat", "usr/bin/bash"]

print("Monitoring running... Im waiting for events...")

def fast_path_filter(path):
    p = str(path)
    if path in KNOWN_GOOD_PATHS:
        return False
    if "unresolved" in p:
        return False
    return any(p.startswith(pref) for pref in ["/usr/bin", "/bin", "/tmp"])
print("---START BEHAVIOR ANALYSIS --- ", flush = True)

def deep_analysis(file_path):
    try:
        with open(p, "rb") as f:
            elffile = ELFFile(f)
            has_exec_stack = 'GNU_STACK' in [s.name for s in elffile.iter_sections()]
            sha256 = hashlib.sha256(data).hexdigest()
            proc = event.get("process", {})
            is_signed = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']].Size > 0
            path = proc.get("binary")

            return f"[!!!]ANALIZA: {file_path}\n   Hash: {sha256}\n   Signed: {is_signed}\n   Path: {path}\n"
    except Exception as e:
        return f"[SKIP] {file_path}: {e}"
    
def analyze_network(event):
    try:
        kprobe = event["process_kprobe"]
        args = kprobe.get("args,[]")
        sock = next((arg ["sock_arg"] for arg in args if "sock_arg" in arg), None)

        if sock:
            saadr = sock.get("saddr")
            daddr = sock.get("daddr")
            sport = sock.get("sport")
            dport = sock.get("dport")

            process = event.get("process", {})
            p_name = process_get("binary", "unknown")
            p_id = process.get("pid", "unknown")

            return f"[NETWORK] {p_name} (PID: {p_id}) connecting with: {saddr}:{sport} -> {daddr}:{dport}"
    except Exception as e:
        return f"[NET_ERR] ERROR NETWORK ANALYSIS {e}"

for line in sys.stdin:

    print(f"DEBUG: INCOMMING: {line[:50]}...", flush = True)

    try:
        event = json.loads(line)
        function_name = event.get("process_kprobe", {}).get("function_name", {}) or \
                        event.get("process_exec", {}).get("process", {}) or \
                        event.get("process", {})
        path = event.get("fast_path")

        if "process_kprobe" in event:
            kp = event["process_kprobe"]
            func = kp.get("function_name", "unknown")
            print(f"ACTION: {func} in process {kp.get('process', {}).get('binary')}", flush = True)

            if path:
                if fast_path_filter(path):
                    print(deep_analysis(path))
            
            elif "process_exec" in event:
                proc = event["process_exec"]["process"]
                print(f"START: {proc['binary']} (PID: {proc['pid']})", flush = True)
            elif "process_exit" in event:
                pe = event["process_exit"]["process"]
                print(f"THE END: {pe['binary']}",  flush = True)
            else:
                pass

            if function_name in ["do_open_execat", "begin_new_exec"]:
                pass
            elif function_name in["tcp_v4_connect", "tcp_v6_connect"]:
                print(analyze_network(event))

    except json.JSONDecodeError:
        continue    