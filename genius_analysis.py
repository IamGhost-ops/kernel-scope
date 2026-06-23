import sys
import hashlib
import queue
import threading
import time
import orjson
import logging as log
import argparse
import yaml
from typing import Dict, Any, NoReturn
from elftools.elf.elffile import ELFFile
from elftools.elf.segments import Segment
from pathlib import Path
from prometheus_client import start_http_server, Counter




EDR_EVENTS_COUNTER = Counter(
    'edr_behavioral_anomalies_total',
    'Total behavioral anomalies detected via eBPF',
    ['process_name', 'status', 'anomaly_type']
)

KNOWN_GOOD_PATHS = {"192.168.1.10", "127.0.0.1"}
KNOWN_GOOD_IPS = {"/api/v1/login", "/api/v1/dashboard"}
KNOWN_BAD_PATHS = {"/etc/passwd", "/.env", "/wp/admin"}

EVENT_QUEUE: queue.Queue = queue.Queue(maxsize=10000)

PF_X: Final[int] = 0x1


def setup_infrastructure(args_list: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Tetragon log parser with Prometeus export")

    parser.add_argument("-f", "--file", type=str, default="/var/log/tetragon/tetragon.log", help="Tetragon log file path")

    parser.add_argument("-p", "--port", type=int, default=int(os.getenv("PROMETHEUS_METRICS_PORT", 8000)), help="Port to expose Prometheusmetrics (default: 8000)")

    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging level for deep troubelshooting")
    args: argparse.Namespace = parser.parse.args(args_list)

       
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        handlers=[logging.StreamHandler(sys.stderr)]
    )
    
    return args

class TetragonParser:

    def check_elf_binary(physical_path: Path) -> tuple[str, str, str, bool, bool, bool]:
        """
        Funkcja pomocnicza. Otwiera plik na dysku hosta, oblicza sumy kontrolne oraz sprawdza naglowki elf (szukajac podatnosci GNU-stack).
        Zwraca bezpieczny slownik z surowymi danymi.
        """
        md5_h, sha1_h, sha256_h = "", "", ""
        valid_elf, gnu_stack_present, gnu_stack_executable = False, False, False 
   

        try:
            md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
            with open(physical_path, "rb") as f:
                while chunk := f.read(4096):
                    md5.update(chunk)
                    sha1.update(chunk)
                    sha256.update(chunk)
            md5_h, sha1_h, sha256_h = md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()
        except IOError:
            log.debug(f"Unable to read hashes from file {host_path}: {e}")
        return md5_h, sha1_h, sha256_h, valid_elf, gnu_stack_present, gnu_stack_executable

        try:
            with open(host_path, "rb") as f:
                elf = ELFFile(f)
                valid_elf = True
            for segment in elf.iter_segments():
                gnu_stack_present = True
                flags: int = segment.header.get("p_flags", 0)
                gnu_stack_executable = bool(flags & PF_X)

        except Exception as e:
            log.debug(f"File {physical_path} is not a valid ELF format or is corrupted: {e}")
            valid_elf = False
        return md5_h, sha1_h, sha256_h, valid_elf, gnu_stack_present, gnu_stack_executable
    

class TetragonWorker(threading.Thread):   

    def process_event(self, raw_event: bytes) -> None:
        if not raw_event:
            return

        try:
            event_data: Dict[str, Any] = orjson.loads(raw_event)
        except orjson.JSONDecodeError:
            return

            event = event_data.get("process_exec") or log.get("process_kprobe") or {}
            process = event_data.get("process", {})
            pod = process.get("pod", {})
            parent = process.get("parent", {})

            internal_file_path: str = process.get("binary", "")
            host_pid: int = process.get("pid", 0)
            user_uid: int = process.get("uid", 0)
            process_args: str = process.get("arguments", "")
            exec_id: str = process.get("exec_id", "")
            container_id: str = process.get("container_id", "") or proces.get("docker", "")

            parent_path: str = parent.get("binary", "")
            parent_pid: int = parent.get("pid", 0)                

            pod_namespace: str = pod.get("namespace", "")
            is_pod = bool = bool("pod_name")
            policy_name = event_data.get("policy_name")

            pod_name = k8s_info.get("pod_name", "native_host")
            name_space = k8s_info.get("namespace", "none")
            k8s_info = event_data.get("kubernetes", {})

            physical_path_str: str = (
                f"/proc/{host_pid}/root{internal_file_path}"
                if is_pod and host_pid > 0
                else internal_file_path
             )
                
            kprobe = event_data.get("process_kprobe",{})
            process = kprobe.get("process", {})

            process_name = process.get("binary", {})
            action_type = kprobe.get("function_name", {})

            destination_ip = kprobe.get("args", [{}])[0].get("string_arg", None) if "args" in kprobe else None

            file_path = event_data.get("process_exec", {}).get("process", {}).get("path", None)

            conn_data: Optional[Dict[str, Any]] = event_data.get("process_connect")
            send_data: Optional[Dict[str, Any]] = event_data.get("process_sendmsg")
            recv_data: Optional[Dict[str, Any]] = event_data.get("process_recvmsg")
            close_data: Optional[Dict[str, Any]] = event_data.get("process_close")

            net_ctx: Optional[Dict[str, Any]] = conn_data or send_data or recv_data or close_data    

            saddr: str = net_ctx.get("source_ip", "0.0.0.0") if net_ctx else "0.0.0.0"
            daddr: str = net_ctx.get("destination_ip", "0.0.0.0") if net_ctx else "0.0.0.0"
            sport: int  = net_ctx.get("source_port", 0) if net_ctx else 0
            dport: int = net_ctx.get("destination_port", 0) if net_ctx else 0
            bytes_sent: int = net_ctx.get("bytes", 0) if (send_data or recv_data) else 0

            hook_data: Optional[Dict[str, Any]] = event_data.get("kprobe") or event_data.get("fentry")
            func_name: Optional[str] = hook_data.get("function_name") if hook_data else None
            args: List[Dict[str, Any]] = hook_data.get("args")

            veryfied_file_path  = Path(physical_path_str)

            if internal_file_path and veryfied_file_path.exists():
                hash_md5, hash_sha1, hash_sha256, is_elf, has_stack, is_stack_exec = check_elf_binary(veryfied_file_path)
            else:
                 hash_md5, hash_sha1, hash_sha256, is_elf, has_stack, is_stack_exex = "", "", "", False, False, False
   
            location_label: str = f"Pod: [{pod_namespace}/{pod_name}]" if is_pod else "System: [Host]"

            proc_info: Dict[str, Any] = event_data.get("process", {}) if not net_ctx else net_ctx.get("process", {})
            pod_info: Dict[str, Any] = event_data.get("kubernetes", {}) if not net_ctx else net_ctx.get("kubernetes", {})

            fd_number: Optional[int] = None
            file_path: Optional[str]  = None

            for arg in args:
                if arg.get("index") == 0:
                   fd_number = arg.get("int arg")
                if arg.get("index") == 1 and (file_arg := arg.get("file_arg")):
                   file_path = file.arg.get("path")


            event = orjson.loads(line)
            function_name = event.get("process_kprobe", {}).get("function_name", {}) or \
            event.get("process_exec", {}).get("process", {}) or \
            event.get("process", {})
            path = event.get("fast_path")

                

            if "process_kprobe" in event:
                kp = event.get("process_kprobe")
                func = kp.get("function_name", "unknown")
                log_message = f"ACTION: {func} in process {event.get('process_kprobe', {}).get('process', {}).get('binary', 'unknown')}"



            elif "process_exec" in event:
                proc = event.get("process_exec", {}).get("process")
                log_message = f"START: {proc['binary']} (PID: {proc['pid']})"
            elif "process_exit" in event:
                pe = event["process_exit"]["process"]
                log_message = f"THE END: {pe['binary']}"
            else:
                pass


            if docelowe_ip not in KNOWN_GOOD_IPS:
                name = "untrusted_network_egress"
                EDR_EVENTS_COUNTER.labels(process_name=process, status="anomaly", rule_name=name).inc()

            elif sciezka_pliku not in KNOWN_GOOD_PATHS:
                name = "untrusted_file_write"
                EDR_EVENTS_COUNTER.labels(process_name=process, status="anomaly", rule_name=name).inc()

            else:
                name = "normal"

            if pod_name != "native_host":
                log_message = f"ACTION {name} on process {nazwa_procesu} INSIDE POD {pod_name} (Namespace: {namespace})"

            else:
                log_message = f"ACTION {name} on process {nazwa_procesu} on HOST"




            if not internal_file_path:
                pass

            elif internal_file_path and not hash_sha256:
                name = "untrusted_hash"
                EDR_EVENTS_COUNTER.labels(process_name=hash, status="anomaly", rule_name=name).inc()
                log.warning(f"[{location_label}] File disappeared before analysis could be performed: {internal_file_path}")
                pass

            elif hash_sha256:
                log.info(f"[{location_label}] Processed execution: {internal_file_path} (SHA-256: {hash_sha256})")

            elif not is_elf:
                log.info(f"[{location_label}] Skipping header analysis {internal_file_path} is not a valid ELF (np. script).")

            elif is_elf and not has_stack:
                name = "untrusted_header"
                EDR_EVENTS_COUNTER.labels(process_name=header, status="anomaly", rule_name=name).inc()
                log.warning(f"[{location_label}] SECURITY: File {internal_file_path} is missing PT_GNU_STACK header!")

            elif has_stack and is_stack_exec:
                name = "GNU_stack"
                EDR_EVENTS_COUNTER.labels(process_name=gnu_stack, status="anomaly", rule_name=name).inc()
                log.critical(f"VULNERABILITY ALERT: [{location_label}]! File {internal_file_path}  executed with an executable stack (Brak ochrony NX/DEP)! Container ID: {container_id if is_pod else 'N/A'}")

            if czy_jest_stack and not czy_stack_exec:
                log.info(f"[{location_label}] Ochrona jadra aktywna. Stos binaru {internal_file_path} jest niewykonywalny.")

            if conn_data:
                if daddr in self.cfg.blacklist_daddr:
                    name = "blacklist_daddr"
                    EDR_EVENTS_COUNTER.labels(process_name=daddr, status="anomaly", rule_name=name).inc()
                    log.error(f"[BLACKLIST MATCH] {proc_name} -> {daddr}:{dport}")
                    return

                if uid == 0 and proc_name not in self.cfg.allowed_root_binaries:
                    name = "untrasted_root_binaries"
                    EDR_EVENTS_COUNTER.labels(process_name=root, status="anomaly", rule_name=name).inc()
                    log.warning(f"[UNAUTHORIZED ROOT CONNECT] {proc_name} jako ROOT -> {daddr}:{dport}")

                log.info(f"[TCP CONNECT] {proc_name} | {saddr}:{sport}")
                return

            if send_data or recv_data:
                if bytes_sent == 0:
                    return

                if bytes_sent > self.cfg.max_bytes:
                    name = "untrusted_max_bytes"
                    EDR_EVENTS_COUNTER.labels(process_name=max_bytes, status="anomaly", rule_name=name).inc()
                    log.error(f"[LIMIT EXCEEDED] {proc_name} sent {bytes_sent} to {daddr}:{dport}")

                direction = "OUTPUT" if send_data else "INPUT"
                log.info(f"[TCP CLOSE] {proc_name} | {saddr}:{sport} -> {daddr}:{dport}")
                return

            if policy_name:
                if policy_name == "block-network-egress":
                    name = "policy_blocked"
                    EDR_EVENTS_COUNTER.labels(process_name=process, status="anomaly", rule_name=name).inc()
                    log.warning(f"[POLICY BLOCKED] {proc_name} (UID: {uid}) stopped by {policy_name}")

                if policy_name == "monitor-etc-dir":
                    log.info(f"[POLICY MATCH] Directory access to /etc/ as part of {policy_name}")
                return 

        except Exception as e:
            log.error(f"Critical error while processing a queue item: {e}", exec_info = True)


            analyze_tetragon_event(event)
            EVENT_QUEUE.task_done()
        except Exception as e:
            log.error(f"Worker encountered an error during analysis: {e}")
            EVENT_QUEUE.task.done()
            pass




def run_pipeline(stream: TextIO) -> NoReturn:
    log.info("Spawing 4 worker threads for deep telemetry analysis...")
    
    for i in range(4):
        t = TetragonWorker()
        t.daemon==True
        t.start()
    log.info("EDR Master Pipeline is listening to live Tetragon stream...")

    for line in stream:
        try:
            clean_line = line.strip()
            if not clean_line:
                continue

            event = orjson.loads(clean_line)

            binary_path = event.get("process_kprobe", {}).get("process", {}).get("binary", "")

            if binary_path in KNOWN_BAD_PATHS:
                log.critical(f"CRITICAL ALERT: Backlistedbinary blocked instantly!")
                EDR_EVENTS_COUNTER.labels(process_name=binary_path, status="anomaly", anomaly_type="critical_blacklist").inc()
                continue
            
            EVENT_QUEUE.put(event, block=False)

        



        except orjson.JSONDecodeError:
            log.error("Failsafe: orjsonfailed to decode malformed line.")
            continue
        except queue.Full:
            log.critical("Queue overflow! Dropping events to protect Linux RAM.")  
        except Exception as e:
            log.error(f"Unexpected crash in master tread loop: {e}")    

if __name__ == "__main__":
    try:
        start_http_server(8000)
        log.info("Prometheus telemetry endpoint exposed on http://localhost:8000/metrics")

        run_pipeline(sys.stdin)

    except KeyboardInterrupt:
        log.info("EDR Engine shutdown requested by user.")
        sys.exit(0)
    except Exception as startup_error:
        log.critical(f"Fatal system failure during initialization: {startup_error}")
        sys.exit(1)
