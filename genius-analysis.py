import json
import sys
import hashlib
import queue
import threading
import time
import orjson
import logging
import argparse
from typing import Dict, Any, NoReturn
from elftools.elf.elffile import ELFFile
from elftools.elf.segments import Segment
from pathlib import Path
from prometheus_client import start_http_server, Counter




EDR_EVENTS_COUNTER = Counter(
    'edr_behavioral_anomalies_total',
    'Total behavioral anomalies detected via eBPF'
    ['process_name', 'status', 'anomaly_type']
)

log_queue: queue.Queue = queue.Queue(maxsize=10000)

PF_X: Final[int] = 0x1


def load_baseline():
    try:
       """ with open("baseline.yaml", "r") as f:
            config = yaml.safe_load(f)
            wynik = {
                good_paths: set(config.get("known_good_paths", []))
                good_ips: set(config.get("known_good_ips", []))
                bad_paths: set(config.get("known_bad_paths", []))
            }
            return wynik
    except FileNotFoundError:
        logging.warning("baseline.yaml not found! Running with empty profiles.")
        return {"good_paths": set(),"good_ips": set(), "bad_paths": set()}

        BASELINE = load_baseline()
        KNOWN_GOOD_PATHS = BASELINE["good_paths"]
        KNOWN_GOOD_IPS = BASELINE["good_ips"] 
        KNOWN_BAD_PATHS = BASELINE["bad_paths"]"""

def setup_infrastructure( args_list: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Parser logow Tetragonz eksportem Prometeusa")

    parser.add_argument("-f", "--file", type=str, default="/var/log/tetragon/tetragon.log", help="Sciezka do plikow logow Tetragon")

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

    def sprawdz_binarke_elf(sciezka fizyczna: Path) -> tuple[str, str, str, bool, bool, bool]:
        """
        Funkcja pomocnicza. Otwiera plik na dysku hosta, oblicza sumy kontrolne oraz sprawdza naglowki elf (szukajac podatnosci GNU-stack).
        Zwraca bezpieczny slownik z surowymi danymi.
        """
        md5_h, sha1_h, sha256_h = "", "", ""
        elf_poprawny, gnu_stack_obecny, gnu_stack_wykonywalny = False, False, False 
   

        try:
           md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()
           with open(sciezka_fizyczna, "rb") as f:
               while chunk := f.read(4096):
                   md5.update(chunk)
                   sha1.update(chunk)
                   sha256.update(chunk)
           md5_h, sha1_h, sha256_h = md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()
        except IOError:
        logger.debug(f"Brak mozliwosci odczytu hashow z pliku {sciezka_na_hoscie}: {e}")
        return md5_h, sha1_h, sha256_h, elf_poprawny, gnu_stack_obecny, gnu_stack_wykonywalny

        try:
            with open(sciezka_na_hoscie, "rb") as f:
            elf = ELFFile(f)
            elf_poprawny = True
            for segment in elf.iter_segments():
                gnu_stack_obecny = True
                flags: int = segment.header.get("p_flags", 0)
                gnu_stack_wykonywalny = bool(flags & PF_X)

        except Exception as e:
            logger.debug(f"Plik {sciezka__fizyczna} nie jest poprawnym formatemELF lub jest uszkodzony: {e}")
            elf_poprawny = False
        return md5_h, sha1_h, sha256_h elf_poprawny, gnu_stack_obecny, gnu_stack_wykonywalny
    

class TetragonWorker(threading.Thread):
    def __init__(
        self,
        worker_id: int,
        event.queue: queue.Queue[bytes],
        shutdown_event: threading.Event,
        cfg: TetragonConfig
    ) -> None:
        super().__init__(name=f"Worker-{worker_id}", daemon=True)
        self.queue: queue.Queue[bytes] = event_queue
        self.shutdown_event: threading.Event = shutdown_event
        self.cfg: TetragonConfig = cfg

    def run(self) -> None:
        while not self.shutdown_event.is_set() or not self.queue.empty():
            try:
                raw_event = self_queue.get(timeout=0.5)
                try:
                    self._process_event(raw_event)
                except Exception as e:
                    logger.error(f"Blad parsowania: {e}", exc_info=True)
                finally:
                    self.queue.task_done()
            except queue.Empty:
                continue   

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

             wewnetrzna_sciezka_pliku: str = process.get("binary", "")
             pid_hosta: int = process.get("pid", 0)
             uid_uzytkownika: int = process.get("uid", 0)
             argumenty_procesu: str = process.get("arguments", "")
             exec_id: str = process.get("exec_id", "")
             id_kontenera: str = process.get("container_id", "") or proces.get("docker", "")

             sciezka_rodzica: str = parent.get("binary", "")
             pid_rodzica: int = parent.get("pid", 0)                

             pid_hosta: int = process.get("pid", 0)
             nazwa_poda: str = pod.get("name", "")
             namespace_poda: str = pod.get("namespace", "")
             czy_to_pod = bool = bool("nazwa_poda")
             policy_name = event_data.get("policy_name")

             sciezka_fizyczna_str: str = (
                 f"/proc/{pid_hosta}/root{wewnetrzna_sciezka_pliku}"
                 if czy_to_pod and pid_hosta > 0
                 else wewnetrzna_sciezka_pliku
             )
                
             kprobe = event_data.get("process_kprobe",{})
             process = kprobe.get("process", {})

             nazwa_procesu = process.get("binary", {})
             typ_akcji = kprobe.get("function_name", {})

             docelowe_ip = kprobe.get("args", [{}])[0].get("string_arg", None) if "args" in kprobe else None

             sciezka_pliku = event_data.get("process_exec", {}).get("process", {}).get("path", None)
             k8s_info = event_data.get("kubernetes", {})
             pod_name = k8s_info.get("pod_name", "native_host")
             name_space = k8s_info.get("namespace", "none")






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

             weryfikowany_plik_path  = Path(sciezka_fizyczna_str)

             if wewnetrzna_sciezka_pliku and weryfikowany_plik_path.exists():
                skrot_md5, skrot_sha1, skrot_sha256, czy_elf, czy_jest_stack, czy_stack_exec = sprawdz_binarke_elf(weryfikowany_plik_path)
             else:
                 skrot_md5, skrot_sha1, skrot_sha256, czy_elf, czy_jest_stack, czy_stack_exex = "", "", "", False, False, False
   
             etykieta_miejsca: str = f"Pod: [{namespace_poda}/{nazwa_poda}]" if czy_to_pod else "System: [Host]"

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
                log_message = f"ACTION: {func} in process {event.get('process_kprobe', {}).get('process', {}).get('binary, 'unknown')}"

            logging.info(log_message)

            elif "process_exec" in event:
                proc = event.get("process_exec", {}).get("process")
                log_message = f"START: {proc['binary']} (PID: {proc['pid']})"
            elif "process_exit" in event:
                pe = event["process_exit"]["process"]
                log_message = f"THE END: {pe['binary']}"
            else:
                pass


            elif docelowe_ip not in KNOWN_GOOD_IPS:
                name = "untrusted_network_egress"
                EDR_EVENTS_COUNTER.labels(process_name=process, status="anomaly", rule_name=name).inc()

            elif sciezka_pliku not in KNOWN_GOOD_PATHS::
                name = "untrusted_file_write"
                EDR_EVENTS_COUNTER.labels(process_name=process, status="anomaly", rule_name=name).inc()

            else:
                name = "normal"

            if pod_name != "native_host":
                log_message = f"ACTION {name} on process {nazwa_procesu} INSIDE POD {pod_name} (Namespace: {namespace})"

            else:
                log_message = f"ACTION {name} on process {nazwa_procesu} on HOST"




            if not wewnetrzna_sciezka_pliku:
                log_queue.task_done()
                continue

            if wewnetrzna_sciezka_pliku and not skrot_sha256:
                log.warning(f"[{etykieta_miejsca}] Plik zniknal przed wykonaniem analizy: {wewnetrzna_sciezka_pliku}")
                log.queue.task_done()
                continue

            if skrot_sha256:
                logger.info(f"[{etykieta_miejsca}] Przetworzono uruchomienie: {wewnetrzna_sciezka_pliku} (SHA-256: {skrot_sha256})

            if not czy_elf:
                logger.info(f"[{etykieta_miejsca}] Pomijanie analizy naglowkow: {wewnetrzna_sciezka_pliku} to nie jest plik ELF (np. skrypt).")

            if czy_elf and not czy_jest_stack:
                logger.warning(f"[{etykieta_miejsca}] BEZPIECZENSTWO: Plik {wewnetrzna_sciezka_pliku} nie posiada naglowka PT_GNU_STACK!")

            if czy_jest_stack and czy_stack_exec:
                logger.critical(
                    f"ALARM PODATNOSCI [{etykieta_miejsca}]! Uruchomiono plik {wewnetrzna_sciezka_pliku} "
                    f"z WYKONYWALNYM stosem (Brak ochrony NX/DEP)! ID Kontenera: {id_kontenera if czy_to_pod else 'N/A'}"
                )

            if czy_jest_stack and not czy_stack_exec:
                logger.info(f"[{etykieta_miejsca}] Ochrona jadra aktywna. Stos binaru {wewnetrzna_sciezka_pliku} jest niewykonywalny.")

            if conn_data:
                if daddr in self.cfg.blacklist_daddr:
                    logger.error(f"[BLACKLIST MATCH] {proc_name} -> {daddr}:{dport}")
                    return

                if uid == 0 and proc_name not in self.cfg.allowed_root_binaries:
                    logger.warning(f"[UNAUTHORIZED ROOT CONNECT] {proc_name} jako ROOT -> {daddr}:{dport}

                logger.info(f"[TCP CONNECT] {proc_name} | {saddr}:{sport}")
                return

            if send_data or recv_data:
                if bytes_sent == 0:
                    return

                if bytes_sent > self.cfg.max_bytes:
                    logger.error(f"[LIMIT EXCEEDED] {proc_name} przeslal {bytes_sent} do {daddr}:{dport}")

                direction = "OUTPUT" if send_data else "INPUT"
                logger.info(f"[TCP CLOSE] {proc_name} | {saddr}:{sport} -> {daddr}:{dport}")
                return

            if policy_name:
                if policy_name == "block-network-egress":
                    logger.warning(f"[POLICY BLOCKED] {proc_name} (UID: {uid}) zatrzymany przez {policy_name}")

                if policy_name == "monitor-etc-dir":
                    logger.info(f"[POLICY MATCH] Dostep do katalogu /etc/ w ramach {policy_name}")
                return 

        except Exception as e:
            logger.error(f"Blad krytyczny podczas przetwarzania elementu z kolejki: {e}", exec_info = True)


            analyze_tetragon_event(event)
            EVENT_QUEUE.task_done()
        except Exception as e:
            logging.error(f"Worker encountered an error during analysis: {e}")
            EVENT_QUEUE.task.done()
            continue




def run_pipeline(stream: TextIO) -> NoReturn:
    logging.info("Spawing 4 worker threads for deep telemetry analysis..."
    
    for i in range(4):
        t = threading.Thread(target=worker_consumer, 
        t.daemon=True)
        t.start()
    logging.info("EDR Master Pipeline is listening to live Tetragon stream...")

    paczka_surowych_logow: list[bytes] = [
        b'{"process_exec":{proces":{binary":"/bin/ls","pid":1234}}}
        b'{"process_exec":{process":{binary:"/app/backend""pid":5678,"container_id":"cri-o://xyz","pod":"name":"api-pod","namespace":"prod"}}}}'

    logger.info("Oczekiwanie na zakonczeniezadan przez watki (log_queue.join...")
    log.queue.join()


    for line in stream:
        try:
            clean_line = line.strip()
            if not clean_line:
                continue

            event = orjson.loads(clean_line)

            binary_path = event.get("process_kprobe", {}).get("process", {}).get("binary", "")

            if binary_path in KNOWN_BAD_PATHS:
                logging.critical(f"CRITICAL ALERT: Backlistedbinary blocked instantly!
                EDR_EVENTS_COUNTER.labels(process_name=binary_path, status="anomaly", anomaly_type="critical_blacklist").inc()
                continue
            
            EVENT_QUEUE.put(event, block=False)

        



        except orjson.JSONDecodeError:
            logging.error("Failsafe: orjsonfailed to decode malformed line.")
            continue
        except queue.Full:
            logging.critical("Queue overflow! Dropping events to protect Linux RAM."
        except Exception as e:
            logging.error(f"Unexpected crash in master tread loop: {e}")    

if __name__ == "__main__":
    try:
        start_http_server(8000)
        logging.info("Prometheus telemetry endpoint exposed on http://localhost:8000/metrics")

        run_pipeline(sys.stdin)

    except KeyboardInterrupt:
        logging.info("EDR Engine shutdown requested by user.")
        sys.exit(0)
    except Exception as startup_error:
        logging.critical(f"Fatal system failure during initialization: {startup_error}")
        sys.exit(1)
