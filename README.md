Custom Multi-Threaded EDR Platform (Tetragon eBPF + Python Daemon)

An advanced proprietary Endpoint Detection and Response (EDR) system. The application monitors OS kernel activity in real time via eBPF, analyzes executed binaries using native GNU utilities, and exports live security metrics to Prometheus.

CRITICAL WARNING: Self-Defense Mechanism & PID Loop

The system implements a proprietary self-defense technology engineered directly into the Python daemon. Its primary purpose is to protect the EDR from being maliciously terminated (e.g., by malware evasion techniques).

The "Ghost PID" Phenomenon

The Issue: If you attempt to initialize the daemon without a valid prometheus.yml file, the consumer thread will throw a critical configuration exception. Our custom supervisor immediately triggers a sub-millisecond crash-loop respawn procedure via double-forking.

The Consequence: The process evades termination by changing its PID so rapidly that traditional user-space tools (like kill -9) become completely ineffective. Intercepting the process via terminal becomes impossible, which might ultimately force a hard hardware reset (pulling the power plug).

How to Safely Manage the Process

Pre-requisite: Always ensure that prometheus.yml is present in the project's root directory before any execution attempts.

Proper Shutdown: The system deliberately ignores standard termination signals from the terminal. To safely stop the EDR and unmount the eBPF tracing policies, the built-in control flag must be used: sudo python3 genius_analysis.py.

Architecture & Core Technologies

The system is designed for maximum throughput and zero packet drop, leveraging an asynchronous multi-threaded architecture in Python.

Kernel Core: Cilium Tetragon (v1.7.0+)
The EDR bypasses user-space polling by hooking directly into the Linux Kernel using eBPF (extended Berkeley Filter) technology. TracingPolicies filter system events at the source, delivering a clean stream of security-relevant logs (such as memory and privilege escalation).

Producer-Consumer Pattern (threading + queue)
To prevent log dropped events during massive system activity spikes (bursts):

Producer Thread: Solely responsible for rapidly reading the raw stream from Tetragon and pushing it into a thread-safe FIFO queue.

Consumer Thread: Pulls data chunks from the queue, decodes them, and passes them to heavy analytics, completely offloading the listener thread.

Ultra-Fast Parsing: orjson
Instead of using the standard Python JSON library, the system processes data using orjson (a blazing-fast, Rust-based JSON parser). This allows the application to handle tens of thousands of kernel events per second with minimal CPU and RAM overhead.

GNU Tools & Cryptography: ELF Executable SHA Hex Analysis
Upon detecting a new file execution event (ELF format), the system extracts its structure, HEX headers, and section details using native GNU binary utilities. Concurrently, cryptographic SHA checksums are generated via optimized system-level utilities to match signature databases. Relying on the native GNU toolchain guarantees maximum stability, low footprint, and compatibility across Linux environments without requiring external GPU hardware dependencies.

Telemetry: Prometheus Metrics
All classified anomalies and internal EDR performance metrics are aggregated and exposed on a dedicated server port, fully compatible with the Prometheus monitoring ecosystem. Prometheus communicates using encrypted TLS (Transport Layer Security) to ensure the confidentiality and integrity of transmitted data.

Tracing Policies

Phase 1 — Network policy: Monitors tcp_v4_connect and tcp_v6_connect (TCP connection attempts) and tcp_close with matchAction: Post (connection close). Extracts saddr, sport, daddr, dport, and process context (pid, binary).

Phase 2 — Process policy: Monitors do_open_execat and the begin_new_exec execution path, additionally observing exec events with matchAction: Post to reliably observe the “new process image.” The goal is to reliably capture when and what program was executed for correlation with network activity.

Phase 3 — File integrity policy: Monitors fd_install with matchAction: Post and a prefix filter for selected installation paths. The goal is to detect and record artifacts that appear in important locations (e.g., binaries, libraries, executable files).

Tech stack

Linux Arch

Kernel 7.0+

eBPF

Tetragon v1.7.0+

Analysis script (Python 3.14.5)

Sources:
Custom Multi-Threaded EDR Platform (Tetragon eBPF + Python Daemon) project description provided in the user prompt.
