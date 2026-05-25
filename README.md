# Tetragon — eBPF observability & event correlation

<aside>
<img src="i" alt="i" width="40px" />

Demo project: Linux behavior observability (eBPF) with correlation across network ↔ processes ↔ files, plus automated file-integrity assessment.

</aside>

## Goal

I built security telemetry on top of **Tetragon (eBPF)** that:

- captures kernel-level events related to **network connections**, **process execution**, and **file activity**,
- enriches them with process context (PID/binary) and file metadata,
- then **merges** everything into clear, structured logs mapping: **who (process)** → **where (IP:port)** → **which binary (integrity signals)**.

## Scope & architecture

The solution has two layers:

1. **Tetragon policies** (kernel event collection)
2. **Analytical script** (normalization, enrichment, and correlation)

### Phase 1 — Network policy

**What I monitor:**

- `tcp_v4_connect` and `tcp_v6_connect` (TCP connection attempts)
- `tcp_close` with `matchAction: Post` (connection close)

**What I extract:**

- `saddr`, `sport`, `daddr`, `dport`
- process context: `pid`, `binary`

### Phase 2 — Process policy

**What I monitor:**

- `do_open_execat` and the `begin_new_exec` execution path
- additionally, exec events with `matchAction: Post` to reliably observe the “new process image”

**Goal:** reliably capture when and what program was executed, so it can be correlated with network activity.

### Phase 3 — File integrity policy

**What I monitor:**

- `fd_install` with `matchAction: Post`
- a **Prefix** filter for selected installation paths

**Goal:** detect and record artifacts that appear in important locations (e.g., binaries, libraries, executable files).

## Analytical script — what I do with the data

The script processes the event stream and performs:

### 1) File verification (for every observed file)

- **Hash**: compute and validate the checksum
- **Signed**: check whether the artifact is digitally signed (verification logic depends on the target environment)
- **Exec stack**: detect the executable-stack flag
- **Path**: validate the file location against trusted directories

### 2) Network event analysis

- normalize `saddr/daddr` and `sport/dport`
- bind each connection to process context (`pid`, `binary`)

### 3) Correlation & final log generation

I merge file-integrity information with runtime activity and generate logs that unambiguously show:

- network parameters (IP/port)
- the responsible process (PID/binary)
- verification results (hash/signature/exec-stack/path)

In practice, the script uses conditional logic (e.g., `elif`) to classify events and produce a readable report.

## Outcome

The result is a mechanism that:

- maps **network connections to specific processes**,
- adds a trust assessment for binaries (**integrity / signature / exec-stack / path**),
- enables fast triage of anomalies such as:
    - unusual outbound connections from suspicious binaries,
    - execution of new processes from unexpected paths,
    - appearance of files in critical directories.

## Tech stack

- Linux
- eBPF
- Tetragon
- analysis script (correlation and enrichment logic)