# Incident Report: Suspicious Windows Artifacts & Masqerading Analysis

## TL;DR

A forensic-style analysis of a Windows system identified multiple suspicious artifacts, including:

- a binary masqerading as JetBrains ('WebStorm-2025.3.3.exe')
- an unsigned MSI installer ('33falc.msi')
- a suspicious DLL('WinStore.App.dll')

The artifacts exhibited PE header incosistencies, missing digital signatures, and forgedor misleading publisher metadata.

Additional indicators included SID 500 (built-in Administrator) related activity, Recycle Bin remnats, and uniform timestamp patterns across files.

The ananlysis suggest a high-confidence case of software masquerading and staged artifact deployment.

---

## Analysis Environment

The investigation was performed using an Arch Linux Live USB environment with read-only access to the target Windows filesystem.

This ensured:
- no modification of the original system
- forensic integrity preservation
- isolated offline analysis

---

## Key Findings

### 1. Masquerading Binary(WebStorm impersonation)

A binary was identified impersonating JetBrains WebStorm ('WebStorm-2025.3.3.exe')

- Architecture: 32-bit (Intel i386)
- PE sections: 5 
- No valid digital signature
- Inconsistent publisher metadata

The structure is not consistent with legitimate WebStorm builds.

---

### 2. Unsigned MSI installer ('33falc.msi')

- No digital signature
- Unknown origin 
- No public OSINT references
- No clear installation trace in sytem logs

Likely used as a delivery mechanism for additional artifacts.

---

### 3. Supicious DLL ('WinStore.App.dll')

- name mimics legitimate Windows component
- No valid Microsoft signature
- Metadata inconsistencies

Suggest potencial masqerading as system component.

---

### 4. PE Header Anomalies

Observed incosistencies across binaries:
- 32-bit architecture (i386) in unexpected context
- simplified PE structure (5 sections)
- metadata mismach (publisher/version fields)

---

### 5. Timestamp Consistency 

All analyzed artifacts shared identical or near-identical timestamps.

- single-day clustering of file creation/modification
- no incremental or staged variation

This pattern may indicate batch deployment or coordinated file introduction.

---

### 6. Recycle Bin Artifacts (SID 500)

Artifacts in Recycle Bin were associated with SID 500(built-in Administrator account).

Some entries appeared corrupted or partially unreadable, limiting reconstruction.

---

## Runtime Observability

Runtime visibility (via eBPF-based tooling such as Tetragon) inidicated execution-related activity not fullyreflected in system logs, suggesting limited logging coverage bor stealth behavior.

---

## Root Cause (Hypothesis)

The most likely scenario involves execution of an unsigned MSI package ('33falc.msi') that deployed a binary masquerading as JetBrains WebStorm.

The binary exhibited:
- PE header inconsistencies
- forged publisher metadata
- lack of valid digital signature

Additional artifacts (DLL masquerading, SID 500 activity, timestamp clustering, and Recycle Bin remnants) suggest privileged execution and possible staged deployment.

Due to limited logging and lack of memory analysis, this remains a high-confidence hypothesis rather than confirmed attribution.

---

## Prevention

- enforce signed  binaries only (WDAC / AppLocker)
- monitor MSI installation events
- detect unsigned or unknown installers
- correlate AV allerts with system logs
- improve centralized logging (SIEM)
- enhance runtime visibility (eBPF-based tooling)

---

## Summary 

This invesigation demostrates a multi-layer analysis approach combining:

- static artifact inspection (PE / MSI / DLL)
- forensic environment isolation (Live USB, read-only)
- runtime observability correlation
- manual hypothesis-driven analysis

The result is a structured incidend analysis of suspected software masqerading and staged artifact deployment.
