# Tetragon

Tetragon is a system to observe and analyze Linux system behavior layered security mechanisms.

## Phase 1: Policy 1 (Network)

## Phase 2: Policy 2 (Processes)
(comming soon) Detection of changes based on the baseline behavior.

## Phase 3: Policy 3 (File Integrity)
(comming soon) Security rules applied at kernel level.

## Analytical Script Functionality
The script processes data from the above policies and performs the following operations:

*File Verification: For every file(not just the connection), the script checks:
     *Hash: Verification of the file's checksum.
     *Signed: Checking if the file is digitally signed.
     *Has exec stack: Checking if the file has an executable stack flag.
     *Path: Verification of the file path.

*Network Log analysis: Organizes data regarding:
     *Addresses and ports: saddr, daddr, sport, dport.
     *Process context: binary, pid.
## Outcome
The system merges file integrity information with system activity. Using elif conditional statesments, the script generaates organized logs that map network parameters (IPs, ports) to specific processes(PID,binary name) along with their verification results (hash, signature, stack status)
