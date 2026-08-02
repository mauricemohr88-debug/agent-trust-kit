# Threat model

## Purpose

These tools make an AI-agent handoff narrower and more inspectable. They are
defence-in-depth for accidental disclosure, unsafe archive handling, ambiguous
inputs, and unsupported completion claims. They are not a sandbox or a security
certification.

## Roles and trust boundaries

- **Controller:** chooses source files, task, packet digest, verification root,
  trusted public keys, and any command policy. It is trusted.
- **Transport:** may alter, replace, replay, truncate, or inspect a packet or
  receipt. It is untrusted.
- **Worker:** receives the packet and returns changes and a receipt. It may be
  buggy, compromised, or dishonest.
- **Verification workspace:** a controller-selected checkout or extracted result.
  Receipt content must never choose files outside this root.

## Assets

- files and credentials that were not intentionally selected for the handoff;
- integrity and identity of the selected task and input archive;
- the controller workstation outside the verification workspace;
- clarity about which facts were worker-reported and which were independently
  rechecked.

## In-scope attacks

### Packet producer

- accidental inclusion of `.env`, key material, VCS metadata, private folders,
  dependencies, or common credential shapes;
- a selected symlink or special file escaping the source boundary;
- output accidentally overwriting existing work;
- local absolute paths leaking in transport metadata.

### Packet consumer

- absolute or traversal paths;
- duplicate or undeclared members;
- symbolic links, hard links, devices, FIFOs, and other special files;
- member-count, per-file, manifest, and total-size abuse;
- archive content that disagrees with its manifest.

### Receipt verifier

- a receipt rebinding relative evidence to an absolute controller path;
- a forged content checksum or unsupported evidence type;
- duplicate claim identifiers and ambiguous schemas;
- arbitrary commands or receipt-chosen working directories;
- replay against the wrong task, packet, input revision, or output set;
- a valid signature being misrepresented as proof that a claim is true.

## Security properties

- Packet paths are allowlisted and root-bound; links and special files are not
  transported.
- Secret detection is heuristic and blocks affected text files by default.
- Materialization is bounded, manually written into a fresh destination, and
  requires an exact manifest file set. Compressed bytes are copied and hashed once,
  then that private snapshot is decompressed under a total-byte limit and parsed;
  hidden tar extension metadata has its own pre-parse limits.
- A separately delivered SHA-256 digest detects archive replacement. A digest
  transported beside the archive through the same untrusted channel is not an
  authenticity control.
- Receipt paths are relative and rechecks use a controller-supplied root.
- Commands are never taken as executable authority merely because they appear in
  a receipt. Independent command rechecks require a controller-owned allowlist.
- An unkeyed content digest detects inconsistent or unrehashed receipt changes;
  an attacker controlling the whole receipt can replace the body and digest. An
  Ed25519 signature can attribute matching content to a trusted key; it does not
  establish truth, safety, freshness, or code quality.

## Non-goals and residual risks

- Finding every secret, especially novel formats, encoded data, binary files, or
  secrets split across files.
- Preventing a malicious agent from exploiting tools it is allowed to run.
- Making an allowlisted test command safe: test runners and build tools execute
  repository code.
- Malware detection, dependency analysis, data-loss prevention, remote
  attestation, timestamping, non-repudiation, compliance, or penetration testing.
- Protecting against a compromised controller, kernel, Python runtime, trusted
  key store, or a local attacker that can win filesystem races.
- Proving a worker actually performed a self-reported command.

Use an OS/container sandbox, least-privilege credentials, an isolated checkout,
code review, and CI controls in addition to these tools.
