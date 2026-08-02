# Threat model

## Purpose

These tools make an AI-agent handoff narrower and more inspectable. They are
defence-in-depth for accidental disclosure, unsafe archive handling, ambiguous
inputs, and unsupported completion claims. They are not a sandbox or a security
certification.

The native Hermes plugin adds a controller-side workflow around these formats:
registered Git projects, explicit includes, clean-commit preparation, an
operator-review workflow, a fixed private return quarantine, and receipt
verification with a deterministic output manifest. It does not change the
fundamental trust model.

## Roles and trust boundaries

- **Controller:** chooses source files, task, packet digest, verification root,
  trusted public keys, and any command policy. It is trusted.
- **Transport:** may alter, replace, replay, truncate, or inspect a packet or
  receipt. It is untrusted.
- **Worker:** receives the packet and returns changes and a receipt. It may be
  buggy, compromised, or dishonest.
- **Verification workspace:** a controller-selected checkout or extracted result.
  Receipt content must never choose files outside this root.
- **Hermes plugin:** a convenience and policy boundary on the controller. It is
  trusted only for the checks it actually performs; it is not an OS or network
  enforcement layer.

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
- bypassing the plugin through a different Hermes tool, a manual transfer, or a
  compromised local process;

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
- Native Hermes preparation requires a registered Git project and explicit
  includes, rejects a dirty input commit, and requires every selected file to
  match a regular tracked blob at that exact commit.
- Native Hermes verification recomputes the exact returned file set and output
  manifest in a fixed private quarantine, copies the declared return into a
  controller-owned read-only snapshot, then performs a full evidence recheck
  there without executing worker-reported commands.
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
- Enforcing that every Hermes egress path, browser session, MCP server, or manual
  action passes through the plugin. The narrow delegation hook is only
  defense-in-depth and can be bypassed when the plugin is not loaded or another
  tool is used.

Use an OS/container sandbox, least-privilege credentials, an isolated checkout,
code review, and CI controls in addition to these tools.
