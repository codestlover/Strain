# Strain

[![Crystal](https://img.shields.io/badge/Crystal-%3E%3D%201.10.0-000000?logo=crystal)](https://crystal-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Status: Research PoC](https://img.shields.io/badge/Status-Research%20PoC-orange.svg)](#scope-and-version-compatibility)

**A research proof of concept for availability weaknesses in the SCP: Secret Laboratory server pre-authentication and query pipelines.**

Strain is written in Crystal and examines connection-request handling, signature pre-verification behavior under load, and Steam A2S query responsiveness. It is a research artifact, not a production monitoring tool or a claim of authentication bypass.

> **Educational and authorized research only.** Some modes intentionally generate disruptive traffic and can deny service, prevent new connections, or leave a server requiring a restart. Use only in an isolated lab on systems you own or have explicit written permission to test. Do not target public or third-party servers without authorization.

## Scope and version compatibility

Strain was originally developed against a legacy SCP:SL server version. The underlying findings remain relevant to newer versions as well.

Version-specific behavior depends on protocol layouts, server configuration, transport changes, and deployed mitigations. This repository does not maintain a release-by-release compatibility matrix; relevance to newer versions does not imply that every release is affected.

The published packet fixture is anonymized: the captured account identifier and signature bytes have been replaced with placeholders. Its protocol layout and the original research comments must be checked against the server build being studied. Successful compilation alone does not establish server compatibility.

## Research scenarios

| Mode | Focus |
| --- | --- |
| `probe` | A single mutated connection request; classify the response and measure round-trip time. |
| `eclipse` | Observe pre-verification response changes before, during, and after load. This is **not** an authentication bypass. |
| `cascade` | Study connection-request backlog growth and delayed recovery of the join pipeline. |
| `mirage` | Study Steam A2S challenge-cache behavior and query-response degradation. |
| `sweep` | Run the three load scenarios sequentially. Recovery may require a server restart. |

These are client-side observations and heuristic classifications. A timeout or a `REPRODUCED` label is not conclusive evidence of a specific server-side flaw: corroborate results with server logs, resource metrics, and the relevant server implementation. Source-code line references in comments belong to the original research build, not all releases.

## Build

Requirements:

- Crystal **1.10.0 or later**, as declared in `shard.yml`.
- Linux for the platform-specific raw-socket functionality; other platforms are not verified.
- No external Crystal shards are declared.

```sh
git clone https://github.com/codestlover/Strain.git
cd Strain
mkdir -p bin
crystal build src/strain.cr -o bin/strain
```

Inspect the interface without sending network traffic:

```sh
./bin/strain --help
./bin/strain --version
```

The binary is built locally and is intentionally not included in the repository.

Publication checks passed on Linux with Crystal **1.21.0**: compilation, `--help`, and `--version`. This compiler emits deprecation warnings for `Time.monotonic`; no live server or load scenarios were executed during these checks.

## Authorized lab use

Before any network test, obtain permission, isolate the environment, agree on resource limits and stop conditions, and prepare a recovery plan. Do not run disruptive modes against production infrastructure.

A single-request example for an **owned local lab server**:

```sh
./bin/strain probe --target 127.0.0.1:7777
```

This still sends a deliberately invalid request. A silent response can reflect a closed port, filtering, rate limiting, incompatible protocol data, or server behavior; it is not by itself proof of vulnerability.

### Exit codes

- `0`: the probe command completed, or a load scenario reported reproduction. In `sweep`, all three scenarios must report reproduction.
- `1`: a load scenario did not report reproduction, or `sweep` did not reproduce all three.
- `2`: a handled argument, configuration, or I/O error. Some unhandled exceptions may use other exit codes.

A successful exit status is not a security certification. In particular, `probe` can finish successfully even when its response is silent or records an I/O error.

## Repository layout

```text
Strain/
├── src/
│   ├── strain.cr             # Command-line entry point
│   └── strain/
│       ├── methods/          # Research scenarios
│       ├── packet.cr         # Anonymized packet fixture
│       ├── probe.cr          # Response classification
│       ├── raw_udp.cr        # Platform-specific transport helpers
│       ├── socks5.cr         # SOCKS5 UDP transport support
│       └── target.cr         # Target endpoint parsing
├── shard.yml
├── .gitignore
├── LICENSE
└── README.md
```

No captured traffic, proxy lists, credentials, dependency directories, or prebuilt binaries are included.

## Defensive considerations

Server-side mitigations to investigate include bounded pre-authentication queues and challenge caches, admission-time rate limits, predictable verification behavior under load, and cleanup work that cannot grow without bound per incoming request. Monitor queue depth, CPU and memory pressure, dropped UDP packets, join latency, and query latency. Keep the server and its networking components up to date. These are general defensive considerations, not a verified patch for a particular release.

## Disclaimer

This project is published solely for educational purposes, security research, and authorized testing. The authors and contributors do not endorse illegal activity or unauthorized interference with any system. The software and documentation are provided **“AS IS”**, without any express or implied warranty. To the maximum extent permitted by applicable law, the authors, contributors, and copyright holders accept no liability for any claims, damages, losses, service interruptions, or other consequences arising from use, misuse, or inability to use this project. Users are solely responsible for obtaining authorization, complying with applicable laws and service terms, and all actions performed with this software. This notice does not grant permission to test third-party systems and does not waive liabilities that cannot legally be excluded.

Strain is an independent project and is not affiliated with or endorsed by Northwood Studios, SCP: Secret Laboratory, or Valve.

## Author

Created and maintained by [codestlover](https://github.com/codestlover).

## License

Released under the [MIT License](LICENSE).
