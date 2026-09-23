---
template-version: 1
type: prd
topic: ebpf-five-tuple
id: ebpf-five-tuple
task: ""
status: draft
authors:
  - jibum.jung@gmail.com
created: 2026-09-23
last-updated: 2026-09-23
---

# PRD: 저부하 서버 5-tuple 수집 및 로컬 조회

## Background

서버 교체, IP 변경, 방화벽·ACL 정비 전에 해당 서버가 실제로 어떤 대상과 통신하는지 확인할 수 있어야 한다. 기존 로그나 방화벽 정책만으로는 서버 관점의 실제 통신 관계와 TCP 연결 발생 횟수를 정확히 파악하기 어렵다.

`net-scouter` 1차 버전은 설치된 Linux 서버에서 애플리케이션 payload 없이 L3/L4 통신 메타데이터를 관찰하고, 같은 통신을 중복 행으로 쌓지 않고 집계하여 로컬 명령으로 조회하게 한다. 관찰 기능의 장애나 지원하지 않는 패킷은 서버 트래픽 처리에 영향을 주지 않아야 한다.

## Goals

1. 설치 서버의 IPv4/IPv6 TCP·UDP 통신을 방향성 5-tuple 단위로 중복 제거하여 집계한다.
2. 각 flow의 최초·최종 관찰 시각, packet 수, byte 수를 기록한다.
3. TCP 3-way handshake가 완료되어 로컬 socket이 `TCP_ESTABLISHED` 상태로 전환된 횟수를 connection 수로 기록한다.
4. packet별 userspace 이벤트를 만들지 않고 bounded kernel map에서 집계하여 서버 성능 영향을 최소화한다.
5. CIDR 규칙으로 불필요한 flow를 결과에서 제외한다.
6. 같은 서버 내부 Docker container 또는 Kubernetes Pod 사이의 통신을 결과에서 제외하되, 외부와 container/Pod 사이의 통신은 유지한다.
7. 중앙 서비스 없이 설치 서버의 CLI에서 수집 결과와 agent 상태를 조회한다.
8. Rocky Linux 8.10 이상과 Ubuntu 22.04 이상을 지원한다.

## Non-Goals / Out of Scope

- packet payload, application message 또는 개인정보성 본문 수집
- packet drop, modify, redirect 또는 방화벽 enforcement
- 중앙 collector, 외부 API, 웹 콘솔 및 다중 서버 통합 조회
- 관찰 기간에 발생하지 않은 휴면·비정기 통신의 추론
- transit/router 역할로 단순 전달되는 TCP flow의 handshake 완료 횟수 계산
- 1차 버전에서의 process/PID 또는 개별 container/Pod identity 귀속
- ICMP/ICMPv6처럼 port가 없는 통신의 5-tuple 표현

## Flow Model

방향성 flow의 유일 키는 다음과 같다.

```text
family + protocol + direction + source IP + destination IP + source port + destination port
```

같은 키가 다시 관찰되면 새로운 행을 만들지 않고 다음 값을 갱신한다.

```text
firstSeen + lastSeen + packets + bytes + connections(TCP only)
```

`connections`는 로컬 TCP socket이 3-way handshake를 완료하고 `TCP_ESTABLISHED`로 전환된 횟수다. SYN 재전송과 완료되지 않은 handshake는 포함하지 않는다. UDP에는 connection 의미를 부여하지 않는다. 이 정의는 로컬 socket을 갖지 않는 transit TCP 통신에는 적용되지 않는다.

## Functional Requirements (FR)

- **FR-1 — 관찰 범위:** IPv4/IPv6의 TCP/UDP ingress와 egress flow를 수집한다.
- **FR-2 — 중복 집계:** 같은 방향성 5-tuple을 한 항목으로 병합하고 `packets`, `bytes`, `firstSeen`, `lastSeen`을 유지한다.
- **FR-3 — TCP connection 수:** `inet_sock_set_state`에서 로컬 TCP socket이 `TCP_ESTABLISHED`로 전환되는 이벤트를 5-tuple별로 집계한다.
- **FR-4 — 저부하 경로:** packet별 데이터를 userspace로 전달하지 않고 kernel map에서 먼저 집계한다. map 크기는 bounded여야 한다.
- **FR-5 — 안전성:** 모든 packet 관찰 경로는 fail-open이어야 하며 packet을 drop, modify 또는 redirect하지 않는다. payload는 읽거나 저장하지 않는다.
- **FR-6 — CIDR 제외:** 설정된 CIDR에 해당하는 불필요한 flow를 조회·보존 대상에서 제외할 수 있어야 한다. 정확한 규칙 형식과 적용 시점은 구현 전에 확정한다.
- **FR-7 — 동일 host workload 제외:** 기본적으로 선택한 uplink interface만 관찰하고 `lo`, `docker0`, CNI bridge, `veth*` 등 내부 virtual interface에는 attach하지 않는다. 추가로 source와 destination이 모두 해당 host의 workload CIDR에 포함되는 flow는 결과에서 제외한다. 한쪽 endpoint만 workload CIDR인 외부↔workload 통신은 유지한다.
- **FR-8 — 로컬 조회:** `net-scouter flows`로 집계 결과를 사람이 읽는 표 형태로 조회하고 machine-readable 출력도 제공한다.
- **FR-9 — 상태 조회:** `net-scouter status`로 실행 상태, attach 대상, 수집 기간, map 포화·누락 가능성과 마지막 오류를 확인할 수 있어야 한다.
- **FR-10 — 로컬 보존:** 재시작 뒤에도 결과를 조회할 수 있도록 로컬 durable storage가 필요하다. 저장 기술, flush 주기, 보존 기간과 디스크 상한은 별도 승인 전까지 미정이다.
- **FR-11 — 플랫폼:** Rocky Linux 8.10+와 Ubuntu 22.04+에서 build artifact 실행, verifier load 및 실제 수집 동작을 검증한다.
- **FR-12 — 종료 처리:** agent 종료 시 자신이 생성한 attach와 자원만 안전하게 정리하며 기존 qdisc/filter를 훼손하지 않는다.

## User Stories

- 서버 운영자로서 `net-scouter flows`를 실행해 이 서버와 실제 통신한 상대, protocol/port, 방향, packet·byte·TCP connection 수와 관찰 기간을 확인한다.
- 서버 운영자로서 CIDR 제외 설정을 적용해 관리망 등 분석에 필요 없는 통신을 결과에서 제거한다.
- Kubernetes 또는 Docker host 운영자로서 같은 host 내부 workload 간 통신은 숨기고 외부 dependency는 유지한다.
- 서버 운영자로서 `net-scouter status`를 실행해 수집기가 정상인지와 결과 누락 가능성이 있는지 판단한다.

## Acceptance Criteria

1. 동일 방향성 5-tuple의 반복 packet은 단일 flow로 조회되며 packet·byte 수가 누적된다.
2. IPv4/IPv6 TCP·UDP 각각에 대해 ingress/egress tuple과 port가 올바르게 표시된다.
3. 성공한 로컬 TCP handshake마다 `connections`가 한 번 증가하고 SYN 재전송 또는 실패한 handshake에는 증가하지 않는다.
4. UDP 결과에는 TCP connection 수가 적용되지 않는다.
5. 설정된 제외 CIDR에 해당하는 flow가 결과에서 보이지 않는다.
6. 같은 host의 container↔container 및 Pod↔Pod 통신은 결과에서 제외되고 외부↔container/Pod 통신은 유지된다.
7. `net-scouter flows`가 최소한 tuple, direction, first/last seen, packets, bytes, TCP connections를 출력한다.
8. `net-scouter status`가 실행·attach·수집 상태와 map 포화 또는 누락 가능성을 출력한다.
9. BPF 프로그램의 모든 분기에서 traffic을 허용하며 payload가 artifact, log 또는 로컬 저장소에 기록되지 않는다.
10. packet별 userspace event가 없고, 합의된 성능 시험에서 허용 기준을 충족한다. 구체적인 CPU/RSS/throughput/latency 기준은 승인 후 확정한다.
11. Rocky Linux 8.10+와 Ubuntu 22.04+의 실제 kernel test node에서 verifier load와 수집 통합 시험을 통과한다.
12. agent 재시작 후에도 이미 flush된 flow를 조회할 수 있다. 보존 정책은 별도 결정에 따른다.

## Current Implementation Status

현재 구현됨:

- TC ingress/egress observation-only classifier
- IPv4/IPv6 TCP·UDP parsing과 VLAN/IPv6 extension header 처리
- 방향성 5-tuple별 bounded LRU map 집계
- `firstSeen`, `lastSeen`, packet 및 byte counter
- `inet_sock_set_state` 기반 TCP connection counter와 Linux 4.18/5.15
  tracepoint ABI variant
- 항상 `TC_ACT_OK`를 반환하는 fail-open packet 경로
- Ubuntu build와 Rocky/Ubuntu 실제 kernel verifier 검증을 분리한 Make/Jenkins 기반

남은 1차 범위:

- Go eBPF loader의 tracefs format probe, 정확히 하나의 connection ABI variant
  명시적 attach, 기존 network 설정을 보존하는 attach/detach lifecycle
- kernel map snapshot 및 connection/packet 집계 병합
- CIDR와 동일 host workload traffic filtering
- 로컬 durable storage와 재시작 복구
- `flows`, machine-readable output, `status` CLI
- systemd 설치·실행 구성
- Rocky 8.10+ 및 Ubuntu 22.04+ 실제 kernel 통합·성능 시험

## Success Metrics

- 기능 acceptance criteria 전부 통과
- 지원하는 최소 OS/kernel baseline의 verifier 및 통합 시험 통과
- 수집으로 인한 packet drop/modify/redirect 0건
- payload 저장 0건
- 성능 기준은 baseline 대비 CPU, RSS, throughput 및 latency로 측정하되 수치 목표는 부하 시험 환경과 함께 별도 승인

## Dependencies / Constraints

- kernel은 TC classifier, LRU hash map, 요구 helper와 `sock:inet_sock_set_state` tracepoint를 제공해야 한다. 배포 전 capability를 실제 kernel에서 확인한다.
- build는 Ubuntu amd64에서 수행할 수 있지만 kernel acceptance는 Rocky와 Ubuntu 실제 kernel node에서 각각 검증한다.
- root 또는 제한된 Linux capability가 BPF load와 TC attach에 필요하다.
- eBPF object load/map access에는 `cilium/ebpf`, TC link 관리에는
  `vishvananda/netlink`, 설정 parsing에는 `gopkg.in/yaml.v3` 사용이 승인되었다.
  정확한 버전은 공식 호환성, 라이선스, Rocky 8.10 kernel baseline과 정적
  빌드 영향을 조사한 뒤 `go.mod`에 고정한다.
- local durable storage와 `bbolt` 도입은 여전히 미정이며 별도 승인이 필요하다.
- 로컬 저장 기술과 보존 정책이 정해질 때까지 durable storage 관련 acceptance는 설계 미정 상태다.

## Open Questions

1. 일반 제외 CIDR이 source 또는 destination 중 하나에 일치하면 제외할지, 방향별 규칙을 지원할지?
2. CIDR filtering을 kernel 집계 전, local persistence 전, 조회 시점 중 어디에서 적용할지?
3. local workload CIDR을 수동 설정만으로 받을지, Docker/Kubernetes 설정에서 안전하게 탐지할지?
4. 로컬 저장 engine, flush 주기, 보존 기간, 최대 디스크 사용량과 오래된 데이터 삭제 정책은 무엇인지?
5. machine-readable 출력은 JSON 또는 JSON Lines 중 무엇을 기본으로 할지?
6. 성능 acceptance의 CPU, RSS, throughput 저하와 p95 latency 증가 상한을 얼마로 할지?
7. TCP socket tuple과 uplink에서 관찰한 NAT 전후 tuple을 1차 버전에서 어떻게 대응시킬지?
