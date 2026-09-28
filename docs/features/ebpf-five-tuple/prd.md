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
last-updated: 2026-09-26
---

# PRD: 저부하 서버 5-tuple 수집 및 로컬 조회

## Background

서버 교체, IP 변경, 방화벽·ACL 정비 전에 해당 서버가 실제로 어떤 대상과 통신하는지 확인할 수 있어야 한다. 기존 로그나 방화벽 정책만으로는 서버 관점의 실제 통신 관계와 TCP 연결 발생 횟수를 정확히 파악하기 어렵다.

`net-scouter` 1차 버전은 설치된 Linux 서버에서 애플리케이션 payload 없이 L3/L4 통신 메타데이터를 관찰하고, 같은 통신을 중복 행으로 쌓지 않고 집계하여 로컬 명령으로 조회하게 한다. 관찰 기능의 장애나 지원하지 않는 패킷은 서버 트래픽 처리에 영향을 주지 않아야 한다.

## Goals

1. 선택한 NIC의 실제 IPv4/IPv6 주소를 로컬 끝점으로 쓰는 TCP·UDP 통신을 방향성 5-tuple 단위로 중복 제거하여 집계한다.
2. 각 flow의 최초·최종 관찰 시각, packet 수, byte 수를 기록한다.
3. TCP 3-way handshake가 완료되어 로컬 socket이 `TCP_ESTABLISHED` 상태로 전환된 횟수를 connection 수로 기록한다.
4. packet별 userspace 이벤트를 만들지 않고 bounded kernel map에서 집계하여 서버 성능 영향을 최소화한다.
5. CIDR 규칙으로 불필요한 flow를 결과에서 제외한다.
6. 일반 Docker container 또는 Kubernetes Pod의 workload IP를 쓰는 통신은 같은 서버 내부와 외부 간 통신 모두 기본 결과에서 제외한다. 별도 workload CIDR 설정은 필수가 아니다.
7. 중앙 서비스 없이 설치 서버의 CLI에서 수집 결과와 agent 상태를 조회한다.
8. Rocky Linux 8.10 이상과 Ubuntu 22.04 이상을 지원한다.
9. 기본 exporter 모드에서 Prometheus 형식 metrics를 제공하고, persistent 모드에서는 서버 재시작 후에도 집계 이력을 로컬에서 조회한다.
10. 저장 실패가 계속되어도 userspace 집계 행 수에 상한을 두고, 이로 인한 손실 가능성을 상태에 표시한다.

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
family + protocol + direction + source IP + destination IP + destination port
```

ACL 기록은 한 포트만 남긴다. ingress는 도착 포트, 이 호스트가 연 egress는 상대 서비스 포트다. 서버가 클라이언트에게 돌려보내는 패킷과 그 응답의 반대 방향은 기록하지 않는다. 출발 포트는 TCP와 UDP 모두 집계 키와 `flows` 표시에서 빠진다.

같은 키가 다시 관찰되면 새로운 행을 만들지 않고 다음 값을 갱신한다.

```text
firstSeen + lastSeen + packets + bytes + connections(TCP only)
```

`connections`는 로컬 TCP socket이 3-way handshake를 완료하고 `TCP_ESTABLISHED`로 전환된 횟수다. SYN 재전송과 완료되지 않은 handshake는 포함하지 않는다. UDP에는 connection 의미를 부여하지 않는다. 이 정의는 로컬 socket을 갖지 않는 transit TCP 통신에는 적용되지 않는다.

## Functional Requirements (FR)

- **FR-1 — 관찰 범위:** IPv4/IPv6의 TCP/UDP ingress와 egress 중 선택한 NIC의 정확한 IP를 로컬 끝점으로 쓰는 flow를 수집한다.
- **FR-2 — 중복 집계:** 같은 방향성 5-tuple을 한 항목으로 병합하고 `packets`, `bytes`, `firstSeen`, `lastSeen`을 유지한다.
- **FR-3 — TCP connection 수:** `inet_sock_set_state`에서 로컬 TCP socket이 `TCP_ESTABLISHED`로 전환되는 이벤트를 5-tuple별로 집계한다.
- **FR-4 — 저부하 경로:** packet별 데이터를 userspace로 전달하지 않고 kernel map에서 먼저 집계한다. map 크기는 bounded여야 한다.
- **FR-5 — 안전성:** 모든 packet 관찰 경로는 fail-open이어야 하며 packet을 drop, modify 또는 redirect하지 않는다. payload는 읽거나 저장하지 않는다.
- **FR-6 — CIDR 제외:** `exclude.ingress`와 `exclude.egress` 각각의 `sources`·`destinations` 중 하나가 일치하는 flow를 해당 방향에서 제외한다. 기존 `exclude.destinations`는 양방향 목적지에, `workloadCIDRs`는 양 끝점이 설정한 CIDR 집합에 속할 때 적용한다. 제외는 raw counter delta 집계 전에 적용하고 조회·metrics·영속 저장·명시적 stdout export에도 일관되게 반영한다.
- **FR-7 — host 주소 기준 범위:** 선택한 uplink interface에만 TC를 attach하고, ingress는 목적지, egress는 출발지가 해당 NIC의 정확한 IP인 flow만 집계한다. 전역 TCP tracepoint에도 같은 로컬 끝점 조건을 적용한다. 일반 workload IP 연결은 상대가 외부여도 기본 범위에서 제외하고, `workloadCIDRs`는 보조 제외 규칙으로 유지한다. IP 변경 후에는 재시작하여 주소를 다시 읽는다.
- **FR-8 — 로컬 조회:** `net-scouter flows`로 집계 결과를 사람이 읽는 표 형태로 조회하고 machine-readable 출력도 제공한다.
- **FR-9 — 상태 조회:** `net-scouter status`로 실행 상태, attach 대상, 수집 기간, map 포화·누락 가능성과 마지막 오류를 확인할 수 있어야 한다.
- **FR-10 — 로컬 보존:** `mode: persistent`는 bbolt에 flow 절대값을 기본 5분마다 원자적으로 저장하고 정상 종료 때 최종 수집·flush한다. 마지막 관찰 후 720시간 비활성 TTL과 기본 65,536행 상한을 적용하며, 에이전트가 멈춰도 CLI가 저장된 행을 읽을 수 있어야 한다.
- **FR-11 — 플랫폼:** Rocky Linux 8.10+와 Ubuntu 22.04+에서 build artifact 실행, verifier load 및 실제 수집 동작을 검증한다.
- **FR-12 — 종료 처리:** agent 종료 시 자신이 생성한 attach와 자원만 안전하게 정리하며 기존 qdisc/filter를 훼손하지 않는다.
- **FR-13 — 휘발 exporter:** 기본 `mode: exporter`는 메모리 누적값을 캐시된 Prometheus `/metrics`로 제공한다. scrape마다 BPF map을 읽지 않으며 서비스를 재시작하면 이력이 사라진다. 이 모드에서는 로컬 DB를 생성하지 않는다.
- **FR-14 — 장애 중 메모리 상한:** persistent 모드의 저장 실패 중에도 `storage.maxEntries`로 userspace 집계 행 수를 제한한다. 초과 시 `lastSeen`이 가장 오래된 행을, 동률이면 정규화된 storage key 순으로 제거한다. DB에 있을 수 있는 행의 삭제 요청은 중복 없이 보존하고, 메모리 제거 누적값 `memoryEvictedTotal`과 `possibleLoss`를 상태에 표시한다.
- **FR-15 — 디스크 경고 기준:** `storage.maxBytes`는 bbolt 파일 크기 경고 임계값으로 표시한다. 물리 파일 크기 hard cap 또는 자동 compaction을 보장하지 않는다.
- **FR-16 — 빌드 도구:** Go 1.26 이상으로 사용자 공간 binary와 테스트를 빌드하며, CI와 Make에서 버전을 확인한다.

## User Stories

- 서버 운영자로서 `net-scouter flows`를 실행해 이 서버와 실제 통신한 상대, protocol/port, 방향, packet·byte·TCP connection 수와 관찰 기간을 확인한다.
- 서버 운영자로서 CIDR 제외 설정을 적용해 관리망 등 분석에 필요 없는 통신을 결과에서 제거한다.
- Kubernetes 또는 Docker host 운영자로서 NIC 주소를 로컬 끝점으로 쓰는 통신을 보고, workload IP 통신은 CIDR을 일일이 등록하지 않고 기본 결과에서 제외한다.
- 서버 운영자로서 `net-scouter status`를 실행해 수집기가 정상인지와 결과 누락 가능성이 있는지 판단한다.
- 운영자로서 재시작 후 이력이 필요 없는 서버에서는 exporter 모드의 metrics를 수집하고, 로컬 이력이 필요한 서버에서는 persistent 모드의 DB를 `flows`로 조회한다.

## Acceptance Criteria

1. 동일 방향성 5-tuple의 반복 packet은 단일 flow로 조회되며 packet·byte 수가 누적된다.
2. IPv4/IPv6 TCP·UDP 각각에 대해 ingress/egress tuple과 port가 올바르게 표시된다.
3. 성공한 로컬 TCP handshake마다 `connections`가 한 번 증가하고 SYN 재전송 또는 실패한 handshake에는 증가하지 않는다.
4. UDP 결과에는 TCP connection 수가 적용되지 않는다.
5. 설정된 제외 CIDR에 해당하는 flow가 결과에서 보이지 않는다.
6. 선택한 NIC 주소를 로컬 끝점으로 쓰지 않는 container/Pod IP 연결은 상대가 같은 host인지 외부인지와 무관하게 기본 결과에서 제외된다. host 네트워크를 공유하는 workload는 IP만으로 구분하지 않는다.
7. `net-scouter flows`가 최소한 tuple, direction, first/last seen, packets, bytes, TCP connections를 출력한다.
8. `net-scouter status`가 실행·attach·수집 상태와 map 포화 또는 누락 가능성을 출력한다.
9. BPF 프로그램의 모든 분기에서 traffic을 허용하며 payload가 artifact, log 또는 로컬 저장소에 기록되지 않는다.
10. packet별 userspace event가 없고, 합의된 성능 시험에서 허용 기준을 충족한다. 구체적인 CPU/RSS/throughput/latency 기준은 승인 후 확정한다.
11. Rocky Linux 8.10+와 Ubuntu 22.04+의 실제 kernel test node에서 verifier load와 수집 통합 시험을 통과한다.
12. persistent 모드에서 이미 flush된 flow는 agent 재시작 후와 정지 중에도 조회할 수 있다. 비정상 종료 시 마지막 성공 flush 이후의 기록은 사라질 수 있다.
13. exporter 모드에서 `/metrics`는 캐시된 Prometheus 형식으로 응답하고 재시작 시 이력이 남지 않는다.
14. ingress/egress 각각의 source/destination CIDR이 지정한 방향에만 적용되고 기존 제외 설정과 호환된다.
15. 연속 저장 오류 및 새로운 flow 증가 중에도 userspace 집계·dirty key가 `storage.maxEntries` 이내이고, 메모리 제거가 발생하면 `memoryEvictedTotal`과 `possibleLoss`가 증가한다. 저장 복구 후 보존된 행의 upsert와 탈락한 기존 DB 행의 삭제가 반영된다.
16. `storage.maxBytes` 초과 시 경고 상태만 표시하고 이를 디스크 hard cap으로 설명하지 않는다.
17. Go 1.26 미만 toolchain은 빌드 전에 명확한 오류로 거부된다.

## Current Implementation Status

현재 구현됨:

- TC ingress/egress observation-only classifier
- IPv4/IPv6 TCP·UDP parsing과 VLAN/IPv6 extension header 처리
- 방향성 5-tuple별 bounded LRU map 집계
- `firstSeen`, `lastSeen`, packet 및 byte counter
- `inet_sock_set_state` 기반 TCP connection counter와 Linux 4.18/5.15
  tracepoint ABI variant
- 시작 시 선택한 NIC의 주소를 읽어 TC와 TCP tracepoint에 동일한 host 주소
  조건을 적용. 일반 workload IP 연결은 CIDR 설정 없이 기본 집계에서 제외
- tracefs format probe, 일치하는 connection ABI variant 하나만 attach,
  기존 qdisc/filter를 유지하는 TC lifecycle
- kernel map snapshot. packet·byte·connection counter는 같은 map value에 있다
- ingress/egress 각각의 source/destination CIDR 제외, 기존 destination CIDR 제외,
  그리고 보조 규칙으로 양 endpoint가 모두 workload CIDR일 때만 제외
- 실행 중 agent에 대한 `flows`와 `status`. 기본 출력은 표이고, JSON과
  JSON Lines는 명시적 `--format`으로 선택할 수 있다
- connection counting을 쓸 수 없으면 0이 아니라 사용할 수 없음으로 표시
- map이 상한에 도달하면 status에 누락 가능성을 표시
- 기본 exporter 모드의 캐시된 Prometheus `/metrics`와 휘발 메모리 집계.
  persistent 모드의 bbolt 저장, 5분 flush, 720시간 비활성 TTL 및 65,536행 상한
- 저장 오류 중 userspace 집계 행 상한, 결정적 오래된 행 제거, 중복 없는 DB 삭제
  대기와 `memoryEvictedTotal`·`possibleLoss` 상태 표시
- 상태 파일과 query socket. persistent 모드에서는 재시작·에이전트 정지 후 DB 조회
- `exclude`가 raw delta 집계 전에 적용되며 저장 이력의 오프라인 조회에도 적용
- Go 1.26 toolchain 검사를 통과한 Make/CI 빌드
- `net-scouter check`의 OS, BPF syscall, bpffs, BTF, tracepoint, kernel config 보고
- systemd unit의 runtime directory와 `make install`
- 항상 `TC_ACT_OK`를 반환하는 fail-open packet 경로
- Ubuntu build와 Rocky/Ubuntu 실제 kernel verifier 검증을 분리한 Make/Jenkins 기반
- host 네트워크를 공유하는 workload는 호스트 프로세스와 IP만으로 구분할 수 없고,
  NAT된 workload 패킷은 TCP packet·byte 수치에 섞일 수 있음. NIC 주소 변경 후 재시작 필요

남은 1차 검증:

- Rocky 8.10+ 및 Ubuntu 22.04+ 실제 kernel의 verifier load, Docker/Kubernetes 통합·성능 시험
- 장애 주입을 포함한 장기 운영에서 CPU·RSS·디스크 성장과 flush 손실 범위 측정

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
- 사용자가 `bbolt` 의존성과 exporter/persistent 두 운영 모드를 승인했다. `go.etcd.io/bbolt`는 `go.mod`에 고정하고, Go 1.26 이상으로 빌드한다.
- bbolt 파일의 `maxBytes`는 경고 임계값이며 실제 디스크 상한이 아니다. 운영 환경에서는 파일 크기를 별도로 관찰해야 한다.

## Open Questions

1. 성능 acceptance의 CPU, RSS, throughput 저하와 p95 latency 증가 상한을 얼마로 할지?
2. NAT 전후 TCP socket tuple과 uplink packet tuple을 대응시켜 packet·byte 수를 해당 socket에 정확히 귀속하는 기능을 후속에 구현할지?
3. host 네트워크를 공유하는 Docker/Kubernetes workload를 cgroup 또는 network namespace로 구별할지?
4. bbolt 파일의 장기 성장에 대한 운영 compaction 절차와 실측 기준을 어떻게 정할지?
