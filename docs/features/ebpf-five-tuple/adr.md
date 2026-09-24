---
template-version: 1
type: adr
topic: ebpf-five-tuple
id: ebpf-five-tuple
task: ""
status: draft
authors:
  - jibum.jung@gmail.com
created: 2026-09-23
last-updated: 2026-09-25
---

# ADR: eBPF 5-tuple 수집 아키텍처

본 파일은 immutable이다. 새로운 결정이 필요하면 새 ADR-NNN 블록을 추가한다. 기존 ADR을 수정하지 않는다 (`status: superseded` 표시만 허용).

---

## ADR-001 — TC와 bounded LRU map에서 packet flow 집계

**Status:** accepted

**Context**

설치 서버의 ingress/egress IPv4/IPv6 TCP·UDP 5-tuple과 packet·byte·관찰 시각을 수집해야 한다. packet마다 userspace event를 발생시키면 고속 통신에서 CPU와 context-switch 부하가 커지고 agent 장애가 traffic path에 영향을 줄 위험이 있다.

**Decision**

선택한 uplink interface의 TC ingress/egress에 observation-only eBPF classifier를 attach한다. 방향을 포함한 5-tuple을 key로 하고 `first_seen`, `last_seen`, `packets`, `bytes`를 value로 하는 bounded LRU map에서 kernel-side 집계한다. 모든 처리 경로는 `TC_ACT_OK`를 반환하며 payload를 복사하거나 packet을 변경하지 않는다.

**Drivers**

- production traffic에 대한 fail-open 안전성
- packet별 userspace 전달 제거
- 방향성 ingress/egress 관찰
- Rocky Linux 8.10 계열 kernel 호환성
- memory 사용량의 명시적 상한

**Alternatives Considered**

- **packet별 ring buffer/perf event:** userspace 처리량과 wake-up 비용 때문에 채택하지 않는다.
- **XDP:** 고성능 filtering이 목적이 아니며 egress 대칭 관찰과 운영 안전성이 더 중요해 채택하지 않는다.
- **pcap/AF_PACKET payload capture:** 요구 범위를 넘고 부하·보안 위험이 있어 채택하지 않는다.

**Consequences**

- 같은 방향성 5-tuple은 kernel에서 중복 제거되어 userspace 부하가 flow 수에 비례한다.
- LRU eviction이 발생할 수 있으므로 status에서 포화와 결과 누락 가능성을 보여야 한다.
- 동시 CPU 갱신에서 `last_seen`은 best-effort일 수 있지만 packet·byte counter는 안전하게 누적해야 한다.
- TC attach lifecycle은 기존 qdisc/filter를 훼손하지 않도록 별도로 구현하고 실제 kernel에서 검증해야 한다.

---

## ADR-002 — TCP connection은 `inet_sock_set_state`에서 집계

**Status:** accepted

**Context**

요구되는 "통신수"는 TCP packet 수가 아니라 3-way handshake가 성공하여 connection이 발생한 횟수다. TC에서 SYN/SYN-ACK/ACK 상태를 별도 map으로 추적하면 packet path의 상태와 비용이 늘고 재전송·동시 open 같은 TCP edge case를 다시 구현해야 한다.

**Decision**

`sock:inet_sock_set_state` tracepoint를 관찰하여 로컬 TCP socket의 새 상태가 `TCP_ESTABLISHED`가 되는 이벤트를 5-tuple별 `connections` counter에 누적한다. SYN 재전송과 handshake 미완료는 세지 않는다. UDP에는 connection count를 적용하지 않는다. 이벤트는 userspace로 건별 전송하지 않고 kernel map에서 집계한다.

**Drivers**

- kernel TCP state machine을 handshake 완료의 source of truth로 사용
- packet hot path의 추가 상태 추적 최소화
- 재전송으로 인한 중복 count 방지
- 낮은 userspace wake-up 비용

**Alternatives Considered**

- **TC에서 TCP flag 3단계 추적:** 임시 상태 map과 timeout이 필요하고 TCP state machine을 불완전하게 중복 구현하므로 채택하지 않는다.
- **SYN packet count:** 시도 횟수일 뿐 성공한 connection 횟수가 아니므로 채택하지 않는다.
- **userspace socket polling:** 짧은 connection 누락과 polling 비용 때문에 채택하지 않는다.

**Consequences**

- 이 count는 이 host 또는 local workload에서 종료되는 local TCP socket에 한정된다. 단순 transit connection은 세지 못한다.
- client와 server 양쪽 state transition의 tuple 방향 및 중복 의미를 통합 시험으로 고정해야 한다.
- NAT가 있으면 socket tuple과 uplink packet tuple이 다를 수 있으므로 안전한 correlation 규칙이 필요하다. 확정 전에는 잘못된 tuple로 병합하지 않는다.
- 지원 kernel에서 tracepoint field와 attach 가능 여부를 시작 시 확인하고 Rocky/Ubuntu 실제 kernel에서 검증해야 한다.

---

## ADR-003 — uplink-only 관찰과 양 endpoint workload CIDR 조건으로 동일 host traffic 제외

**Status:** superseded

**Context**

Docker container와 Kubernetes Pod 사이의 동일 host 내부 통신은 외부 dependency 분석에 필요하지 않다. 반면 외부 host와 local container/Pod 간 통신은 보존해야 한다. interface 이름이나 CIDR 한 가지 신호만으로 제외하면 CNI 구성, routing 또는 NAT에 따라 필요한 통신을 잃을 수 있다.

**Decision**

기본 attach 대상은 명시적으로 선택한 physical/uplink interface로 제한한다. `lo`, `docker0`, CNI bridge 및 `veth*` 등 내부 virtual interface에는 자동 attach하지 않는다. 그 위에서 source와 destination이 모두 이 host의 configured workload CIDR에 포함될 때만 동일 host workload flow로 제외한다. 한쪽 endpoint만 workload CIDR이면 외부↔workload 통신으로 보고 유지한다.

일반적인 불필요 traffic을 제거하는 CIDR 규칙은 workload 양 endpoint 규칙과 별도의 설정으로 취급한다. 일반 CIDR의 endpoint 일치 의미와 적용 시점은 PRD open question을 해소한 뒤 새 ADR로 결정한다.

**Drivers**

- 같은 host의 workload 간 noise 제거
- 외부 dependency 보존
- packet hot path와 attach 수 최소화
- Docker/CNI 구현 차이에 대한 방어적 동작

**Alternatives Considered**

- **모든 interface에 attach 후 interface 이름만 제외:** 중복 관찰과 attach 비용이 늘고 이름 규칙이 환경마다 달라 채택하지 않는다.
- **workload CIDR 한 endpoint 일치 시 제외:** 외부↔workload dependency를 잃으므로 채택하지 않는다.
- **process/container attribution:** 1차 범위를 넘으므로 후속 단계로 둔다.

**Consequences**

- uplink를 지나지 않는 대부분의 same-host traffic은 수집 자체가 발생하지 않는다.
- routing 또는 CNI 구성상 uplink에 나타나는 same-host flow는 양 endpoint workload CIDR 규칙이 보완한다.
- workload CIDR 설정이 누락되거나 부정확하면 noise가 남거나 필요한 flow가 제외될 수 있으므로 status에서 적용 설정을 노출해야 한다.
- NAT 전후 주소 때문에 양 endpoint 판단이 불명확한 환경은 실제 Docker/Kubernetes 통합 시험이 필요하다.

---

## ADR-004 — 로컬 durable storage와 보존 정책

**Status:** proposed

**Context**

agent 또는 서버 재시작 뒤에도 이전 flow를 조회하고 장기간 중복 집계하려면 kernel map 외부의 로컬 durable storage가 필요하다. 저장 engine, flush cadence, retention과 disk cap은 성능, 데이터 손실 범위 및 운영 복잡도에 직접 영향을 준다.

**Proposed Decision**

Go agent가 kernel map snapshot을 주기적으로 로컬 durable store에 merge하고 CLI가 그 store를 조회하는 구조를 사용한다. 정확히 한 번 반영하기 위한 snapshot/reset 또는 delta 계산 방식, storage engine, flush 주기, retention 기간, disk 상한과 compaction 정책은 benchmark와 운영 요구 확인 후 결정한다.

`bbolt`는 embedded transactional store 후보지만 승인되지 않았다. `cilium/ebpf`, netlink library 및 YAML library도 각각 loader, TC lifecycle, configuration 후보일 뿐 이 ADR에서 채택하지 않는다. 각 dependency는 버전, 라이선스, 유지보수 상태, 정적 build, Rocky 8.10 kernel baseline 및 성능 영향을 검토한 후 명시적으로 승인해야 한다.

**Drivers**

- 재시작 후 조회 가능성
- 중복 merge의 정확성
- bounded disk 사용량
- 중앙 서비스 없는 단일 binary 운영
- low write amplification과 낮은 CPU/RSS

**Alternatives Considered**

- **kernel map만 사용:** 재시작과 eviction 때 데이터가 사라져 요구사항을 충족하지 못한다.
- **append-only JSONL만 사용:** 단순하지만 동일 flow merge, crash consistency, retention과 compaction 비용을 추가 검증해야 한다.
- **외부 database/collector:** 1차 범위를 넘고 설치 의존성이 커서 채택하지 않는다.

**Consequences**

- 결정 후 schema migration, crash recovery, atomic merge와 corruption handling 시험이 필요하다.
- flush가 너무 잦으면 부하가 늘고 너무 드물면 비정상 종료 시 손실 범위가 커진다.
- retention 숫자와 dependency는 이 ADR이 `accepted`로 변경되기 전까지 구현 전제 또는 보장으로 사용하지 않는다.
- 이 결정을 수락하려면 storage benchmark 및 dependency 검토 결과와 명시적인 운영 정책 승인이 필요하다.

---

## ADR-005 — tracefs format에 따라 하나의 TCP state tracepoint ABI만 attach

**Status:** accepted

**Context**

`sock:inet_sock_set_state` tracepoint의 raw context layout은 지원 대상
kernel에서 동일하지 않다. Linux 4.18 계열은 `protocol`이 8-bit이고 address
field가 offset 31에서 시작하지만, Linux 5.15 계열은 `protocol`이 16-bit이고
address field가 offset 32에서 시작한다. 잘못된 layout으로 raw context를 읽으면
tuple을 잘못 해석할 수 있으며, 두 프로그램을 동시에 attach하면 한 번의 상태
전환을 두 번 집계할 수 있다.

**Decision**

eBPF object에는 다음 두 connection counter program을 각각 독립적으로 선택할 수
있는 variant로 build한다.

- Linux 4.18 layout: 8-bit `protocol`, address offset 31
- Linux 5.15 layout: 16-bit `protocol`, address offset 32

Go loader는 실행 중인 kernel의 tracefs
`events/sock/inet_sock_set_state/format`을 읽어 field size와 offset을 확인한다.
확인된 layout과 일치하는 variant 정확히 하나만 실제
`sock:inet_sock_set_state` tracepoint에 명시적으로 attach한다. 두 variant의 동시
attach를 금지한다. 알려지지 않은 format, 읽기 실패 또는 모호한 format에서는
connection counting을 비활성화하고 진단 상태를 노출하되 TC packet/byte flow
수집은 계속한다.

**Drivers**

- Rocky Linux 8.10의 Linux 4.18 계열과 Ubuntu 22.04+ 계열 kernel 지원
- raw tracepoint context의 정확한 tuple 해석
- 한 handshake당 connection counter 중복 증가 방지
- 알 수 없는 ABI에서 잘못된 데이터보다 명시적 기능 축소 선택
- connection 기능 실패가 packet 관찰에 영향을 주지 않는 fail-open 동작

**Alternatives Considered**

- **kernel version string으로 variant 선택:** vendor backport와 custom kernel에서
  실제 tracepoint layout을 보장하지 못하므로 채택하지 않는다.
- **두 variant를 동시에 attach하고 userspace에서 중복 제거:** kernel counter가
  이미 이중 증가하며 잘못된 layout 접근도 막지 못하므로 금지한다.
- **하나의 고정 layout만 build:** 지원 OS baseline 양쪽을 안전하게 지원하지
  못하므로 채택하지 않는다.
- **알 수 없는 layout을 추정:** 조용한 tuple corruption 위험이 있으므로
  채택하지 않는다.

**Consequences**

- build와 verifier 검증 대상은 TC classifier 2개와 connection ABI variant 2개,
  총 4개 program이다.
- verifier 단계에서는 두 variant가 각각 load 가능한지 확인하지만 실제 실행
  단계에서는 loader가 선택한 하나만 attach한다.
- loader에 tracefs format parser, exact-match selection, exactly-one attach 보장과
  상태 보고가 필요하다.
- 알 수 없는 ABI에서는 `connections`가 제공되지 않지만 packet·byte flow
  수집은 유지된다. CLI는 이 상태를 정상적인 0 connection으로 오해하지 않게
  표시해야 한다.

---

## ADR-006 — Go loader, TC lifecycle 및 YAML 설정 라이브러리 도입

**Status:** accepted

**Context**

Go agent에는 eBPF object와 map을 안전하게 다루고, 기존 network 설정을
보존하면서 TC attach/detach lifecycle을 관리하며, 사람이 관리할 수 있는 설정을
읽는 기능이 필요하다. 이 기능을 자체 구현하면 netlink protocol, BPF syscall,
YAML parsing의 오류 처리와 kernel 호환성 부담이 커진다. 사용자는 이 세 역할에
대한 외부 라이브러리 도입을 승인했다.

**Decision**

다음 라이브러리를 역할 경계를 지켜 도입한다.

- `github.com/cilium/ebpf`: eBPF collection/object load, map access, program과
  tracepoint attach에 사용한다.
- `github.com/vishvananda/netlink`: TC qdisc/filter 조회와 기존 설정을 보존하는
  attach/detach lifecycle에 사용한다.
- `gopkg.in/yaml.v3`: agent configuration parsing에 사용한다.

정확한 버전은 각 프로젝트의 공식 문서와 release compatibility를 조사하고,
지원 Go version, Rocky Linux 8.10/Linux 4.18 및 Ubuntu 22.04+ 동작, 유지보수
상태와 라이선스를 검토한 뒤 `go.mod`에 직접 고정한다. release binary는 가능한
한 `CGO_ENABLED=0` 정적 빌드를 유지하며, 선택 버전이 이를 깨뜨리지 않는지 CI와
대상 OS에서 검증한다.

이 결정은 local durable storage engine을 선택하지 않는다. 특히 `bbolt`는 계속
후보일 뿐 승인된 dependency가 아니며 ADR-004의 proposed 상태와 open decision을
유지한다.

**Drivers**

- 검증된 BPF syscall/object/map abstraction 사용
- 기존 TC qdisc와 filter를 훼손하지 않는 명시적 lifecycle 구현
- 설정 파일의 안정적인 parsing과 오류 보고
- Ubuntu build artifact의 Rocky/Ubuntu 공용 배포와 정적 빌드 유지
- dependency 역할을 좁게 제한하여 운영·공급망 위험 관리

**Alternatives Considered**

- **BPF syscall과 ELF loader 자체 구현:** kernel ABI와 relocation 처리 위험이
  크므로 채택하지 않는다.
- **netlink message 직접 구현 또는 `tc` subprocess 호출:** 정확한 소유권 추적,
  구조화된 오류 처리와 안전한 정리가 어려워 채택하지 않는다.
- **YAML parser 자체 구현:** 설정 문법과 오류 처리 부담 대비 이점이 없어
  채택하지 않는다.
- **`bbolt` 동시 도입:** 저장 schema, flush, retention과 disk cap 결정이 아직
  열려 있으므로 이 ADR 범위에서 승인하지 않는다.

**Consequences**

- 세 dependency와 필요한 transitive dependency를 `go.mod`/`go.sum`으로
  재현 가능하게 고정해야 한다.
- version 선택 전에 공식 compatibility와 release 정보를 확인하고 라이선스 및
  transitive dependency를 검토해야 한다.
- CI는 `CGO_ENABLED=0` Linux amd64 build와 Rocky 8.10/Ubuntu 22.04+ 실행·kernel
  integration을 검증해야 한다.
- library API를 agent 내부 adapter 경계에 가두어 이후 upgrade와 교체 범위를
  제한해야 한다.
- local durable storage 구현은 ADR-004가 별도로 accepted되기 전까지 이 결정의
  일부로 간주하지 않는다.

---

## ADR-007 — TCP 집계 키에서 출발 포트를 제외

**Status:** accepted

**Context**

TCP 출발 포트는 연결마다 바뀌는 ephemeral port다. ACL 신청에는 도착 포트만 필요하고, 출발 포트를 키에 두면 같은 서비스 통신이 행으로 쪼개져 조회와 map 용량을 낭비한다.

**Decision**

TCP flow의 kernel map 키와 조회 결과에서 출발 포트를 제외한다. 같은 방향, 주소, 도착 포트의 packet·byte·connection 수는 한 항목으로 합친다. UDP 출발 포트는 키와 표시에 유지한다.

**Drivers**

- ACL에 필요한 식별자만 남긴다.
- ephemeral port로 인한 map 증가를 줄인다.
- 패킷 경로와 TCP established 이벤트가 같은 키를 쓰게 한다.

**Alternatives Considered**

- **표시만 숨기고 키는 유지:** 조회는 짧아지지만 kernel map은 여전히 연결마다 항목을 소비하므로 채택하지 않는다.
- **UDP 출발 포트도 제외:** DNS처럼 출발 포트가 통신을 구분하는 경우가 있어 채택하지 않는다.

**Consequences**

- 개별 TCP 연결의 출발 포트는 복원할 수 없다.
- 기존 BPF object는 재배포해야 커널 집계에 반영된다. 재배포 전에는 조회 시점에 같은 병합을 적용한다.

---

## ADR-008 — ACL에 해당하는 방향만 기록

**Status:** accepted

**Context**

조회 결과가 응답 패킷과 ephemeral port까지 남겨 ACL 신청에 바로 쓸 수 없다. ADR-007은 TCP 출발 포트만 제외하고 UDP 출발 포트와 서버→클라이언트 방향은 남겼다.

**Decision**

`flows`와 kernel 집계는 ACL 후보만 남긴다.

- ingress는 도착 포트만 남긴다. 출발 포트는 키와 표시에서 뺀다.
- 이 호스트가 연 egress는 상대 서비스의 도착 포트만 남긴다.
- 서버가 클라이언트에게 보내는 응답 패킷과, 그 반대 방향의 응답은 기록하지 않는다.
- UDP 출발 포트도 키에서 뺀다. ADR-007의 "UDP 출발 포트는 유지"는 이 결정으로 대체한다.

**Drivers**

- ACL 신청 항목은 출발지와 서비스 포트다.
- 응답 방향은 방화벽 규칙이 아니다.
- ephemeral port는 행만 늘린다.

**Alternatives Considered**

- **egress를 로컬 출발 포트로 집계:** 밖으로 연 연결의 출발 포트는 ephemeral이라 ACL에 쓸 수 없으므로 채택하지 않는다.
- **응답 패킷을 요청 행에 바이트만 합산:** 방향이 섞여 ACL 건수와 패킷 의미가 흐려지므로 채택하지 않는다.

**Consequences**

- 서비스 포트가 32768 이상이면 응답 방향과 구분하지 못해 빠질 수 있다.
- 커널의 낮은 포트 응답 제거는 1024 미만 출발 포트에만 적용된다. 그 외 응답은 조회 시 반대 방향이 있으면 제거한다.
- BPF object를 다시 배포해야 커널 map에도 반영된다.

---

## ADR-009 — 선택한 NIC의 주소를 로컬 끝점으로 쓰는 통신만 기본 집계

**Status:** accepted

**Context**

ADR-003의 양 endpoint workload CIDR 조건은 Docker와 Kubernetes 네트워크가 바뀔 때마다 운영자가 CIDR을 관리해야 한다. TCP connection을 세는 `inet_sock_set_state` tracepoint는 NIC에 한정되지 않고 host 전체 socket을 관찰하므로, TC를 선택한 물리 NIC에만 붙여도 container 간 연결이 결과에 나타날 수 있다.

**Decision**

에이전트 시작 시 설정된 NIC의 실제 IPv4/IPv6 주소를 읽는다. TC와 TCP tracepoint는 ingress의 목적지 또는 egress의 출발지가 선택한 NIC의 정확한 주소인 flow만 집계한다. 일반 Docker/Kubernetes workload IP를 로컬 끝점으로 쓰는 연결은 상대가 같은 host인지 외부인지에 관계없이 기본 범위에서 제외한다. `workloadCIDRs`는 필요한 환경에서 사용하는 보조 제외 규칙으로 유지한다. NIC 주소가 변경되면 에이전트를 재시작해 주소 집합을 갱신한다.

**Drivers**

- Docker/Kubernetes CIDR 수동 관리 제거
- 전역 tracepoint에서 발생하는 workload 연결 행 제외
- 선택한 NIC 주소를 기준으로 서버 자체의 통신 관계 조회

**Alternatives Considered**

- **ADR-003의 양 endpoint workload CIDR만 사용:** 네트워크 변경 시 CIDR 관리가 필요하고, 비어 있으면 전역 tracepoint의 workload 연결이 남는다.
- **선택한 NIC에 TC만 attach:** TCP tracepoint가 전역으로 실행되어 container socket 연결을 막지 못한다.
- **network namespace 또는 cgroup 기반 workload 식별:** host 네트워크를 공유하는 workload까지 구별할 수 있으나 이번 결정의 주소 기반 범위를 넘는다.

**Consequences**

- 일반 workload IP를 쓰는 외부↔container/Pod 연결도 기본 집계에서 제외된다.
- host 네트워크를 공유하는 Pod 또는 container는 호스트 주소를 쓰므로 IP만으로 호스트 프로세스와 구분할 수 없다.
- NAT 뒤의 workload 패킷은 선택한 NIC에서 호스트 주소로 보일 수 있다. 따라서 TCP connection 존재·횟수는 socket tracepoint를 기준으로 하되 packet·byte 수에는 workload 트래픽이 섞일 수 있다.
- 주소 조회에 실패하거나 활성 주소가 없으면 수집을 시작하지 않는다. 주소가 바뀌면 재시작이 필요하다.
