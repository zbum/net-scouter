# 개발

사용자가 보는 목적과 결과 예시는 [README.md](README.md), 설치와 명령은 [INSTALL.md](INSTALL.md)에 있습니다. 요구사항과 결정은 `docs/features/ebpf-five-tuple/`의 PRD와 ADR을 따른다.

## 목표

- 실제 들어온 연결과 밖으로 연 연결의 L3/L4 흐름을 작은 부담으로 관찰한다.
- TCP와 UDP, IPv4와 IPv6를 본다. ICMP는 포트가 없어 5-tuple이 아니므로 이번 범위가 아니다.
- 패킷마다 사용자 공간으로 올리지 않고 커널에서 모은다.
- 처음 본 시각, 마지막 시각, 패킷 수, 바이트 수, TCP 연결 성립 횟수를 남긴다.
- 조회 결과는 ACL에 쓸 수 있는 모양으로 줄인다.
- 페이로드는 보지 않는다.
- 관찰이 실패해도 운영 트래픽에 영향을 주지 않는다.

## 지원 기준

- Rocky Linux 8.10 / RHEL 8 호환 커널
- Ubuntu 22.04 LTS 이상

설계 때 확인한 Rocky 8.10 커널은 `4.18.0-553.51.1.el8_10.x86_64`이다. BTF, BPF syscall/JIT, `sched_cls`, LRU hash, 필요한 패킷 helper가 있었다. 커널 버전 문자열만으로 지원을 판단하지 않는다. `net-scouter check`가 기능 존재를 보고한다.

## 구조

```text
                  Linux host
                      |
             network interface
                      |
          +-----------+-----------+
          |                       |
      TC ingress               TC egress
          |                       |
          +-----------+-----------+
                      |
             eBPF L3/L4 parser
                      |
               BPF LRU hash map
                      |
            periodic map snapshot
                      |
                  Go agent
                      |
          +-----------+-----------+
          |                       |
   /run query socket       mode-specific sink
          |               exporter: /metrics
     flows/status          persistent: bbolt DB
```

첫 구현은 XDP가 아니라 TC ingress/egress다. 목적은 관찰이지 패킷 필터링이 아니다.

Go 에이전트가 오브젝트를 읽고, 설정한 인터페이스에만 붙인다. 시작 시 선택한 모든 NIC의 활성 IP family 주소를 조회해 BPF `host_addrs` map에 넣는다. TC와 TCP tracepoint는 로컬 끝점이 이 주소 집합에 속하는 흐름만 집계한다. 선택한 NIC를 읽을 수 없거나 활성 family 주소가 전혀 없으면 수집을 시작하지 않는다. 이미 붙인 TC 자원은 종료 경로에서 정리되며 패킷은 언제나 통과한다. IP를 바꾼 뒤에는 에이전트를 재시작해 주소 집합을 다시 읽어야 한다. TCP 연결 수는 `sock:inet_sock_set_state`의 `TCP_ESTABLISHED` 전이로 센다. tracefs format을 읽어 Linux 4.18(`protocol` u8, 주소 offset 31)과 5.15(`protocol` u16, 주소 offset 32) 중 맞는 variant 하나만 붙인다. 둘 다 붙이지 않는다. ABI를 모르면 연결 수만 끄고 패킷과 바이트 수집은 계속하지만, 기본 TCP 결과와 stdout export는 성공 여부가 확인되지 않은 행을 숨긴다.

집계 맵은 `BPF_MAP_TYPE_LRU_HASH`다. 기본 `maxFlows`는 65536이고 시작 때 그 크기만큼 잡는다. 키와 값을 합쳐 항목당 약 150바이트 안쪽이라 전체는 10MB 안팎이다. 꽉 차면 가장 오래 안 보인 항목을 버린다. 맵은 프로세스와 함께 사라진다. Go 에이전트는 각 raw map entry의 `FirstSeenNS` epoch와 counter high-water를 기억하고 증가분만 ACL 키로 합친다. TCP는 성립 횟수가 있는 행만 집계하며 UDP는 패킷 기준으로 집계한다. 카운터 감소는 이전 상한을 유지하고 `possible loss`로 알린다.

`mode: exporter`는 기본이며 메모리 누적값을 미리 렌더링해 `127.0.0.1:9469/metrics`로 제공한다. scrape는 BPF map을 읽지 않는다. `exporter.maxFlows`의 기본값은 4096개이고, 넘치는 행은 metrics에서 생략한다. 저장 파일은 만들지 않는다. `mode: persistent`는 HTTP 포트를 열지 않고 bbolt DB(`/var/lib/net-scouter/flows.db`)를 5분마다 절대값으로 갱신한다. 정상 종료에는 마지막 snapshot과 flush를 수행한다. 실패한 flush는 메모리 누적값을 유지하고 재시도하며 status를 degraded로 만든다. 보존은 마지막 관찰 후 720시간 비활성 TTL과 최대 65536행이다. 64MiB `maxBytes`는 물리 파일 크기 경고 기준이다. systemd는 상태 디렉터리 `0700`, DB는 `0600`으로 만든다.

`flows`와 `status`는 `/run/net-scouter/query.sock`으로 실행 중인 에이전트에 물어본다. 기본 `flows`는 누적값을 보여 준다. `--attempts`는 현재 BPF snapshot의 packet-only 시도도 보여 주는 별도 진단 조회다. 소켓이 없으면 `status`는 `/run/net-scouter/status.json`을 읽고, persistent 모드의 `flows`는 DB를 읽는다. exporter 모드에는 오프라인 이력이 없다. 이전 `export.type: stdout`을 명시한 설정은 변경된 누적 행 JSONL을 추가 출력한다.

CIDR 제외는 snapshot의 공통 filter에서 raw counter delta 집계 전에 적용한다. `exclude.ingress`와 `exclude.egress`는 각 방향의 `sources`·`destinations` 중 하나가 일치하면 제외한다. 기존 `exclude.destinations`는 모든 방향의 목적지에, `exclude.workloadCIDRs`는 양쪽 끝점이 CIDR 집합에 속할 때 적용한다. 저장된 과거 행도 현재 CIDR 규칙으로 다시 필터링하지만 현재 NIC 주소로 과거 행을 제거하지 않는다. 원본 BPF 집계 맵에는 제외된 행이 남을 수 있다.

## 흐름 모델

커널에 남기는 값:

```text
firstSeen
lastSeen
packets
bytes
connections (TCP established)
```

ACL 조회의 키:

```text
protocol + direction + src IP + dst IP + service port
```

- ingress의 서비스 포트는 도착 포트다.
- 이 호스트가 연 egress의 서비스 포트는 상대 도착 포트다.
- TCP와 UDP 출발 포트는 키와 표시에서 뺀다.
- 서버가 클라이언트에게 보내는 응답과, 그 반대 방향의 응답은 기록하지 않는다. 목적지 포트가 32768 이상이고 반대 방향에 더 낮은 서비스 포트가 있으면 응답으로 본다. 커널은 출발 포트가 1024 미만이고 목적지 포트가 32768 이상인 패킷만 응답으로 건너뛴다.
- ingress는 목적지 IP, egress는 출발지 IP가 선택한 NIC의 정확한 주소일 때만 결과에 남긴다. Docker/Kubernetes workload IP를 쓰는 TCP socket은 자동으로 빠진다. 다중 NIC와 IPv4/IPv6를 함께 지원한다. 이 필터는 `--local`로 해제되지 않는다.
- 기본 `flows`와 stdout export는 TCP `connections > 0`만 보여 준다. 연결 검출을 쓸 수 없으면 기본 TCP 결과는 비어 있다. `--attempts`는 TC 패킷만 관찰된 행도 표시한다. UDP는 항상 포함한다.
- 출발지와 도착지가 같거나, 둘 다 루프백이거나, 둘 다 설정한 NIC 주소이면 기본 조회에서 뺀다. `--local`로 본다.

예시:

```text
192.0.2.10 -> 198.51.100.20 TCP ingress 22
198.51.100.20 -> 203.0.113.53 UDP egress 53
```

패킷과 바이트는 4.18에서 되는 atomic add를 쓴다. `first_seen`은 맵에 처음 넣은 CPU의 시각이다. `last_seen`은 동시 CPU에서 순서가 바뀔 수 있는 best-effort다. 더 새 BPF CMPXCHG는 쓰지 않는다.

NAT가 있으면 관찰 위치가 SNAT/DNAT 앞인지 뒤인지에 따라 주소가 달라진다. 호스트 주소로 SNAT된 workload 패킷은 `--attempts`에 나타날 수 있고, 같은 집계 키를 쓰는 호스트 연결의 packet/byte counter와 섞일 수도 있다. 따라서 기본 TCP의 연결 존재·횟수는 socket tracepoint로 확인하지만 packet/byte 수를 해당 호스트 socket에 엄밀하게 귀속하지는 않는다. host 네트워크를 공유하는 Pod/컨테이너는 IP만으로 호스트 프로세스와 구별할 수 없다.

## 안전 원칙

1. 페이로드를 수집하지 않는다. L3/L4 메타데이터만 본다.
2. eBPF 프로그램은 `TC_ACT_OK`만 반환한다. 패킷을 버리거나 바꾸거나 다른 곳으로 보내지 않는다.
3. 높은 패킷률에서도 패킷마다 사용자 공간 이벤트를 만들지 않는다.
4. 흐름 상태는 상한이 있는 LRU 맵이다.
5. 파싱이나 맵 갱신 실패가 트래픽을 막지 않는다.
6. RHEL 계열의 백포트 때문에 커널 버전만으로 기능을 단정하지 않는다.

종료할 때는 이 프로세스가 만든 TC 필터만 지운다. clsact qdisc는 제거하지 않는다. 이미 있는 필터와 충돌하면 교체하지 않고 수집을 중단한다. 동시 실행은 `/run/net-scouter.lock`으로 막는다.

## 범위

### 1차에 들어 있는 것

- 커널 기능 확인
- 인터페이스 선택
- TC ingress/egress 관찰
- IPv4/IPv6, TCP/UDP
- 커널 LRU 집계, firstSeen/lastSeen, 패킷/바이트
- Linux 4.18와 5.15 TCP established 카운터
- ACL 조회, 프로토콜 필터, 성립한 TCP만 보기, 로컬 흐름 숨기기
- 방향별 source/destination CIDR 제외, 양쪽이 맞는 workload CIDR 제외
- exporter 모드 Prometheus metrics, persistent 모드 재시작 후 이력 보존
- 명시적 레거시 stdout JSONL
- systemd unit
- Nexus yum/apt 패키지 게시

### 아직 없는 것

- ICMP/ICMPv6
- 중앙 수집기, 기존 ACL과 비교, IP 이전 보고서
- DNS 보강, PID/프로세스/컨테이너 귀속
- Web UI, 알림
- `net-scouter report`

프로세스와 컨테이너 귀속은 1차에서 의도적으로 빼 두었다.

## 디렉터리

```text
net-scouter/
├── cmd/net-scouter/       CLI
├── internal/agent/        수집 루프, 조회 소켓
├── internal/ebpf/         로더와 TC attach
├── internal/flow/         흐름 모델과 ACL 축소
├── internal/query/        flows/status 표현과 필터
├── internal/metrics/      캐시된 Prometheus exporter
├── internal/storage/      bbolt 영속 저장과 보존 정책
├── internal/exporter/     레거시 stdout JSONL
├── internal/platform/     커널 기능 확인
├── bpf/                   eBPF C
├── configs/               설정 예
├── deploy/systemd/        systemd unit
├── deploy/docker/         패키지 빌드 이미지
├── deploy/kubernetes/     DaemonSet 예
├── deploy/rpm/            RPM spec
├── scripts/               검사와 패키징
└── Makefile
```

## 빌드

사용자 공간은 Go, 커널 센서는 eBPF C다. `cilium/ebpf`가 미리 컴파일한 `flow.bpf.o`를 읽는다.
사용자 공간 빌드에는 Go 1.26 이상이 필요하다. `make check-go-version`으로 설치된 Go를 확인할 수 있으며, 모든 Go 빌드와 테스트는 이 검사를 먼저 실행한다.

```text
bpf/flow.bpf.c
    |
   clang -target bpf
    |
dist/flow.bpf.o + dist/net-scouter-linux-$GOARCH
```

BPF 타깃이 있는 clang과 Linux UAPI 헤더가 설치된 Linux 호스트에서는 `make build-bpf`로 빌드한다. Ubuntu는 `linux-libc-dev`, Rocky Linux는 `kernel-headers` 패키지가 필요하다. BPF helper ID, 맵 상수, `__sk_buff`는 `<linux/bpf.h>`, 정수 타입은 `<linux/types.h>`의 공식 정의를 사용한다. libbpf 개발 패키지는 필요하지 않다. Ubuntu의 multiarch 헤더 경로는 Makefile에서 추가하며, 별도 sysroot를 사용하면 `BPF_CPPFLAGS`로 재정의한다.

Apple clang에는 BPF 타깃이 없으므로 macOS의 BPF 빌드와 검사는 다음 Linux 이미지를 쓴다.

- `net-scouter-deb-build:22.04`: Ubuntu 22.04, clang, make, linux-libc-dev
- `net-scouter-rpm-build:8`: Rocky Linux 8, clang, make, rpm-build, kernel-headers

```bash
make package-images
make build-bpf-image
make deb
make rpm
```

이미지가 없으면 패키징 스크립트와 macOS BPF 검사가 자동으로 만든다. `make build-bpf-image`는 이미지 빌드 후 BPF를 컴파일한다. Dockerfile 변경 후 기존 이미지는 `make package-images`로 갱신한다. 컨테이너는 현재 uid로 실행해서 산출물이 root 소유가 되지 않는다. macOS의 `make test`는 BPF 문법·주소 검사만 Ubuntu 컨테이너에서 실행하므로 Docker가 필요하고, Go 테스트는 호스트에서 실행한다.

Go 바이너리는 `CGO_ENABLED=0`으로 빌드 머신의 libc에 묶이지 않는다. BPF 오브젝트는 배포판용이 아니다. 커널이 받아들이는지는 지원 커널에서 따로 본다.

IPv4/IPv6 파서는 IP 헤더가 선언한 길이와 skb 경계를 넘지 않는다. IPv6 jumbogram은 무시한다. 지원하지 않거나 깨진 패킷은 세지 않고 통과시킨다.

## CI

Jenkinsfile은 `linux && amd64 && ubuntu-build` 노드와 `linux && amd64 && rocky-build` 노드에서 두 빌드를 병렬로 실행한다. 두 노드 모두 Git, Go 1.26 이상, Make, Docker, `file`, Clang이 필요하며, 빌드 시작 즉시 도구, Go 버전과 Docker daemon을 점검한다. Go 바이너리는 호스트 Jenkins 노드에서 빌드하고 패키지 Docker 이미지는 BPF와 배포 패키지 생성에 사용하므로, 두 Jenkins 노드 자체에 Go 1.26 이상을 설치해야 한다.

호스트에서 실행하는 BPF 검사에도 Linux UAPI 헤더가 필요하므로 Ubuntu Jenkins 노드에는 `linux-libc-dev`, Rocky 노드에는 `kernel-headers`를 설치한다.

`release/<version>` 브랜치는 루트 `VERSION`과 버전이 같아야 한다. Jenkins는 다르면 빌드를 중단하고, 같으면 빌드 표시명을 `#<build> v<version>`으로 설정한다.

Ubuntu 노드는 `make test`와 `make deb`를 실행하고 Linux 바이너리, BPF 오브젝트, checksum, deb 패키지를 보관한다. Rocky 노드는 `make test`와 `make rpm`을 실행하고 만든 바이너리의 `check`를 직접 실행한 뒤 rpm 패키지를 보관한다. 배포판별 BPF와 패키지 빌드는 각각 Ubuntu 22.04와 Rocky Linux 8 Docker 이미지 안에서 이루어진다.

`release/*` 브랜치에서 두 빌드가 모두 성공하면 Jenkins에 고정된 전용 username/password 자격증명으로 deb와 rpm을 패키지 저장소에 게시한다. 자격증명 ID와 노드 라벨은 빌드 파라미터로 받지 않는다. change request에서는 저장소 코드를 실행하거나 게시·커널 verifier 단계를 수행하지 않는다. 빌드 및 메타데이터 확인이 끝난 산출물만 게시하며 게시 단계에서 다시 빌드하지 않는다.

그 다음은 역할이 나뉜다.

1. `RUN_KERNEL_VERIFIERS`를 켠 신뢰 브랜치에서만 Ubuntu 22.04+와 Rocky 8.10+ verifier 노드가 root 소유의 `/usr/local/sbin/net-scouter-verify-bpf-load`를 실행한다. 기본은 꺼져 있다. 이 고정 스크립트만 passwordless sudo로 허용하며 checkout의 Makefile이나 스크립트를 root로 실행하지 않는다.
2. `make verify-bpf-load`는 TC classifier 둘과 tracepoint variant 둘을 로드하고 pin을 확인한 뒤 바로 지운다. `tc`를 실행하거나 인터페이스와 tracepoint에 붙이지 않는다.

로컬에서 Rocky 8 사용자 공간 호환성을 보려면 Docker가 필요하다. 권한과 네트워크를 제거한 컨테이너에서 `flows --help`를 실행해 바이너리가 로드되는지 확인한다. Docker Hub에는 `rockylinux:8.10` 태그가 없으므로 `rockylinux:8`을 사용한다.

```bash
make build-linux verify-rocky-userspace
```

## 패키지 게시

`NEXUS_URL`, `NEXUS_USER`, `NEXUS_PASS`가 없으면 게시 타깃은 빌드를 시작하지 않는다. 실제 저장소 URL과 자격증명은 공개 저장소가 아니라 Jenkins 또는 로컬 비밀 설정에서 주입한다.

```bash
NEXUS_URL=https://packages.example.net NEXUS_USER=... NEXUS_PASS=... make publish-deb
NEXUS_URL=https://packages.example.net NEXUS_USER=... NEXUS_PASS=... make publish-rpm
```

릴리스 버전은 루트 `VERSION`이다. `release/<version>` 브랜치에서만 올리고, 그 브랜치를 `main`과 `develop`에 `--no-ff`로 머지한 뒤 `v<version>` 태그를 `main`에 단다. 현재 릴리스는 `0.1.4`이다. `VERSION`이 없으면 `scripts/package-version.sh`가 개발용 `0.0.0+UTC시각.git해시`를 내며, 작업 트리가 더러우면 `.dirty`가 붙는다. apt와 dnf는 이 개발 버전도 이전 `0+git` 패키지보다 새 것으로 정렬한다.

yum 게시 경로는 `${NEXUS_URL}/repository/${NEXUS_YUM_REPO}/net-scouter/`이고 repodata depth는 1이다. apt는 `${NEXUS_APT_REPO}`에 컴포넌트 API로 POST한다. Distribution이 `${NEXUS_APT_DISTRIBUTION}`과 다르면 기대한 package list에 나타나지 않는다. apt 메타데이터 서명 여부는 저장소 운영 설정에 달려 있으며 deb 파일 자체의 서명과는 별개다.

## 개발 방향

eBPF C는 작게 유지한다. 패킷 파싱과 상한이 있는 집계만 커널에 둔다. 설정, 조회, 정규화, 저장, 내보내기, 이후 연동은 Go에 둔다.
