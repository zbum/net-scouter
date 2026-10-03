# Changelog

이 문서는 `net-scouter`의 사용자 관점 변경 사항을 기록한다.

## [Unreleased]

## [0.1.9] - 2026-10-03

### Changed

- Linux UAPI 헤더 대신 저장소의 최소 `vmlinux.h`와 CO-RE를 사용한다. macOS에서 Linux 헤더나 Docker 없이 BPF 문법·파서 검사가 가능하며, 실행 커널에는 `__sk_buff` 타입을 포함한 BTF가 필요하다.
- BPF 맵을 BTF `.maps` 정의로 전환하고 TC 프로그램에 표준 `classifier` 섹션을 사용한다. ingress/egress 연결은 기존 로더가 함수 이름으로 구분한다.

### Fixed

- 커널 로드 검증 스크립트에서 bpffs가 거부하는 점이 포함된 임시 디렉터리 이름을 수정했다.

### 검증 — 2026-10-03 (`feature/btf-map-definitions`)

- 전체 테스트, Linux amd64/arm64 및 Windows·macOS amd64 빌드, Ubuntu/Rocky 8 이미지의 BPF 컴파일을 통과했다.
- Docker VM의 Linux 6.8 ARM64에서 네 프로그램의 verifier 로드와 실제 Go 로더의 TC attach를 확인했다. 격리된 veth에서 UDP ingress/egress를 각각 한 패킷씩 검증하고 종료 후 TC 필터와 pin 정리를 확인했다.
- Rocky 8 및 Ubuntu 배포 대상 커널별 검증은 별도로 필요하다.

### Added

- Docker 표준 브리지의 IPv4/IPv6 서브넷을 자동 감지해 양쪽 끝점 중 하나가 해당 대역인 흐름을 집계·조회·metrics·영속 저장에서 제외한다. 30초 주기로 재감지하고 적용 대역과 오류를 status에 표시한다.

### 검증 — 2026-10-02 (`feature/exclude-docker-networks`)

- Docker 소켓 없이 표준 브리지 이름과 인터페이스 주소로 감지한다. 사용자 지정 브리지·host 네트워크 및 NAT 후 호스트 주소만 남은 흐름은 자동 식별에 제한이 있다.
- 전체 테스트와 Linux·Windows·macOS amd64 빌드를 통과했다. 실제 Ubuntu 서버의 트래픽 수집 검증은 별도로 필요하다.

## [0.1.8] - 2026-10-01

### Fixed

- 명시적 레거시 stdout flow export가 systemd와 rsyslog를 통해 `/var/log/syslog`를 무제한 키울 수 있는 문제를 방지했다. 서비스 stdout은 폐기하고 stderr journal에는 rate limit을 적용한다.

### Operational Notes

- 기존 설정에 `export.type: stdout`이 남아 있다면 제거하고 서비스를 재시작한다. 기존 대용량 syslog는 원인 제거와 필요한 로그 보존 후에 회수한다.

## [0.1.7] - 2026-09-29

### Added

- `flows -k`/`-m`/`-h`로 바이트를 KiB/MiB/자동 단위로 표시할 수 있다. 도움말은 `flows --help`로 확인한다.
- `flows --sort-by=packets|bytes|connections`로 원래 숫자 기준 내림차순 정렬을 지원한다. 대소문자와 단수·복수형, 약어 `p`/`b`/`c`를 모두 허용한다.

### Changed

- BPF helper ID, 맵 상수, `__sk_buff`와 정수 타입을 Linux UAPI 헤더에서 가져오도록 변경했다. Linux BPF 빌드·검사에는 배포판의 UAPI 헤더 패키지가 필요하며, macOS BPF 검사는 Docker에서 실행한다.

## [0.1.6] - 2026-09-28

### Added

- `mode: exporter`와 `mode: persistent` 운영 모드를 추가했다.
- exporter 모드에 캐시된 Prometheus text format 0.0.4 `/metrics` endpoint를 추가했다.
- persistent 모드에 bbolt 기반 로컬 flow 저장, 재시작 복구, agent 정지 중 CLI 조회를 추가했다.
- persistent 저장소에 기본 5분 flush, 720시간 비활성 TTL, 65,536개 flow 상한을 추가했다.
- ingress/egress별 source·destination CIDR 제외 설정을 추가했다.
- 저장 장애 중 메모리 flow 상한과 `memoryEvictedTotal`, `possibleLoss` 상태를 추가했다.
- Linux, Windows, macOS 사용자 공간 binary의 cross-build와 Go toolchain 버전 검사를 추가했다.
- exporter, 저장·복구, TTL, 저장 장애, 방향별 제외에 대한 회귀 테스트를 추가했다.

### Changed

- 사용자 공간 빌드 기준을 Go 1.26 이상으로 높였다.
- Go module 경로를 `github.com/zbum/net-scouter`로 변경했다.
- `go.etcd.io/bbolt v1.5.0`을 영속 저장 의존성으로 추가했다.
- 기본 모드를 DB를 생성하지 않는 exporter 모드로 정했다.
- 제외 규칙을 raw counter delta가 누적되기 전에 적용하고 조회, metrics, 저장 결과에 동일하게 반영한다.
- systemd 서비스가 `/var/lib/net-scouter` 상태 디렉터리를 사용할 수 있게 했다.
- Debian/RPM 패키지에 라이선스와 SHA-256 checksum 생성을 추가했다.
- PRD와 ADR에 두 운영 모드, bbolt, 방향별 제외, Go 1.26 결정을 반영했다.

### Fixed

- 저장 실패가 지속될 때 persistent 메모리와 dirty flow가 무한히 증가할 수 있는 문제를 방지했다.
- 연속된 만료 flow를 bbolt cursor 삭제 중 일부 건너뛸 수 있는 문제를 수정했다.
- 뒤늦게 반대 방향 서비스 flow가 발견된 뒤에도 과거 UDP 응답 행이 남는 문제를 수정했다.
- 저장 commit 성공 후 reload 실패 시 새 snapshot을 잘못 누적할 수 있는 복구 경로를 수정했다.
- `make`의 기본 target이 버전 검사만 수행하던 회귀를 수정해 다시 binary를 빌드한다.

### Operational Notes

- `storage.maxBytes`는 경고 임계값이며 bbolt 파일의 hard cap이나 자동 compaction을 제공하지 않는다.
- exporter는 Prometheus text format 0.0.4를 제공하며 native OpenMetrics content negotiation은 아직 지원하지 않는다.
- 비정상 종료 시 마지막 성공 flush 이후의 flow는 유실될 수 있다.
- 실제 Rocky Linux와 Ubuntu kernel에서 verifier, 운영 부하 및 강제 전원 장애 시험이 필요하다.

## [0.1.5] - 2026-09-28

### Fixed

- IPv4/IPv6 파서의 가변 패킷 포인터 연산을 `bpf_skb_load_bytes`와 길이 검사로 교체하여 kernel verifier의 프로그램 load 거부를 수정했다.
- BPF 프로그램 load 실패 시 verifier log 전체를 출력하도록 진단 정보를 보강했다.

### Verification

- Go 테스트, parser 회귀 테스트, 플랫폼별 빌드와 Ubuntu 6.8 kernel 실행을 검증했고 사용자 Ubuntu 서버에서도 정상 실행을 확인했다.

## [0.1.4] - 2026-09-25

- 선택한 물리 NIC 주소를 로컬 endpoint로 사용하는 flow만 기본 집계하도록 변경했다.
- Docker/Kubernetes workload IP 통신이 전역 TCP tracepoint 결과에 섞이는 문제를 줄였다.
- TCP handshake 완료 횟수와 packet·byte 집계를 로컬 CLI에서 조회하도록 제공했다.
