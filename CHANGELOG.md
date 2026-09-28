# Changelog

이 문서는 `net-scouter`의 사용자 관점 변경 사항을 기록한다.

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

## [0.1.4] - 2026-09-25

- 선택한 물리 NIC 주소를 로컬 endpoint로 사용하는 flow만 기본 집계하도록 변경했다.
- Docker/Kubernetes workload IP 통신이 전역 TCP tracepoint 결과에 섞이는 문제를 줄였다.
- TCP handshake 완료 횟수와 packet·byte 집계를 로컬 CLI에서 조회하도록 제공했다.
