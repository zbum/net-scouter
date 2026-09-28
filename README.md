# net-scouter

현재 릴리스는 0.1.4입니다.

서버를 교체하거나 IP를 바꾸기 전에, 그 서버가 실제로 누구와 어떤 포트로 통신하는지 보는 도구입니다. 방화벽이나 ACL을 고칠 때 필요한 통신 관계를 트래픽에서 찾습니다.

패킷 내용은 보지 않습니다. 통신을 막거나 바꾸거나 다른 곳으로 보내지 않습니다. 관찰에 실패해도 기존 트래픽은 그대로 통과합니다.

관찰 시간 안에 실제로 발생한 통신만 알 수 있습니다. 그 구간에 쓰지 않은 백업 경로나 월간 배치는 결과에 나오지 않습니다.

설치와 명령은 [INSTALL.md](INSTALL.md), 동작 방식과 개발 절차는 [DEVELOP.md](DEVELOP.md)에 있습니다.

## 결과에서 보는 것

한 행은 ACL 후보 하나입니다.

- `ingress`는 상대가 이 서버의 포트로 들어온 접속입니다. `PORT`는 이 서버의 포트입니다.
- `egress`는 이 서버가 밖으로 연 접속입니다. `PORT`는 상대 서비스 포트입니다.
- 서버가 클라이언트에게 돌려보내는 패킷과, 상대 서버의 응답은 빠집니다.
- 출발 포트는 보이지 않습니다. 같은 방향, 같은 주소, 같은 서비스 포트는 한 행으로 합쳐집니다.
- 기본 화면의 TCP는 연결이 성립한 것만입니다. `127.0.0.1`끼리, 같은 주소끼리의 흐름은 빠집니다.

`CONNECTIONS`는 TCP가 `ESTABLISHED`까지 간 횟수입니다. UDP는 연결 개념이 없어서 `-`입니다. 패킷과 바이트는 그 행으로 합쳐진 누적값입니다.

에이전트는 시작할 때 `interfaces`에 지정한 NIC의 실제 IP를 읽고, 그 IP를 로컬 끝점으로 쓰는 흐름만 커널에서 집계하고 결과에 남깁니다. 따라서 일반 Docker·Kubernetes Pod IP를 쓰는 연결은 CIDR 설정 없이 빠집니다. `hostNetwork` Pod와 Docker host 네트워크 컨테이너는 호스트 IP를 공유하므로 구분할 수 없습니다. NAT 뒤의 workload 패킷이 호스트 IP로 보일 수 있어 TCP `PACKETS`·`BYTES`는 연결 수만큼 엄밀하게 귀속된 수치가 아닐 수 있습니다.

## 샘플

아래는 문서용 주소 대역을 사용한 예시입니다. 실제 시스템이나 캡처에서 가져온 값이 아닙니다.

```text
tcp connections: enabled (trace ABI 5.15)
durable storage: disabled
SRC                DST                PROTO  DIR      PORT  FIRST SEEN                 LAST SEEN                  PACKETS  BYTES  CONNECTIONS
192.0.2.10         198.51.100.20      TCP    ingress  22    2025-01-02T03:04:05Z       2025-01-02T03:05:10Z       98       8372   1
203.0.113.30       198.51.100.20      TCP    ingress  22    2025-01-02T03:04:15Z       2025-01-02T03:04:15Z       5        1336   1
192.0.2.40         198.51.100.20      TCP    ingress  9091  2025-01-02T03:04:25Z       2025-01-02T03:04:25Z       6        624    1
198.51.100.20      203.0.113.50       TCP    egress   443   2025-01-02T03:03:30Z       2025-01-02T03:04:50Z       10       668    1
```

이 샘플을 ACL로 읽으면 다음과 같습니다.

- `192.0.2.10`과 `203.0.113.30`은 이 서버의 TCP 22번으로 들어옵니다.
- `192.0.2.40`은 이 서버의 TCP 9091번으로 들어옵니다.
- 이 서버는 `203.0.113.50`의 TCP 443번으로 나갑니다.
- UDP는 기본 화면에 없습니다. `sudo net-scouter flows --protocol udp` 또는 `--protocol both`로 봅니다.

## 자주 쓰는 조회

서비스를 띄운 뒤 같은 서버에서 실행합니다. 조회는 root만 할 수 있습니다.

```bash
sudo net-scouter flows
sudo net-scouter flows --protocol udp
sudo net-scouter flows --protocol both
sudo net-scouter status
```

연결에 실패한 TCP 시도까지 보려면 `--attempts`를 붙입니다. 루프백과 같은 주소끼리의 흐름까지 보려면 `--local`을 붙입니다.

`--attempts`에는 NAT를 거쳐 호스트 IP로 보이는 workload 패킷도 포함될 수 있습니다. TCP 연결 검출을 사용할 수 없을 때 기본 조회에서는 성공 여부를 확인할 수 없는 TCP를 숨기며, 상태와 출력에 해당 오류를 표시합니다.

```bash
sudo net-scouter flows --protocol tcp --attempts
sudo net-scouter flows --local
```

기본 `mode: exporter`는 메모리 집계를 `127.0.0.1:9469/metrics`에 Prometheus 형식으로 제공합니다. 새 설정에서 표준출력 JSONL은 기본으로 내보내지 않습니다. 서비스를 재시작하면 이 모드의 기록은 사라집니다.

재시작 후에도 기록이 필요하면 `mode: persistent`로 바꾸십시오. 이 모드는 HTTP 포트를 열지 않고 `/var/lib/net-scouter/flows.db`에 bbolt 데이터를 5분마다 저장합니다. 정상 종료 시 마지막으로 다시 수집해 저장하며, 비정상 종료 시 마지막 성공 저장 이후의 기록은 잃을 수 있습니다. 기본 보존 기간은 마지막 관찰 후 720시간, 최대 항목은 65536개입니다. `maxBytes`는 디스크 사용 경고 기준이며 파일 크기를 강제로 제한하지 않습니다. 서비스가 멈춘 상태에서도 `sudo net-scouter flows`가 저장된 기록을 읽습니다.

```yaml
mode: persistent
storage:
  path: /var/lib/net-scouter/flows.db
  flushInterval: 5m
  retention: 720h
  maxEntries: 65536
  maxBytes: 67108864
```

기존 `export: {type: stdout}` 설정은 계속 받아들이며, 이를 명시한 경우에만 변경된 누적 행을 JSONL로 추가 출력합니다. `sudo net-scouter status`는 현재 모드와 저장 또는 exporter 상태를 보여 줍니다.

## 결과에서 CIDR 제외

`exclude.ingress.sources`는 서버에 들어오는 연결의 상대 IP를, `exclude.egress.destinations`는 서버가 접속하는 상대 IP를 기준으로 거릅니다. 필요하면 각 방향의 `sources`와 `destinations`를 모두 지정할 수 있습니다. 지정한 목록 중 하나라도 일치하면 그 행은 조회·metrics·저장·선택적 표준출력에서 빠집니다. IPv4와 IPv6 CIDR을 사용할 수 있습니다.

```yaml
exclude:
  destinations: []
  workloadCIDRs: []
  ingress:
    sources: [192.0.2.0/24]
    destinations: []
  egress:
    sources: []
    destinations: [2001:db8:1::/48]
```

기존 `exclude.destinations`는 방향과 관계없이 목적지에 적용되고, `workloadCIDRs`는 양쪽 주소가 모두 해당 CIDR에 들어올 때만 제외합니다. 설정을 바꾸면 에이전트를 재시작하십시오. `net-scouter status`에서 적용된 목록을 확인할 수 있습니다.
