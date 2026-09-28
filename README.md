# net-scouter

## 변경 이력

- 2026-09-28 — `bugfix/bpf-verifier-pointer-bounds`: IPv4/IPv6 파서의 가변 패킷 포인터 연산을 `bpf_skb_load_bytes`와 길이 검사로 교체하여 커널 verifier의 프로그램 로드 거부를 수정했습니다. 로드 실패 시 verifier 로그 전체를 출력합니다. Go 테스트, 파서 회귀 테스트, 플랫폼별 빌드와 Ubuntu 6.8 커널 실행을 검증했고 사용자 Ubuntu 서버에서도 정상 실행을 확인했습니다.


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

아래는 `enp2s0`의 주소가 `192.168.31.102`인 서버에서 `sudo net-scouter flows`를 실행했을 때의 형태입니다. 숫자는 읽기 위한 예시입니다.

```text
tcp connections: enabled (trace ABI 5.15)
durable storage: unavailable
SRC                DST                PROTO  DIR      PORT  FIRST SEEN                 LAST SEEN                  PACKETS  BYTES  CONNECTIONS
192.168.31.1       192.168.31.102     TCP    ingress  22    2026-09-24T00:06:35+09:00  2026-09-24T00:07:23+09:00  98       8372   1
106.75.153.103     192.168.31.102     TCP    ingress  22    2026-09-23T23:40:03+09:00  2026-09-23T23:40:03+09:00  5        1336   1
192.168.31.6       192.168.31.102     TCP    ingress  9091  2026-09-23T23:39:26+09:00  2026-09-23T23:39:26+09:00  6        624    1
192.168.31.102     34.120.177.193     TCP    egress   443   2026-09-23T23:37:36+09:00  2026-09-23T23:39:07+09:00  10       668    1
```

이 샘플을 ACL로 읽으면 다음과 같습니다.

- `192.168.31.1`과 `106.75.153.103`은 이 서버의 TCP 22번으로 들어옵니다.
- `192.168.31.6`은 이 서버의 TCP 9091번으로 들어옵니다.
- 이 서버는 `34.120.177.193`의 TCP 443번으로 나갑니다.
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

집계는 커널 메모리에만 있습니다. 서비스를 재시작하면 그때까지 모은 행은 사라집니다.
