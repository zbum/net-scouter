# 설치와 사용

Rocky Linux 8.10 / RHEL 8 계열과 Ubuntu 22.04 이상을 대상으로 합니다. 배포판 버전보다 커널의 eBPF, BTF, TC 기능이 중요합니다. 패키지는 서비스를 자동으로 시작하지 않습니다.

## Ubuntu

Nexus apt 저장소 `apt-hosted`의 Distribution은 `stable`이어야 합니다. 저장소 서명에 쓴 공개 키가 필요합니다.

```bash
sudo install -d -m 0755 /etc/apt/keyrings
sudo gpg --dearmor -o /etc/apt/keyrings/manty-apt.gpg < public.gpg.key
echo 'deb [signed-by=/etc/apt/keyrings/manty-apt.gpg] https://nexus.manty.co.kr/repository/apt-hosted/ stable main' \
  | sudo tee /etc/apt/sources.list.d/net-scouter.list
sudo apt update
sudo apt install net-scouter
```

이미 설치되어 있으면 다음으로 올립니다.

```bash
sudo apt update
sudo apt install --only-upgrade net-scouter
sudo systemctl restart net-scouter
```

## Rocky Linux / RHEL

Nexus yum 저장소는 패키지 디렉터리 아래에 repodata가 있습니다.

```bash
cat >/etc/yum.repos.d/net-scouter.repo <<'EOF'
[net-scouter]
name=net-scouter
baseurl=https://nexus.manty.co.kr/repository/yum-hosted/net-scouter/
enabled=1
gpgcheck=0
EOF
dnf install net-scouter
```

RPM은 서명하지 않습니다.

## 직접 설치

```bash
make build-release
sudo make install
sudo cp /etc/net-scouter/net-scouter.yaml.example /etc/net-scouter/net-scouter.yaml
```

## 설정

예제는 `configs/net-scouter.yaml`입니다. 패키지를 설치하면 `/etc/net-scouter/net-scouter.yaml`입니다.

기본 라우트가 사용하는 인터페이스만 넣습니다. `lo`, `docker0`, `veth*`는 넣지 않습니다.

```bash
ip route show default
```

```yaml
interfaces:
  - enp2s0
```

목적지 CIDR은 목적지가 맞으면 빠집니다. workload CIDR은 양쪽 주소가 모두 그 대역일 때만 빠집니다. `allowVirtualInterfaces: true`를 명시하지 않으면 가상 인터페이스는 거부됩니다.

## 실행

```bash
sudo net-scouter check
sudo systemctl start net-scouter
sudo systemctl status net-scouter --no-pager
```

`check`는 OS, BPF syscall, bpffs, BTF, TCP state tracepoint, euid, 읽을 수 있는 커널 설정을 보여 줍니다. 지원하지 않는 OS이거나 BPF syscall이 없으면 실패합니다. 그 외 빠진 항목은 경고입니다.

실행 중에는 설정한 인터페이스의 ingress와 egress에 이 프로세스가 붙인 필터가 있습니다. 종료하면 그 필터만 지우고, clsact qdisc는 남길 수 있습니다. 이미 있는 필터와 충돌하면 기존 필터를 바꾸지 않고 수집을 멈춥니다. 동시에 두 프로세스는 뜨지 않습니다. Linux에서는 `/run/net-scouter.lock`을 사용합니다.

앞 터미널에서 직접 실행할 수도 있습니다. 바뀐 행은 표준출력으로 JSON 한 줄씩 나갑니다.

```bash
sudo net-scouter run --config /etc/net-scouter/net-scouter.yaml
```

## 조회

조회 소켓은 `/run/net-scouter/query.sock`이고 root만 열 수 있습니다. 에이전트가 없으면 `status`는 `/run/net-scouter/status.json`을 읽습니다. 이 파일에는 흐름 목록이 없고, 프로세스가 없으면 오래된 상태로 표시됩니다.

```bash
sudo net-scouter status
sudo net-scouter status --format json
sudo net-scouter flows
sudo net-scouter flows --protocol tcp
sudo net-scouter flows --protocol udp
sudo net-scouter flows --protocol both
sudo net-scouter flows --attempts
sudo net-scouter flows --local
sudo net-scouter flows --format json
sudo net-scouter flows --format jsonl
```

| 옵션 | 기본값 | 의미 |
|---|---|---|
| `--protocol` | `both` | `tcp`, `udp`, `both` |
| `--attempts` | 끄기 | 성립하지 않은 TCP 시도도 표시 |
| `--local` | 끄기 | 루프백, 출발지와 도착지가 같은 흐름, 설정한 NIC 주소끼리의 흐름도 표시 |
| `--format` | `table` | `table`, `json`, `jsonl` |
| `--config` | `/etc/net-scouter/net-scouter.yaml` | NIC 주소를 찾을 설정 파일 |

TCP 연결 집계를 쓸 수 없으면 연결 수는 `0`이 아니라 `n/a` 또는 JSON `null`입니다. 에이전트를 띄우기 전에 이미 연결되어 있던 TCP는 연결 수가 0이라 기본 화면에는 없고, `--attempts`로 볼 수 있습니다.

`net-scouter report`는 아직 없습니다.

## 데이터가 남는 곳

흐름 집계는 커널의 LRU 해시 맵에만 있습니다. 기본 상한은 65536개이고, 시작할 때 한 번 잡히며 그 이상으로 커지지 않습니다. 크기는 10MB 안팎입니다. 꽉 차면 가장 오래 안 보인 항목을 버립니다. 서비스를 재시작하면 맵도 사라집니다.

표준출력 JSONL은 바뀐 행만 내보냅니다. 파일 경로는 설정할 수 없습니다. `/run/net-scouter/status.json`은 실행 상태와 마지막 오류만 담는 임시 파일입니다.

## 패키지를 만들 때

버전은 `0.0.0+UTC시각.git해시`입니다. apt와 dnf는 이 형식을 이전의 `0+git` 버전보다 새로운 것으로 봅니다.

BPF 컴파일은 로컬 이미지 `net-scouter-deb-build:22.04`와 `net-scouter-rpm-build:8`을 사용합니다. 없으면 한 번 만들고, 이후에는 다시 받지 않습니다. Dockerfile을 바꾸면 `make package-images`로 다시 만듭니다.

```bash
make package-images
NEXUS_USER=... NEXUS_PASS=... make publish-deb
NEXUS_USER=... NEXUS_PASS=... make publish-rpm
```

`GOARCH=arm64`는 각각 arm64와 aarch64 패키지입니다. 기본은 amd64와 x86_64입니다. yum 저장소 이름은 `yum-hosted`이고 경로는 `net-scouter/`입니다. apt 저장소 이름은 `apt-hosted`이고 Distribution은 `stable`입니다.
