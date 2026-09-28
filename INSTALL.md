# 설치와 사용

## 수정 빌드 적용 및 로그 확인

바이너리와 `/usr/lib/net-scouter/flow.bpf.o`를 함께 교체해야 BPF 수정이 적용됩니다. `make build-all`은 deb 패키지를 갱신하지 않습니다. 같은 릴리스의 수정 패키지는 `DEB_REVISION=2 make deb`처럼 revision을 지정해 새로 빌드하십시오. 실제 버전과 파일 경로는 `dist/deb/latest.env`에서 확인합니다.

```bash
sudo apt install ./net-scouter_0.1.6-1_amd64.deb
sudo systemctl restart net-scouter
sudo net-scouter status
sudo journalctl -u net-scouter -n 100 --no-pager
```

파일명은 생성된 패키지에 맞춰 바꾸십시오. 같은 버전을 재설치할 때는 `apt install --reinstall`을 사용합니다. 서비스가 이전 직접 설치본을 실행하는지 확인하려면 `systemctl show net-scouter -p ExecStart -p FragmentPath`를 실행합니다. deb의 실행 파일은 `/usr/bin/net-scouter`입니다. BPF verifier 오류가 나면 수정된 바이너리가 출력하는 전체 로그와 `uname -r` 결과를 함께 확인하십시오.

Rocky Linux 8.10 / RHEL 8 계열과 Ubuntu 22.04 이상을 대상으로 합니다. 배포판 버전보다 커널의 eBPF, BTF, TC 기능이 중요합니다. 패키지는 서비스를 자동으로 시작하지 않습니다.

## 배포 패키지

빌드 결과의 deb 또는 RPM과 같은 이름의 `.sha256` 파일을 신뢰할 수 있는 릴리스 채널에서 함께 받아 checksum을 확인한 뒤 설치하십시오. 저장소에는 특정 조직의 내부 패키지 서버 주소나 자격증명이 포함되지 않습니다.

```bash
sha256sum --check net-scouter_*.deb.sha256
sha256sum --check net-scouter-*.rpm.sha256
sudo apt install ./net-scouter_*.deb        # Ubuntu
sudo dnf install ./net-scouter-*.rpm        # Rocky Linux / RHEL
```

현재 RPM은 서명하지 않습니다. `gpgcheck=0`인 yum/dnf 저장소 설정을 배포하지 마십시오. 운영 저장소로 제공하려면 RPM과 저장소 메타데이터를 서명하고, 공개 키를 별도의 신뢰 경로로 배포한 뒤 `gpgcheck=1`과 `repo_gpgcheck=1`을 사용하십시오.

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

`capture.ipv6: false`처럼 주소 체계나 TCP/UDP 중 하나만 끌 수 있습니다. 둘 다 끄면 시작이 거부됩니다. ICMP는 아직 지원하지 않으므로 `false`여야 합니다.

목적지 CIDR은 목적지가 맞으면 빠집니다. workload CIDR은 양쪽 주소가 모두 그 대역일 때만 빠집니다. `allowVirtualInterfaces: true`를 명시하지 않으면 가상 인터페이스는 거부됩니다.

## 실행

```bash
sudo net-scouter check
sudo systemctl start net-scouter
sudo systemctl status net-scouter --no-pager
```

`check`는 OS, BPF syscall, bpffs, BTF, TCP state tracepoint, euid, 읽을 수 있는 커널 설정을 보여 줍니다. 지원하지 않는 OS이거나 BPF syscall이 없으면 실패합니다. 그 외 빠진 항목은 경고입니다.

실행 중에는 설정한 인터페이스의 ingress와 egress에 이 프로세스가 붙인 필터가 있습니다. 종료하면 그 필터만 지우고, clsact qdisc는 남길 수 있습니다. 이미 있는 필터와 충돌하면 기존 필터를 바꾸지 않고 수집을 멈춥니다. 동시에 두 프로세스는 뜨지 않습니다. Linux에서는 `/run/net-scouter.lock`을 사용합니다.

앞 터미널에서 직접 실행할 수도 있습니다. `mode: exporter`에서는 `127.0.0.1:9469/metrics`에서 Prometheus 텍스트를 읽습니다. 표준출력 JSONL은 설정에 `export: {type: stdout}`을 명시한 이전 형식에서만 추가로 나갑니다.

```bash
sudo net-scouter run --config /etc/net-scouter/net-scouter.yaml
```

## 조회

조회 소켓은 `/run/net-scouter/query.sock`이고 root만 열 수 있습니다. 에이전트가 없으면 `status`는 `/run/net-scouter/status.json`을 읽습니다. 이 파일에는 흐름 목록이 없고, 프로세스가 없으면 오래된 상태로 표시됩니다. `mode: persistent`인 경우 `flows`는 저장된 DB를 읽어 오프라인에서도 결과를 표시합니다. exporter 모드에는 오프라인 이력이 없습니다.

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
| `--protocol` | `tcp` | `tcp`, `udp`, `both` |
| `--attempts` | 끄기 | 현재 수집 원본에서 성립하지 않은 TCP 시도도 표시. 영속/metrics 집계에는 성립한 TCP와 UDP만 포함 |
| `--local` | 끄기 | 루프백, 출발지와 도착지가 같은 흐름, 설정한 NIC 주소끼리의 흐름도 표시 |
| `--format` | `table` | `table`, `json`, `jsonl` |
| `--config` | `/etc/net-scouter/net-scouter.yaml` | NIC 주소와 오프라인 DB 경로·제외 규칙을 읽을 설정 파일 |

에이전트는 선택한 NIC의 IP를 시작할 때 읽습니다. 주소가 없거나 조회에 실패하면 수집을 시작하지 않으므로, IP 변경 후에는 서비스를 재시작하십시오. `status`에서 적용된 `host addresses`를 확인할 수 있습니다. TCP 연결 집계를 쓸 수 없으면 연결 수는 `0`이 아니라 `n/a` 또는 JSON `null`이며, 기본 조회에서는 성공 여부를 확인할 수 없는 TCP를 숨깁니다. 에이전트를 띄우기 전에 이미 연결되어 있던 TCP는 연결 수가 0이라 기본 화면에는 없고, `--attempts`로 볼 수 있습니다.

방향별 제외는 `/etc/net-scouter/net-scouter.yaml`의 `exclude.ingress.sources`, `exclude.ingress.destinations`, `exclude.egress.sources`, `exclude.egress.destinations`에 CIDR 목록으로 지정합니다. 예를 들어 `ingress.sources: [192.0.2.0/24]`는 해당 출발지에서 들어오는 행만 제외합니다. 어느 한 목록이라도 일치하면 조회·metrics·영속 저장·선택적 표준출력에서 빠집니다. 기존 `exclude.destinations`는 양방향 목적지 제외, `workloadCIDRs`는 양쪽 주소가 같은 workload CIDR 집합에 속하는 경우의 제외로 유지됩니다. 변경 후 서비스를 재시작하고 `sudo net-scouter status`에서 적용 목록을 확인하십시오.

`net-scouter report`는 아직 없습니다.

## 데이터가 남는 곳

커널 집계는 LRU 해시 맵에 있고 기본 상한은 65536개입니다. `mode: exporter`는 메모리 집계를 Prometheus `/metrics`로 제공하며 재시작 후 기록은 사라집니다. `exporter.listen` 기본값은 `127.0.0.1:9469`, `exporter.maxFlows` 기본값은 4096입니다. 원격 수집이 필요하면 접근 제어가 있는 프록시 또는 명시적으로 허용한 주소를 사용하십시오.

`mode: persistent`는 `/var/lib/net-scouter/flows.db`에 bbolt로 저장합니다. systemd는 `/var/lib/net-scouter`를 `0700`으로 만들고 DB는 `0600`입니다. 기본 저장 간격 5분, 비활성 이력 보존 720시간, 최대 65536행입니다. 한도 초과 항목은 오래 관찰되지 않은 순서로 제거합니다. `storage.maxBytes` 기본값 67108864바이트는 운영 경고 기준이며 디스크를 강제로 제한하지 않습니다. 마지막 성공 저장 이후에 비정상 종료하면 그 사이의 기록은 사라질 수 있습니다. 저장 오류는 `status`의 degraded 상태로 표시되고 다음 주기에 다시 시도합니다. 시작 시 손상된 DB나 잠금 실패는 수집 시작을 중단합니다.

`/run/net-scouter/status.json`은 실행 상태만 담는 임시 파일입니다. `export.type: stdout`은 이전 설정과 호환되며, 명시한 경우에만 바뀐 누적 행을 JSONL로 추가 출력합니다.

## 패키지를 만들 때

릴리스 버전은 루트의 `VERSION` 파일입니다. `release/<version>`에서 이 값을 올리고 `main`과 `develop`에 머지합니다. 현재 릴리스는 `0.1.6`입니다. `VERSION`이 없는 개발 빌드만 `0.0.0+UTC시각.git해시`를 쓰며, apt와 dnf는 그 형식도 이전 `0+git` 패키지보다 새로운 것으로 봅니다.

BPF 컴파일은 로컬 이미지 `net-scouter-deb-build:22.04`와 `net-scouter-rpm-build:8`을 사용합니다. 없으면 한 번 만들고, 이후에는 다시 받지 않습니다. Dockerfile을 바꾸면 `make package-images`로 다시 만듭니다.

```bash
make package-images
NEXUS_USER=... NEXUS_PASS=... make publish-deb
NEXUS_USER=... NEXUS_PASS=... make publish-rpm
```

`GOARCH=arm64`는 각각 arm64와 aarch64 패키지입니다. 기본은 amd64와 x86_64입니다. yum 저장소 이름은 `yum-hosted`이고 경로는 `net-scouter/`입니다. apt 저장소 이름은 `apt-hosted`이고 Distribution은 `stable`입니다.
