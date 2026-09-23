FROM rockylinux:8

RUN dnf install -y clang make rpm-build \
	&& dnf clean all
