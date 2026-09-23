pipeline {
    agent none

    parameters {
        string(name: 'BUILD_NODE_LABEL', defaultValue: 'linux && amd64 && ubuntu-build', description: 'Ubuntu amd64 node used for tests and release builds')
        booleanParam(name: 'RUN_ROCKY_USERSPACE_CHECK', defaultValue: true, description: 'Run artifacts in an unprivileged Rocky Linux 8.10 container')
        booleanParam(name: 'RUN_KERNEL_VERIFIERS', defaultValue: false, description: 'Opt in to non-attaching kernel verifier gates on dedicated nodes')
        string(name: 'UBUNTU_VERIFIER_LABEL', defaultValue: 'linux && amd64 && ubuntu-22 && ebpf-verifier', description: 'Dedicated Ubuntu 22.04+ verifier node')
        string(name: 'ROCKY_VERIFIER_LABEL', defaultValue: 'linux && amd64 && rocky-8 && ebpf-verifier', description: 'Dedicated Rocky 8.10+ verifier node')
    }

    options {
        disableConcurrentBuilds()
        skipDefaultCheckout(true)
        timestamps()
        timeout(time: 30, unit: 'MINUTES')
    }

    stages {
        stage('Test and build on Ubuntu') {
            agent { label "${params.BUILD_NODE_LABEL}" }
            steps {
                checkout scm
                sh 'make test-ci'
                sh 'file dist/net-scouter-linux-amd64 dist/flow.bpf.o'
                stash name: 'linux-amd64-release', includes: 'dist/**,scripts/verify-bpf-load.sh,Makefile', useDefaultExcludes: false
                archiveArtifacts artifacts: 'dist/**', fingerprint: true
            }
        }

        stage('Rocky 8.10 userspace compatibility') {
            when {
                beforeAgent true
                expression { params.RUN_ROCKY_USERSPACE_CHECK }
            }
            agent { label "${params.BUILD_NODE_LABEL}" }
            steps {
                deleteDir()
                unstash 'linux-amd64-release'
                sh 'make verify-rocky-userspace'
            }
        }

        stage('Kernel verifier deployment gates') {
            when {
                beforeAgent true
                expression { params.RUN_KERNEL_VERIFIERS }
            }
            parallel {
                stage('Ubuntu verifier load') {
                    agent { label "${params.UBUNTU_VERIFIER_LABEL}" }
                    steps {
                        deleteDir()
                        unstash 'linux-amd64-release'
                        sh 'sudo -n make verify-bpf-load'
                    }
                }
                stage('Rocky verifier load') {
                    agent { label "${params.ROCKY_VERIFIER_LABEL}" }
                    steps {
                        deleteDir()
                        unstash 'linux-amd64-release'
                        sh 'sudo -n make verify-bpf-load'
                    }
                }
            }
        }
    }
}
