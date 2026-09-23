pipeline {
    agent none

    parameters {
        string(name: 'UBUNTU_BUILD_NODE_LABEL', defaultValue: 'linux && amd64 && ubuntu-build', description: 'Ubuntu amd64 node used to test and build the deb package')
        string(name: 'ROCKY_BUILD_NODE_LABEL', defaultValue: 'linux && amd64 && rocky-build', description: 'Rocky Linux amd64 node used to test and build the RPM package')
        string(name: 'NEXUS_CREDENTIALS_ID', defaultValue: 'nexus-credentials', description: 'Jenkins username/password credential used to publish release packages')
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
        stage('Test and build distributions') {
            parallel {
                stage('Ubuntu deb') {
                    agent { label "${params.UBUNTU_BUILD_NODE_LABEL}" }
                    steps {
                        checkout scm
                        sh 'for tool in git go make docker file clang curl gzip; do command -v "$tool"; done'
                        sh 'docker version'
                        script {
                            if (env.BRANCH_NAME?.startsWith('release/')) {
                                def branchVersion = env.BRANCH_NAME.substring('release/'.length())
                                def releaseVersion = readFile('VERSION').trim()
                                if (releaseVersion != branchVersion) {
                                    error("release branch ${env.BRANCH_NAME} does not match VERSION ${releaseVersion}")
                                }
                                currentBuild.displayName = "#${env.BUILD_NUMBER} v${releaseVersion}"
                                currentBuild.description = env.BRANCH_NAME
                            }
                        }
                        sh 'make package-image-deb'
                        sh 'make test'
                        sh 'make deb'
                        sh 'make checksums'
                        sh 'file dist/net-scouter-linux-amd64 dist/flow.bpf.o dist/deb/*.deb'
                        stash name: 'linux-amd64-release', includes: 'dist/**,scripts/verify-bpf-load.sh,Makefile', useDefaultExcludes: false
                        stash name: 'ubuntu-deb-package', includes: 'dist/deb/**,scripts/publish-deb.sh', useDefaultExcludes: false
                        archiveArtifacts artifacts: 'dist/net-scouter-linux-amd64,dist/flow.bpf.o,dist/SHA256SUMS,dist/deb/**', fingerprint: true
                    }
                }
                stage('Rocky RPM') {
                    agent { label "${params.ROCKY_BUILD_NODE_LABEL}" }
                    steps {
                        checkout scm
                        sh 'for tool in git go make docker file clang curl gzip; do command -v "$tool"; done'
                        sh 'docker version'
                        sh 'make package-image-rpm'
                        sh 'make test'
                        sh 'make rpm'
                        sh 'dist/net-scouter-linux-amd64 check'
                        sh 'file dist/net-scouter-linux-amd64 dist/flow.bpf.o dist/rpm/*.rpm'
                        stash name: 'rocky-rpm-package', includes: 'dist/rpm/**,scripts/publish-rpm.sh', useDefaultExcludes: false
                        archiveArtifacts artifacts: 'dist/rpm/**', fingerprint: true
                    }
                }
            }
        }

        stage('Publish release packages to Nexus') {
            when {
                beforeAgent true
                expression { env.BRANCH_NAME?.startsWith('release/') }
            }
            parallel {
                stage('Publish deb') {
                    agent { label "${params.UBUNTU_BUILD_NODE_LABEL}" }
                    steps {
                        deleteDir()
                        unstash 'ubuntu-deb-package'
                        withCredentials([usernamePassword(credentialsId: params.NEXUS_CREDENTIALS_ID, usernameVariable: 'NEXUS_USER', passwordVariable: 'NEXUS_PASS')]) {
                            sh 'SKIP_PACKAGE_BUILD=1 ./scripts/publish-deb.sh'
                        }
                    }
                }
                stage('Publish RPM') {
                    agent { label "${params.ROCKY_BUILD_NODE_LABEL}" }
                    steps {
                        deleteDir()
                        unstash 'rocky-rpm-package'
                        withCredentials([usernamePassword(credentialsId: params.NEXUS_CREDENTIALS_ID, usernameVariable: 'NEXUS_USER', passwordVariable: 'NEXUS_PASS')]) {
                            sh 'SKIP_PACKAGE_BUILD=1 ./scripts/publish-rpm.sh'
                        }
                    }
                }
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
