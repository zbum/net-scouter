pipeline {
    agent none

    parameters {
        booleanParam(name: 'RUN_KERNEL_VERIFIERS', defaultValue: false, description: 'Opt in to non-attaching kernel verifier gates on dedicated nodes')
    }

    environment {
        NEXUS_CREDENTIALS_ID = 'nexus-credentials'
    }

    options {
        disableConcurrentBuilds()
        skipDefaultCheckout(true)
        timestamps()
        timeout(time: 30, unit: 'MINUTES')
    }

    stages {
        stage('Reject untrusted change requests') {
            when {
                beforeAgent true
                changeRequest()
            }
            steps {
                error('This Jenkins pipeline does not execute repository code from change requests')
            }
        }

        stage('Test and build distributions') {
            when {
                beforeAgent true
                not { changeRequest() }
            }
            parallel {
                stage('Ubuntu deb') {
                    agent { label 'linux && amd64 && ubuntu-build' }
                    steps {
                        checkout scm
                        sh 'for tool in git go make docker file clang curl gzip; do command -v "$tool"; done'
                        sh 'make check-go-version'
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
                        stash name: 'linux-amd64-release', includes: 'dist/**', useDefaultExcludes: false
                        stash name: 'ubuntu-deb-package', includes: 'dist/deb/**,scripts/publish-deb.sh', useDefaultExcludes: false
                        archiveArtifacts artifacts: 'dist/net-scouter-linux-amd64,dist/flow.bpf.o,dist/SHA256SUMS,dist/deb/**', fingerprint: true
                    }
                }
                stage('Rocky RPM') {
                    agent { label 'linux && amd64 && rocky-build' }
                    steps {
                        checkout scm
                        sh 'for tool in git go make docker file clang curl gzip; do command -v "$tool"; done'
                        sh 'make check-go-version'
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
                allOf {
                    not { changeRequest() }
                    expression { env.BRANCH_NAME?.startsWith('release/') }
                }
            }
            parallel {
                stage('Publish deb') {
                    agent { label 'linux && amd64 && ubuntu-build' }
                    steps {
                        deleteDir()
                        unstash 'ubuntu-deb-package'
                        withCredentials([usernamePassword(credentialsId: env.NEXUS_CREDENTIALS_ID, usernameVariable: 'NEXUS_USER', passwordVariable: 'NEXUS_PASS')]) {
                            sh 'SKIP_PACKAGE_BUILD=1 ./scripts/publish-deb.sh'
                        }
                    }
                }
                stage('Publish RPM') {
                    agent { label 'linux && amd64 && rocky-build' }
                    steps {
                        deleteDir()
                        unstash 'rocky-rpm-package'
                        withCredentials([usernamePassword(credentialsId: env.NEXUS_CREDENTIALS_ID, usernameVariable: 'NEXUS_USER', passwordVariable: 'NEXUS_PASS')]) {
                            sh 'SKIP_PACKAGE_BUILD=1 ./scripts/publish-rpm.sh'
                        }
                    }
                }
            }
        }

        stage('Kernel verifier deployment gates') {
            when {
                beforeAgent true
                allOf {
                    not { changeRequest() }
                    expression { params.RUN_KERNEL_VERIFIERS }
                }
            }
            parallel {
                stage('Ubuntu verifier load') {
                    agent { label 'linux && amd64 && ubuntu-22 && ebpf-verifier' }
                    steps {
                        deleteDir()
                        unstash 'linux-amd64-release'
                        sh 'sudo -n /usr/local/sbin/net-scouter-verify-bpf-load "$PWD/dist/flow.bpf.o"'
                    }
                }
                stage('Rocky verifier load') {
                    agent { label 'linux && amd64 && rocky-8 && ebpf-verifier' }
                    steps {
                        deleteDir()
                        unstash 'linux-amd64-release'
                        sh 'sudo -n /usr/local/sbin/net-scouter-verify-bpf-load "$PWD/dist/flow.bpf.o"'
                    }
                }
            }
        }
    }
}
