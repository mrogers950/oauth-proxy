#!/bin/bash -x
set -e

DOCKER_REPO=localhost:5000
TESTDIR=test
REV=$(git rev-parse --short HEAD)
DOCKER_IMG=${DOCKER_REPO}/oauth-proxy-${REV}:latest
KUBECONFIG=~/admin.kubeconfig

oc login -u system:admin
go build -o ${TESTDIR}/oauth-proxy
docker build -t ${DOCKER_IMG} ${TESTDIR}/
docker push ${DOCKER_IMG}
go test -c github.com/openshift/oauth-proxy/test/e2e -o ${TESTDIR}/e2e.test
${TESTDIR}/e2e.test
