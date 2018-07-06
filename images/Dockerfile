#oit## This file is managed by the OpenShift Image Tool: https://github.com/openshift/enterprise-images
#oit## by the OpenShift Continuous Delivery team (#aos-cd-team on IRC).
#oit## 
#oit## Any yum repos listed in this file will effectively be ignored during CD builds.
#oit## Yum repos must be enabled in the oit configuration files.
#oit## Some aspects of this file may be managed programmatically. For example, the image name, labels (version,
#oit## release, and other), and the base FROM. Changes made directly in distgit may be lost during the next
#oit## reconciliation.
#oit## 
FROM rhel7:7-released

RUN yum-config-manager --enable rhel-7-server-ose-3.8-rpms && \
    yum install -y golang-github-openshift-oauth-proxy && \
    yum clean all

ENTRYPOINT   [ "/bin/oauth-proxy" ]

LABEL \
        com.redhat.component="golang-github-openshift-oauth-proxy-docker" \
        io.k8s.description="OpenShift OAuth Proxy." \
        maintainer="OpenShift Development <dev@lists.openshift.redhat.com>" \
        name="openshift3/oauth-proxy" \
        License="GPLv2+" \
        io.k8s.display-name="OpenShift OAuth Proxy" \
        version="v3.10.0" \
        architecture="x86_64" \
        release="0.32.0.0" \
        vendor="Red Hat" \
        io.openshift.tags="oauth"

