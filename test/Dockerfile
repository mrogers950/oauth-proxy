FROM centos:7
ADD . /bin
ENTRYPOINT [ "/bin/oauth-proxy" ]
ENV OPENSHIFT_BUILD_NAME oauth-proxy-5
ENV OPENSHIFT_BUILD_NAMESPACE ci
ENV PATH /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
