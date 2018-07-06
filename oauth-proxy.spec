%global debug_package	%{nil}
%global snapshot	1

%if ! 0%{?gobuild:1}
%define gobuild(o:) go build -ldflags "${LDFLAGS:-} -B 0x$(head -c20 /dev/urandom|od -An -tx1|tr -d ' \\n')" -a -v -x %{?**};
%endif

%global provider	github
%global provider_tld	com
%global project		openshift
%global repo		oauth-proxy
# github.com/openshift/oauth-proxy
%global provider_prefix	%{provider}.%{provider_tld}/%{project}/%{repo}
%global import_path	%{provider_prefix}
%global commit		57b6863264c89307830fccadf2f122e5cea3d2a0
%global shortcommit	%(c=%{commit}; echo ${c:0:8})
%global build_gopath    %{_builddir}/%{repo}-%{shortcommit}-gopath

Name:		golang-%{provider}-%{project}-%{repo}
Version:	2.3
Release:	1.git%{shortcommit}%{?dist}
Summary:	A reverse proxy that provides authentication with OpenShift and other OAuth providers
License:	MIT
URL:		https://%{provider}.%{provider_tld}/%{project}/%{repo}
Source0:	https://%{provider_prefix}/archive/%{commit}/%{repo}-%{commit}.tar.gz

# e.g. el6 has ppc64 arch without gcc-go, so EA tag is required
ExclusiveArch:  %{?go_arches:%{go_arches}}%{!?go_arches:%{ix86} x86_64 aarch64 %{arm} ppc64le s390x}
BuildRequires:	%{?go_compiler:compiler(go-compiler)}%{!?go_compiler:golang}

Provides:       %{repo} = %{version}-%{release}

%description
%{summary}

%prep
%setup -q -n %{repo}-%{commit}

%build
mkdir -p %{build_gopath}/src/%{provider}.%{provider_tld}/%{project}
ln -s ../../../../%{repo}-%{commit} %{build_gopath}/src/%{import_path}

# Ensure the default GOBIN is used ${GOPATH}/bin
unset GOBIN
export GOPATH=%{build_gopath}
export LDFLAGS='-s -w'
%gobuild %{import_path}

%install
install -d %{buildroot}%{_bindir}
install -D -p -m 0755 %{_builddir}/%{repo}-%{commit}/%{repo} %{buildroot}/%{_bindir}/%{repo}

%files
%license LICENSE
%{_bindir}/%{repo}

%changelog
* Thu Apr 12 2018 Simo Sorce <simo@redhat.com> - 2.3-1.git57b68632
- New release
