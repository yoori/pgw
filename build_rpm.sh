#!/bin/bash


NAME=tel-gateway
VERSION=1.0.0
RELEASE=53
SUDO_PREFIX=sudo

# script require 'sudo rpm' for install RPM packages
# create build/RPMS folder - all built packages will be duplicated here
RES_TMP=build_rpm/TMP/
RES_RPMS=build_rpm/RPMS/

rm -rf "$RES_TMP" >/dev/null 2>&1
mkdir -p $RES_TMP
mkdir -p $RES_RPMS

# download and install packages required for build
$SUDO_PREFIX yum -y install yum-utils rpmdevtools redhat-rpm-config rpm-build epel-rpm-macros || \
  { echo "can't install RPM build packages" >&2 ; exit 1 ; }

# create folders for RPM build environment
mkdir -vp $(rpm -E '%_tmppath %_rpmdir %_builddir %_sourcedir %_specdir %_srcrpmdir %_rpmdir/%_arch')

BIN_RPM_FOLDER=$(rpm -E '%_rpmdir/%_arch')
SPEC_FILE=$(rpm -E %_specdir)/"$NAME.spec"

rm -f "$SPEC_FILE" >/dev/null 2>&1

RPM_SOURCES_DIR=`rpm -E %_sourcedir`

cat << "EOF" > $SPEC_FILE
Name:   %{PRODUCT_NAME}
Version: %{PRODUCT_VERSION}
Release: %{PRODUCT_RELEASE}
Summary: Telecom gateway
Group:   Development/Libraries
License: Specific
Source0: %{name}-%{version}-%{release}.tar.gz

Requires: pcre libpcap libxcrypt openssl-libs pam
Requires: glibc libtalloc shadow-utils libcom_err
BuildRequires: openssl-devel openssl-libs brotli-devel libcom_err-devel
BuildRequires: lksctp-tools-devel rapidjson-devel libkqueue-devel

%define __install_dir /opt/tel-gateway

BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot

%description


%prep
%setup -q -n %{name}-%{version}-%{release}


%build
mkdir build
pushd build
cmake3 .. -DINSTALL_PREFIX=/opt/tel-gateway/
cmake3 --build . -j
popd


%install
%__rm -rf %buildroot
%__mkdir_p %{buildroot}%{__install_dir}
pushd build
cmake3 --install . --prefix "%{buildroot}"
popd

mkdir -p "%{buildroot}%{__install_dir}/var/run/radiusd/"
mkdir -p "%{buildroot}%{__install_dir}/var/log/radius/"
rm -rf files.list
find %{buildroot}%{__install_dir} -type f -printf "%{__install_dir}/%%P\n" >>files.list
find %{buildroot}%{__install_dir} -type l -printf "%{__install_dir}/%%P\n" >>files.list
find %{buildroot}/usr/lib/systemd -type f -printf "/usr/lib/systemd/%%P\n" >>files.list
cp files.list /tmp/files.list


%clean
rm -rf %{buildroot}


%files -n %{name} -f files.list
%defattr(-,root,root)

%defattr(-, tel_gateway, tel_gateway)
/opt/tel-gateway/var/run/radiusd/
/opt/tel-gateway/var/log/radius/

%pre
# add tel_gateway user for run service
getent group tel_gateway >/dev/null || \
  /usr/sbin/groupadd -r -g 1111 tel_gateway > /dev/null 2>&1
getent passwd tel_gateway >/dev/null || \
  /usr/sbin/useradd  -r -g tel_gateway -u 1111 -c "tel_gateway user" \
    -d /opt/tel_gateway -s /sbin/nologin tel_gateway >/dev/null 2>&1


EOF


rm -rf "$RES_TMP/$NAME-$VERSION-$RELEASE"
mkdir "$RES_TMP/$NAME-$VERSION-$RELEASE"

# push sources for pack
rsync -av --exclude '/build' --exclude '/build_rpm' \
  --exclude ".git" --exclude ".svn" \
  ./ "$RES_TMP/$NAME-$VERSION-$RELEASE/"

pushd "$RES_TMP"
tar -czvf "$RPM_SOURCES_DIR/$NAME-$VERSION-$RELEASE.tar.gz" "$NAME-$VERSION-$RELEASE"
popd

$SUDO_PREFIX yum-builddep -y \
  --define "PRODUCT_NAME $NAME" \
  --define "PRODUCT_VERSION $VERSION" \
  --define "PRODUCT_RELEASE $RELEASE" \
  "$SPEC_FILE" || \
  { echo "can't install build requirements" >&2 ; exit 1 ; }

rpmbuild --force -ba \
  --define "PRODUCT_NAME $NAME" \
  --define "PRODUCT_VERSION $VERSION" \
  --define "PRODUCT_RELEASE $RELEASE" \
  "$SPEC_FILE" || \
  { echo "can't build RPM" >&2 ; exit 1 ; }

cp $BIN_RPM_FOLDER/$NAME-$VERSION-$RELEASE*.rpm $RES_RPMS/
