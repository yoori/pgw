#!/bin/bash

INSTALL_ROOT=$1

sudo yum install openssl3-devel openssl3-libs
sudo yum install brotli-devel

export LDFLAGS="-L/usr/lib64/openssl3/"
./configure --with-openssl-include-dir=/usr/include/openssl3/ --prefix="$INSTALL_ROOT"
make
make install prefix="$INSTALL_ROOT"

find "$INSTALL_ROOT/etc/raddb/sites-enabled/" -type f -delete
find "$INSTALL_ROOT/etc/raddb/sites-enabled/" -type l -delete
rm "$INSTALL_ROOT/etc/raddb/clients.conf"

cp config/clients.conf "$INSTALL_ROOT/etc/raddb/clients.conf"
cp config/site "$INSTALL_ROOT/etc/raddb/sites-enabled/"
rm -f "$INSTALL_ROOT/etc/raddb/mods-enabled/eap"
rm -f "$INSTALL_ROOT/etc/raddb/mods-enabled/eap_inner"
cp config/mods-available/sber "$INSTALL_ROOT/etc/raddb/mods-enabled/"
