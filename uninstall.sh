#!/bin/bash

#获取golang root目录
GOROOT=`echo ${GOROOT}`
if [ ! -d ${GOROOT} ]; then
  echo ${GOROOT} not exist
  exit
fi

echo "uninstall list:"
ls -1 ${GOROOT}/src/crypto/tls/*_plugin.go
rm ${GOROOT}/src/crypto/tls/*_plugin.go
echo "uninstall success..."