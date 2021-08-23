#!/bin/bash

GIT_DIR=$(cd `dirname $0`;pwd)

#获取golang root目录
GOROOT_PATH=`echo ${GOROOT}`
if [ -z "$GOROOT_PATH" ]; then
  echo "go root empty"
  exit
fi
if [ ! -d ${GOROOT_PATH} ]; then
  echo ${GOROOT_PATH} not exist
  exit
fi



ls -1 ${GIT_DIR}/*_plugin.go
cp -r ${GIT_DIR}/*_plugin.go ${GOROOT_PATH}/src/crypto/tls

echo "install list:"
ls -1 ${GOROOT_PATH}/src/crypto/tls/*_plugin.go
echo "install success..."