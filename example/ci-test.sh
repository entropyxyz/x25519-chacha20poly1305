#!/bin/bash
readonly EXEC_DIR=$(dirname "$(realpath $0)") && cd $__EXEC_DIR
readonly NODE_VERSION="v18.12.1"
readonly NODE_OS="linux"
readonly NODE_ARCH="x64"
readonly FN="node-$NODE_VERSION-$NODE_OS-$NODE_ARCH"

wget https://nodejs.org/dist/$NODE_VERSION/$FN.tar.xz
tar xf $FN.tar.xz
export PATH=$PATH:$EXEC_DIR/$FN/bin
npm install -g ts-node

ts-node test.ts

