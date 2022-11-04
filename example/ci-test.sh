#!/bin/bash
readonly EXEC_DIR=$(dirname "$(realpath $0)") 
readonly NODE_VERSION="v18.12.1"
readonly NODE_OS="linux"
readonly NODE_ARCH="x64"
readonly FN="node-$NODE_VERSION-$NODE_OS-$NODE_ARCH"

# Install JS dependencies
cd $EXEC_DIR
wget https://nodejs.org/dist/$NODE_VERSION/$FN.tar.xz
tar xf $FN.tar.xz
export PATH=$PATH:$EXEC_DIR/$FN/bin
npm install -g ts-node

# Run tests
ts-node test.ts

