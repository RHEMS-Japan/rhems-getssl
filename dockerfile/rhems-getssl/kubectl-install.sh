#!/bin/bash

set -e

echo "Installing kubectl v2"
# Platform check
if uname -a | grep "x86_64 Linux"; then
  export SYS_ENV_PLATFORM=linux_x86
elif uname -a | grep "aarch64 Linux"; then
  export SYS_ENV_PLATFORM=linux_arm
else
  echo "This platform appears to be unsupported."
  uname -a
  exit 1
fi

echo "Platform: $SYS_ENV_PLATFORM"

case $SYS_ENV_PLATFORM in
linux_x86)
  echo "Installing kubectl x86"
  curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
  chmod +x ./kubectl
  ;;
linux_arm)
  echo "Installing kubectl arm"
  curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/arm64/kubectl"
  chmod +x ./kubectl
  ;;
*)
  echo "no support your platform"
  exit 1
  ;;
esac
