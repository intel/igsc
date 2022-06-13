# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2022 Intel Corporation

BUILD_TYPE=$1
BUILD_TYPE=${BUILD_TYPE:-Release}

export BUILD_DIR=$(dirname "$(readlink -f "$0")")

# workaround for https://github.com/conan-io/conan/issues/4322
export CC=$(which cc)

rm -rf ${BUILD_TYPE}
mkdir -p ${BUILD_TYPE}
pushd ${BUILD_TYPE}

cat << EOF > cmake.config
set(CMAKE_BUILD_TYPE ${BUILD_TYPE} CACHE STRING "CMAKE_BUILD_TYPE")
set(BUILD_USE_CONAN "ON" CACHE STRING "Use Conan for dependencies download")
EOF

cmake -C cmake.config .. || exit $?
make -j$(nproc) || exit $?

popd
