# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2022 Intel Corporation

BUILD_TYPE=$1
BUILD_TYPE=${BUILD_TYPE:-Release}

export PUBLISH_DIR=Bin/Kit/IGSC_FUL

# Create publish directories
mkdir -p ${PUBLISH_DIR}
mkdir -p ${PUBLISH_DIR}/INTERNAL

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

#copy to kit
cp include/igsc_lib.h ${PUBLISH_DIR}/
cp ${BUILD_TYPE}/lib/libigsc.so ${PUBLISH_DIR}/
cp ${BUILD_TYPE}/lib/libigsc.so.* ${PUBLISH_DIR}/
cp ${BUILD_TYPE}/lib/libigsc.so ${PUBLISH_DIR}/INTERNAL/
cp ${BUILD_TYPE}/lib/libigsc.so.* ${PUBLISH_DIR}/INTERNAL/
cp ${BUILD_TYPE}/src/igsc ${PUBLISH_DIR}/INTERNAL/
