#!/bin/bash
set -e

KWPROJECT=IGSC_FUL
KWURL=https://sfip-kw-cd.intel.com:8080
WORKSPACE=kwbuild
Jobs_num=$(nproc)
#replace_path=--replace_path
echo "variables:"
echo "-------------------------------------------------------------------------"
echo "KWPROJECT : ${KWPROJECT}"
echo "KWURL     : ${KWURL}"
echo "KWBUILD   : ${KWBUILD}"
echo "WORKSPACE : ${WORKSPACE}"
echo "Jobs_num  : ${Jobs_num}"
echo "replace_path: ${replace_path}"
echo "Compiler_options ${Compiler_options}"
echo "-------------------------------------------------------------------------"

[ -z ${KWPROJECT} ] && { echo "KWPROJECT is not set "; exit 1; }
[ -z ${KWURL} ] && { echo "KWURL is not set "; exit 1; }
[ -z ${KWBUILD} ] &&  { echo "KWBUILD is not set"; exit 1; }
[ -z ${WORKSPACE} ] && { echo "WORKSPACE is not set"; exit 1; }

BUILD_DIR=build
CMPL_CMD="make -C ${BUILD_DIR}"
KW_SRC_ROOT=$PWD
WORKAREA="${WORKSPACE}/KW/"
TABLES=$WORKAREA/Tables
rm -rf ${WORKAREA}

kwdeploy sync --url $KWURL

mkdir -p ${TABLES}
echo `date +%R:%S` Tracing the build...
# Scan
make -C ${BUILD_DIR} clean
kwinject --trace-out $WORKAREA/kwtrace.out $CMPL_CMD  2>&1 | tee $WORKAREA/kwtrace.log

### Create a KM Buildspec out of the trace of the build
echo `date +%R:%S` Translateing the trace into a buildspec...
kwinject \
    --trace-in  ${WORKAREA}/kwtrace.out \
    --output    ${WORKAREA}/kwbuildspec.tpl \
    --variable "kwpsroot=$KW_SRC_ROOT" 2>&1 | tee ${WORKAREA}/kwspec.log

### Scan
echo `date +%R:%S` Analyzing...
kwbuildproject \
    --url $KWURL/$KWPROJECT ${WORKAREA}/kwbuildspec.tpl \
    --tables-directory ${TABLES} \
    --buildspec-variable "kwpsroot=${KW_SRC_ROOT}" \
    --force --jobs-num $Jobs_num ${replace_path} ${Compiler_options} 2>&1 | tee ${WORKAREA}/output.log

awk '/([0-9]+) error\(s\) and ([0-9]+) warning\(s\)/{print $1$4}' ${WORKAREA}/output.log

### Upload to server
echo `date +%R:%S` Uploading...
### Disable for testing
kwadmin --url $KWURL load ${KWPROJECT} ${TABLES} --name ${KWBUILD} --force 2>&1 | tee ${WORKAREA}/kwload.log
