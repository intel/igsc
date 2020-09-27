#!/usr/bin/python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2020 Intel Corporation

def get_ver():
    ''' Obtain version string from VERSION file '''
    with open('VERSION') as the_fd:
        return the_fd.readline()

if __name__ == '__main__':

    version = get_ver()
    print(version)
