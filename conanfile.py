#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2021-2022 Intel Corporation
from conans import ConanFile
import os

class LMSConan(ConanFile):
    name = "igsc"
    generators = "cmake", "cmake_find_package", "visual_studio"
    settings = "os"

    def requirements(self):
        self.requires("metee/3.1.3@mesw/stable")
