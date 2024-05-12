#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2021-2023 Intel Corporation
from conans import ConanFile

class IgscConan(ConanFile):
    name = "igsc"
    generators = "cmake", "cmake_find_package", "visual_studio"

    def requirements(self):
        self.requires("metee/4.1.0@mesw/stable")
