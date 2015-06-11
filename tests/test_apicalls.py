#!/usr/bin/env python
# Copyright (C) 2015 Dmitry Rodionov
# This file is part of my GSoC'15 project for Cuckoo Sandbox:
#	http://www.cuckoosandbox.org
# This software may be modified and distributed under the terms
# of the MIT license. See the LICENSE file for details.

import unittest
from sets import Set

from common import DtraceTestCase
from analyzer.darwin.lib.dtrace.apicalls import *


# TODO(rodionovd): add assets for these tests
# TODO(rodionovd): run tests

class TestAPICalls(DtraceTestCase):

    def test_apicalls_basic(self):
        # given
        expected_api = ("system", ["whoami"], 0)
        output = []
        # when
        for call in apicalls(self.current_target()):
            output.append(call)
        # then
        matched = [x for x in output if (x.api, x.args, x.retval) == expected_api]
        self.assertEqual(len(matched), 1)

    def test_apicalls_root(self):
        # given
        expected_api = ("printf", ["I'm root!\n"], 10)
        output = []
        # when
        for call in apicalls(self.current_target(), run_as_root=True):
            output.append(call)
        # then
        matched = [x for x in output if (x.api, x.args, x.retval) == expected_api]
        self.assertEqual(len(matched), 1)

    def test_apicalls_timeout_root(self):
        # given
        expected_api = ("system", ["whoami"])
        t = 1
        output = []
        # when
        for call in apicalls(self.current_target(), timeout = t, run_as_root=True):
            output.append(call)
        # then
        matched = [x for x in output if (x.api, x.args) == expected_api]
        self.assertEqual(len(matched), 1)

    def test_apicalls_timeout(self):
        # given
        expected_api = ("system", ["whoami"])
        t = 1
        output = []
        # when
        for call in apicalls(self.current_target(), timeout = t):
            output.append(call)
        # then
        matched = [x for x in output if (x.api, x.args) == expected_api]
        self.assertEqual(len(matched), 1)

    def test_apicalls_with_args_root(self):
        # given
        expected_api = ("strlen", 5) # strlen(fo1oP) == 5
        args = ["fo1oP", "-k", "bar"]
        output = []
        # when
        for call in apicalls(self.current_target(), args=args, run_as_root=True):
            output.append(call)
        # then
        matched = [x for x in output if (x.api, x.retval) == expected_api]
        self.assertEqual(len(matched), 1)

    def test_apicalls_with_args(self):
        # given
        expected_api = ("strlen", 5) # strlen(fo1oP) == 5
        args = ["fo1oP", "-k", "bar"]
        output = []
        # when
        for call in apicalls(self.current_target(), args=args):
            output.append(call)
        # then
        matched = [x for x in output if (x.api, x.retval) == expected_api]
        self.assertEqual(len(matched), 1)


    def test_apicalls_children(self):
        # given
        expected_child_api  = ("printf", ["child's here\n"], 13)
        expected_parent_api = ("printf", ["parent's here\n"], 14)
        pids = Set()
        output = []
        # when
        for call in apicalls(self.current_target()):
            output.append(call)
            pids.add(call.pid)

        matched_child = [x for x in output if (x.api, x.args, x.retval) == expected_child_api]

        matched_parent = [x for x in output if (x.api, x.args, x.retval) == expected_parent_api]
        # then
        self.assertEqual(len(pids), 2)
        self.assertEqual(len(matched_child), 1)
        self.assertEqual(len(matched_parent), 1)
        self.assertLess(matched_parent[0].pid, matched_child[0].pid)


    def test_apicalls_children_root(self):
        # given
        expected_child_api  = ("printf", ["child's here\n"], 13)
        expected_parent_api = ("printf", ["parent's here\n"], 14)
        pids = Set()
        output = []
        # when
        for call in apicalls(self.current_target(), run_as_root=True):
            output.append(call)
            pids.add(call.pid)

        matched_child = [x for x in output if (x.api, x.args, x.retval) == expected_child_api]

        matched_parent = [x for x in output if (x.api, x.args, x.retval) == expected_parent_api]
        # then
        self.assertEqual(len(pids), 2)
        self.assertEqual(len(matched_child), 1)
        self.assertEqual(len(matched_parent), 1)
        self.assertLess(matched_parent[0].pid, matched_child[0].pid)
