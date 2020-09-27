# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2020 Intel Corporation

from gitlint.rules import CommitRule, RuleViolation
from gitlint.options import IntOption, ListOption
from gitlint import utils


class BodyMinLineCount(CommitRule):
    name = "body-min-line-count"

    # A rule MUST have a *unique* id, we recommend starting with UC (for User-defined Commit-rule).
    id = "UC1"

    options_spec = [IntOption('min-line-count', 2, "Minimum body line count excluding Signed-off-by")]

    def validate(self, commit):
        filtered = [x for x in commit.message.body if not x.lower().startswith("signed-off-by") and x != '']
        line_count = len(filtered)
        min_line_count = self.options['min-line-count'].value
        if line_count < min_line_count:
            message = "Body has no content, should at least have {} line.".format(min_line_count)
            return [RuleViolation(self.id, message, line_nr=1)]

class SignedOffBy(CommitRule):
    """ This rule will enforce that each commit contains a "Signed-off-by:" line.
    We keep things simple here and just check whether the commit body contains a line that starts with "Signed-off-by:".
    """

    name = "body-requires-signed-off-by"

    # A rule MUST have a *unique* id, we recommend starting with UC (for User-defined Commit-rule).
    id = "UC2"

    def validate(self, commit):
        for line in commit.message.body:
            if line.startswith("Signed-off-by:"):
                return

        return [RuleViolation(self.id, "Body does not contain a 'Signed-off-by' line", line_nr=1)]

