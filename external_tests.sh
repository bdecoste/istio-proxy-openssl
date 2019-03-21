#!/bin/bash
#
# Wraps upstream test
set -x

export TEST_WORKSPACE=envoy
$@

