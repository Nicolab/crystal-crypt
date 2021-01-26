# This file is part of "crypt" module.
#
# This source code is licensed under the MIT license, please view the LICENSE
# file distributed with this source code. For the full
# information and documentation: https://github.com/Nicolab/crystal-crypt
# ------------------------------------------------------------------------------

require "spec"
require "../src/crypt"

SIGN_SEP = Crypt::Signer::SIGN_SEP

# Simulates a heavier load by adding iterations for some tests
LOOP_ITER = 10
