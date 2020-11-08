# This file is part of "Crypt" module.
#
# This source code is licensed under the MIT license, please view the LICENSE
# file distributed with this source code. For the full
# information and documentation: https://github.com/Nicolab/crystal-crypt
# ------------------------------------------------------------------------------

require "random/secure"

module Crypt
  # Generates a slice filled with *n* random bytes.
  # * https://crystal-lang.org/api/Random.html#random_bytes(n:Int=16):Bytes-instance-method
  #
  # See also:
  #
  # * `random_string`
  # * `random_bytes_string`
  def self.random_bytes(n : Int = 16) : Bytes
    Random::Secure.random_bytes(n)
  end

  # Generates a string whose size is *n* bytes.
  # Be careful the string generated contains more characters than *n*, but size is *n* bytes.
  #
  # ```
  # str = Crypt.random_bytes_string(4) # => "\u001DF\xD4\u000E"
  # str.bytesize                       # => 4
  # str.to_slice                       # => Bytes[195, 219, 187, 142]
  # ```
  #
  # See also:
  #
  # * `random_bytes`
  # * `random_string`
  def self.random_bytes_string(n : Int = 16) : String
    String.new(Random::Secure.random_bytes(n))
  end

  # Generates a string filled with *n* random characters.
  # The string generated is URL and filename safe alphabet (RFC 4648).
  # The alphabet uses `'-'` instead of `'+'` and `'_'` instead of `'/'`.
  #
  # # See also:
  #
  # * `random_bytes`
  # * `random_bytes_string`
  def self.random_string(n : Int = 16) : String
    # random_bytes encoded
    Random::Secure.urlsafe_base64(n, padding: false)[0, n]
  end
end
