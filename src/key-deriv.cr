# This file is part of "Crypt" module.
#
# This source code is licensed under the MIT license, please view the LICENSE
# file distributed with this source code. For the full
# information and documentation: https://github.com/Nicolab/crystal-crypt
# ------------------------------------------------------------------------------

require "openssl/pkcs5"

module Crypt
  # Key derivation PKCS5/PBKDF2 (Password-Based Key Derivation Function 2).
  #
  # * https://crystal-lang.org/api/OpenSSL/HMAC.html
  # * https://en.wikipedia.org/wiki/PBKDF2
  def self.key_deriv(
    password,
    salt,
    iter = 65_536,
    algo : OpenSSL::Algorithm = OpenSSL::Algorithm::SHA1,
    key_size = 64
  )
    OpenSSL::PKCS5.pbkdf2_hmac(
      self.check_min_bytesize(6, password, "Password"),
      self.check_min_bytesize(8, salt, "Salt"),
      iter,
      algo,
      key_size
    )
  end

  # See `key_deriv`.
  #
  # Argument *algo* takes a `Symbol` instead of `OpenSSL::Algorithm` (`Enum`).
  # > :md4, :md5, :ripemd160, :sha1, :sha224, :sha256, :sha384, :sha512
  def self.key_deriv(password, salt, iter = 65_536, algo : Symbol = :sha1, key_size = 64)
    {% begin %}
    case algo
    {% for algo_name in [
                          "MD4",
                          "MD5",
                          "RIPEMD160",
                          "SHA1",
                          "SHA224",
                          "SHA256",
                          "SHA384",
                          "SHA512",
                        ] %}
    when :{{algo_name.downcase.id}}
      algo = OpenSSL::Algorithm::{{algo_name.id}}
    {% end %}
    else
      raise CryptError.new(
        "#{algo} algorithm not supported.
        See https://crystal-lang.org/api/#{Crystal::VERSION}/OpenSSL/Algorithm.html"
      )
    end
    {% end %}

    self.key_deriv(password, salt, iter, algo, key_size)
  end
end
