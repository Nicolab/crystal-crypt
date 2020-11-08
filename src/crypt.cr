# This file is part of "Crypt" module.
#
# This source code is licensed under the MIT license, please view the LICENSE
# file distributed with this source code. For the full
# information and documentation: https://github.com/Nicolab/crystal-crypt
# ------------------------------------------------------------------------------

# Crypto utilities.
#
# See also in complement:
#
# * https://crystal-lang.org/api/OpenSSL/Cipher.html
# * https://crystal-lang.org/api/Crypto/Bcrypt/Password.html
# * https://crystal-lang.org/api/Random/Secure.html
# * https://crystal-lang.org/api/Random.html
module Crypt
  VERSION = "0.1.0"

  # Generic Crypt's Error.
  # Inherited by all Crypt's exception classes.
  class CryptError < Exception
  end

  # Raised when an error has occurred with a secret key.
  class SecretKeyError < CryptError
  end

  # Raised when an error has occurred with a signature.
  class SignatureError < CryptError
  end

  # Raised when an error has occurred with a signature.
  class BytesizeError < CryptError
  end

  # Check the desired minimal *value* bytesize.
  # Raises a `BytesizeError` if the *value* bytesize is lesser than *min_bytesize*.
  #
  # *value* must implements `value.bytesize` (`String` and `Slice` / `Bytes` implements bytesize).
  #
  # > *name* argument is used to contextualize error message.
  def self.check_min_bytesize(
    min_bytesize : Int,
    value,
    name : String = "Value"
  )
    return value unless value.bytesize < min_bytesize
    raise BytesizeError.new(
      "#{name} must be #{min_bytesize} bytes or more characters.
      Use `Crypt.random_string(#{min_bytesize})`."
    )
  end
end
