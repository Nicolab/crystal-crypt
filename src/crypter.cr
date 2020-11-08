# This file is part of "Crypt" module.
#
# This source code is licensed under the MIT license, please view the LICENSE
# file distributed with this source code. For the full
# information and documentation: https://github.com/Nicolab/crystal-crypt
# ------------------------------------------------------------------------------

require "openssl/cipher"
require "./signer"

module Crypt
  # Encrypt / Decrypt using OpenSSL Cipher.
  # See https://crystal-lang.org/api/OpenSSL/Cipher.html
  class Crypter
    getter signer : Signer

    # Creates a new `Crypter` instance.
    def initialize(@secret : String, @digest = :sha1, @cipher_algo = "aes-256-cbc")
      @signer = Signer.new(@secret, digest: @digest)
      @block_size = 16
    end

    # Equivalent to `cipher_encrypt`, just a shortcut.
    def encrypt(value) : Bytes
      cipher_encrypt(value)
    end

    # Equivalent to `cipher_decrypt`, just a shortcut.
    def decrypt(value : Bytes) : Bytes
      cipher_decrypt(value)
    end

    # Equivalent to `encrypt_and_sign`, just a shortcut.
    def encrypt(value : Bytes, kind : Symbol) : String
      check_kind(kind, :sign)
      encrypt_and_sign(value)
    end

    # Equivalent to `encrypt_and_sign`, just a shortcut.
    def encrypt(value : String, kind : Symbol) : String
      check_kind(kind, :sign)
      encrypt_and_sign(value)
    end

    # Equivalent to `verify_and_decrypt`, just a shortcut.
    def decrypt(value : Bytes, kind : Symbol, sign_error = Signer::INVALID_SIGN) : Bytes
      check_kind(kind, :sign)
      verify_and_decrypt(value, sign_error)
    end

    # Equivalent to `verify_and_decrypt`, just a shortcut.
    def decrypt(value : String, kind : Symbol, sign_error = Signer::INVALID_SIGN) : Bytes
      check_kind(kind, :sign)
      verify_and_decrypt(value, sign_error)
    end

    # Encrypt and sign a *value*. We need to sign the *value* in order to avoid
    # padding attacks. Reference: http://www.limited-entropy.com/padding-oracle-attacks.
    def encrypt_and_sign(value : Bytes) : String
      signer.sign(encrypt(value))
    end

    # :ditto:
    def encrypt_and_sign(value : String) : String
      encrypt_and_sign(value.to_slice)
    end

    # Verify and decrypt a signed *value*. We need to verify the *value* in order to
    # avoid padding attacks. Reference: http://www.limited-entropy.com/padding-oracle-attacks.
    def verify_and_decrypt(value : String, sign_error = Signer::INVALID_SIGN) : Bytes
      cipher_decrypt(signer.verify_raw(value, sign_error))
    end

    # :ditto:
    def verify_and_decrypt(value : Bytes, sign_error = Signer::INVALID_SIGN) : Bytes
      cipher_decrypt(signer.verify_raw(value, sign_error))
    end

    # Encrypt the *value* which should be decrypted by `cipher_decrypt`.
    # See also `encrypt`, `encrypt_and_sign`.
    def cipher_encrypt(value) : Bytes
      cipher = OpenSSL::Cipher.new(@cipher_algo)
      cipher.encrypt
      set_cipher_key(cipher)

      # Rely on OpenSSL for the initialization vector
      iv = cipher.random_iv

      encrypted_data = IO::Memory.new
      encrypted_data.write(cipher.update(value))
      encrypted_data.write(cipher.final)
      encrypted_data.write(iv)

      encrypted_data.to_slice
    end

    # Decrypt *value* encrypted by `cipher_encrypt`.
    def cipher_decrypt(value : Bytes) : Bytes
      cipher = OpenSSL::Cipher.new(@cipher_algo)
      data = value[0, value.size - @block_size]
      iv = value[value.size - @block_size, @block_size]

      cipher.decrypt
      set_cipher_key(cipher)
      cipher.iv = iv

      decrypted_data = IO::Memory.new
      decrypted_data.write cipher.update(data)
      decrypted_data.write cipher.final
      decrypted_data.to_slice
    end

    private def set_cipher_key(cipher)
      cipher.key = @secret
    rescue error : ArgumentError
      raise SecretKeyError.new(<<-MESSAGE
        The secret key is invalid:

          #{error.message}

        You can generate a new key using `Crypt.random_string` method
        or 'craft gen secret-key' in your terminal:

          ▸ craft gen secret-key



        MESSAGE
      )
    end

    private def check_kind(value : Symbol, expected : Symbol)
      raise CryptError.new("#{value} kind is invalid") unless expected == value
    end
  end
end
