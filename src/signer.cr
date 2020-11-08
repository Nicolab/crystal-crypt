# This file is part of "Crypt" module.
#
# This source code is licensed under the MIT license, please view the LICENSE
# file distributed with this source code. For the full
# information and documentation: https://github.com/Nicolab/crystal-crypt
# ------------------------------------------------------------------------------

require "openssl/hmac"
require "crypto/subtle"

module Crypt
  # Sign and verify given data.
  class Signer
    SIGN_SEP     = "--"
    INVALID_SIGN = "Not valid"

    # Create a `Signer` instance.
    def initialize(@secret : String, @digest = :sha1)
    end

    # Compare *data* and *digest*.
    def valid?(data, digest) : Bool
      data.size > 0 &&
        digest.size > 0 &&
        Crypto::Subtle.constant_time_compare(digest, digest_and_encode(data))
    end

    # Verify and decode.
    #
    # > It is recommended to use `verify` which has a more
    #   precise return (returns `String` or raises a `SignatureError`).
    def verify_and_decode(signed_data : String) : String?
      begin
        data, digest = Signer.parse_data_and_digest(signed_data)
        # catch IndexError: Index out of bounds
      rescue
        return nil
      end

      if valid?(data, digest)
        String.new(decode(data))
      end
    rescue arg_error : ArgumentError
      return if arg_error.message =~ %r{invalid base64}
      raise SignatureError.new("#{arg_error.class}: #{arg_error.message}")
    end

    # Verify and decode.
    # *error_message* allows to customize the error message when the signature is not valid.
    def verify(signed_data, error_message = INVALID_SIGN) : String
      verify_and_decode(signed_data) || raise SignatureError.new(error_message)
    end

    # Verify and decode.
    # *error_message* allows to customize the error message when the signature is not valid.
    #
    # > This method can produce a different error message than *error_message*.
    def verify_raw(signed_data : String, error_message = INVALID_SIGN) : Bytes
      data, digest = Signer.parse_data_and_digest(signed_data)

      return decode(data) if valid?(data, digest)
      raise SignatureError.new(error_message)
    end

    # :ditto:
    def verify_raw(signed_data : Bytes, error_message = INVALID_SIGN) : Bytes
      verify_raw(String.new(signed_data), error_message)
    end

    # Generates signed data.
    # Returns an URL and filename safe alphabet (RFC 4648).
    def sign(value : String | Bytes) : String
      data = encode(value)
      "#{digest_and_encode(data)}#{SIGN_SEP}#{data}"
    end

    def self.parse_data_and_digest(signed_data) : Tuple(String, String)
      digest, data = signed_data.split(SIGN_SEP, 2)
      {data, digest}
    rescue e
      raise SignatureError.new("#{e.class}: #{e.message}")
    end

    # Encode to URL safe `Base64` `String`.
    private def encode(data) : String
      ::Base64.urlsafe_encode(data)
    end

    # Decode `Base64` data to `Bytes`.
    private def decode(data) : Bytes
      ::Base64.decode(data)
    end

    private def digest_and_encode(data) : String
      encode(digest(data))
    end

    private def digest(data) : Bytes
      OpenSSL::HMAC.digest(
        OpenSSL::Algorithm.parse(@digest.to_s),
        @secret,
        data
      )
    end

    private def hexdigest(data) : String
      OpenSSL::HMAC.hexdigest(
        OpenSSL::Algorithm.parse(@digest.to_s),
        @secret,
        data
      )
    end
  end
end
