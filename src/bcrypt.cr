# This file is part of "Crypt" module.
#
# This source code is licensed under the MIT license, please view the LICENSE
# file distributed with this source code. For the full
# information and documentation: https://github.com/Nicolab/crystal-crypt
# ------------------------------------------------------------------------------

require "crypto/bcrypt/password"

module Crypt
  # Create a `Bcrypt` password (`Crypto::Bcrypt::Password`).
  # https://crystal-lang.org/api/Crypto/Bcrypt/Password.html
  #
  # Generate, read and verify `Crypto::Bcrypt` hashes:
  #
  # ```
  # require "crypt"
  # require "crypt/bcrypt"
  #
  # password = Crypt.create_bcrypt_password("super secret", cost: 10)
  # # => $2a$10$rI4xRiuAN2fyiKwynO6PPuorfuoM4L2PVv6hlnVJEmNLjqcibAfHq
  #
  # password.verify("wrong secret") # => false
  # password.verify("super secret") # => true
  # ```
  def self.create_bcrypt_password(
    secret : String,
    cost : Int32 = Crypto::Bcrypt::DEFAULT_COST
  ) : Crypto::Bcrypt::Password
    Crypto::Bcrypt::Password.create(secret, cost: cost)
  end

  # Loads a `Bcrypt` password hash.
  #
  # ```
  # require "crypt"
  # require "crypt/bcrypt"
  #
  # password = Crypt.load_bcrypt_password(
  #   "$2a$10$X6rw/jDiLBuzHV./JjBNXe8/Po4wTL0fhdDNdAdjcKN/Fup8tGCya"
  # )
  # password.version # => "2a"
  # password.salt    # => "X6rw/jDiLBuzHV./JjBNXe"
  # password.digest  # => "8/Po4wTL0fhdDNdAdjcKN/Fup8tGCya"
  # ```
  def self.load_bcrypt_password(hash : String) : Crypto::Bcrypt::Password
    Crypto::Bcrypt::Password.new(hash)
  end
end
