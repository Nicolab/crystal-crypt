# This file is part of "crypt" module.
#
# This source code is licensed under the MIT license, please view the LICENSE
# file distributed with this source code. For the full
# information and documentation: https://github.com/Nicolab/crystal-crypt
# ------------------------------------------------------------------------------

require "./spec_helper"
require "../src/key-deriv"
require "../src/random"

describe "Crypt.key_deriv" do
  it "should generate Key derivation PKCS5/PBKDF2" do
    key = Crypt.key_deriv(Crypt.random_string(10), Crypt.random_string(10))
    key.size.should eq 64
    key.should be_a(Bytes)

    key = Crypt.key_deriv(Crypt.random_string(10), Crypt.random_string(8), key_size: 32)
    key.size.should eq 32
    key.should be_a(Bytes)

    password = Crypt.random_string(10)
    salt = Crypt.random_string(16)

    # -- 64 bytes

    key = Crypt.key_deriv(password, salt, iter: 2000)
    key.size.should eq 64

    key2 = Crypt.key_deriv(password, salt, iter: 2000)
    key2.size.should eq 64

    key.should eq key2
    key.hexstring.should eq key2.hexstring

    # -- 8 bytes

    key = Crypt.key_deriv(password, salt, key_size: 8)
    key.size.should eq 8

    key2 = Crypt.key_deriv(password, salt, key_size: 8)
    key2.size.should eq 8

    key.should eq key2
    key.hexstring.should eq key2.hexstring

    # -- mix key_size

    key = Crypt.key_deriv(password, salt, key_size: 8)
    key.size.should eq 8

    key2 = Crypt.key_deriv(password, salt, key_size: 16)
    key2.size.should eq 16

    key.should_not eq key2
    key.hexstring.should_not eq key2.hexstring

    # truncate
    key2[0, 8].should eq key

    # -- mix iter

    key = Crypt.key_deriv(password, salt, iter: 1000)
    key.size.should eq 64

    key2 = Crypt.key_deriv(password, salt, iter: 2000)
    key2.size.should eq 64

    key.should_not eq key2
    key.hexstring.should_not eq key2.hexstring

    # truncate
    key2[0, 8].should_not eq key
  end

  it "should change algo" do
    password = Crypt.random_string(10)
    salt = Crypt.random_string(16)

    # -- default
    key = Crypt.key_deriv(password, salt, iter: 1000)
    key2 = Crypt.key_deriv(password, salt, iter: 1000, algo: OpenSSL::Algorithm::SHA1)
    key.size.should eq 64
    key.should eq key2

    key2 = Crypt.key_deriv(password, salt, iter: 1000, algo: OpenSSL::Algorithm::SHA256)
    key2.size.should eq 64
    key2.should_not eq key

    key3 = Crypt.key_deriv(password, salt, iter: 1000, algo: :sha256)
    key3.size.should eq 64
    key3.should_not eq key
    key3.should eq key2
  end

  it "should take a Symbol as algo instead of OpenSSL::Algorithm" do
    algo_count = 0
    password = Crypt.random_string(10)
    salt = Crypt.random_string(8)

    {% begin %}
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
    algo_count += 1
    symb_key = Crypt.key_deriv(
      password,
      salt,
      iter: 1000,
      algo: :{{algo_name.downcase.id}}
    )
    enum_key = Crypt.key_deriv(
      password,
      salt,
      iter: 1000,
      algo: OpenSSL::Algorithm::{{algo_name.id}}
    )
    symb_key.size.should eq 64
    symb_key.should eq enum_key
    {% end %}
    {% end %}

    # check loop
    (algo_count > 1).should be_true
    algo_count.should eq OpenSSL::Algorithm.names.size
  end

  it "should raise a CryptError if the algo Symbol is not supported" do
    expect_raises(
      Crypt::CryptError,
      /\/api\/#{Crystal::VERSION}\/OpenSSL\/Algorithm/
    ) do
      Crypt.key_deriv("123456", "12345678", iter: 2000, algo: :shatouille)
    end
  end

  it "should raise BytesizeError if password size is too small" do
    expect_raises Crypt::BytesizeError, /Password .* 6/ do
      Crypt.key_deriv("12345", "12345678", iter: 2000)
    end
  end

  it "should raise BytesizeError if salt size is too small" do
    expect_raises Crypt::BytesizeError, /Salt .* 8/ do
      Crypt.key_deriv("123456", "1234567", iter: 2000)
    end
  end
end
