# This file is part of "crypt" module.
#
# This source code is licensed under the MIT license, please view the LICENSE
# file distributed with this source code. For the full
# information and documentation: https://github.com/Nicolab/crystal-crypt
# ------------------------------------------------------------------------------

require "./spec_helper"
require "../src/random"

describe "Crypt" do
  describe "Crypt custom Exception classes" do
    it "should provide custom Exception classes inherited from Exception and Crypt::CryptError" do
      Crypt::CryptError.new.should be_a(Exception)
      Crypt::SecretKeyError.new.should be_a(Crypt::CryptError)
      Crypt::SignatureError.new.should be_a(Crypt::CryptError)
      Crypt::BytesizeError.new.should be_a(Crypt::CryptError)
    end
  end

  describe "Crypt.check_min_bytesize" do
    value = Crypt.random_string(4)
    value.bytesize.should eq 4

    it "should return value if bytesize is ok" do
      value.bytesize.should eq 4
      Crypt.check_min_bytesize(4, value).should be value
      Crypt.check_min_bytesize(4, Crypt.random_bytes_string(5)).should be_a(String)
      Crypt.check_min_bytesize(4, Crypt.random_bytes(256).to_slice).should be_a(Bytes)

      v2 = Crypt.random_bytes_string(1024)
      Crypt.check_min_bytesize(256, v2).should be_a(String)
      Crypt.check_min_bytesize(256, v2).should eq(v2)
      Crypt.check_min_bytesize(256, v2).should be(v2)
    end

    it "should raise BytesizeError if bytesize is lesser than desired" do
      value.bytesize.should eq 4
      expect_raises Crypt::BytesizeError, /Value .* 5/ do
        Crypt.check_min_bytesize(5, value)
      end
    end

    it "should contextualize error message" do
      expect_raises Crypt::BytesizeError, /Message .* 5/ do
        Crypt.check_min_bytesize(5, value, "Message")
      end
    end
  end
end
