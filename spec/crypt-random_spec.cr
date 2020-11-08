# This file is part of "crypt" module.
#
# This source code is licensed under the MIT license, please view the LICENSE
# file distributed with this source code. For the full
# information and documentation: https://github.com/Nicolab/crystal-crypt
# ------------------------------------------------------------------------------

require "./spec_helper"
require "../src/random"

describe "Random" do
  describe "Crypt.random_bytes" do
    it "should generate a Bytes slice filled with *n* random bytes" do
      value = Crypt.random_bytes(4)
      value.bytesize.should eq 4
      value.should be_a Bytes

      value = Crypt.random_bytes(6)
      value.bytesize.should eq 6
      value.should be_a Bytes
    end

    it "should generate 16 random bytes by default" do
      value = Crypt.random_bytes
      value.bytesize.should eq 16
      value.should be_a Bytes
    end
  end

  describe "Crypt.random_bytes_string" do
    it "should generate a string whose size is *n* bytes" do
      value = Crypt.random_bytes_string(4)
      value.bytesize.should eq 4
      value.should be_a String

      value = Crypt.random_bytes_string(6)
      value.bytesize.should eq 6
      value.should be_a String
    end

    it "should generate a string whose size is 16 bytes by default" do
      value = Crypt.random_bytes_string
      value.bytesize.should eq 16
      value.should be_a String
    end
  end

  describe "Crypt.random_string" do
    it "should generate a string filled with *n* random characters" do
      value = Crypt.random_string(4)
      value.size.should eq 4
      value.size.should eq value.bytesize
      value.should be_a String
      value.should_not contain "="
      value.should_not contain "/"
      Base64.decode_string(value).should be_a String
      Base64.decode_string(value).should_not eq value

      value = Crypt.random_string(6)
      value.size.should eq 6
      value.size.should eq value.bytesize
      value.should be_a String
      value.should_not contain "="
      value.should_not contain "/"
      Base64.decode_string(value).should be_a String
      Base64.decode_string(value).should_not eq value
    end

    it "should generate a string filled with 16 random characters by default" do
      value = Crypt.random_string
      value.size.should eq 16
      value.size.should eq value.bytesize
      value.should be_a String
      value.should_not contain "="
      value.should_not contain "/"
      Base64.decode_string(value).should be_a String
      Base64.decode_string(value).should_not eq value
    end
  end
end
