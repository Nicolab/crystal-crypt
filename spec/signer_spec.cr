# This file is part of "crypt" module.
#
# This source code is licensed under the MIT license, please view the LICENSE
# file distributed with this source code. For the full
# information and documentation: https://github.com/Nicolab/crystal-crypt
# ------------------------------------------------------------------------------

require "./spec_helper"
require "../src/signer"

describe "Signer" do
  it "#valid?" do
    LOOP_ITER.times do |i|
      data = "abcd #{i}"
      secret = "super secret"
      signer = Crypt::Signer.new(secret, digest: :sha1)

      signed_data = signer.sign(data)

      _data, _digest = Crypt::Signer.parse_data_and_digest(signed_data)
      _data.should_not eq data
      _digest.should_not eq secret
      _digest.should_not eq :sha1

      signer.valid?(data, _digest).should be_false
      signer.valid?(_data, secret).should be_false
      signer.valid?(_data, _digest).should be_true
    end
  end

  describe "#verify" do
    it "should generate, read and verify signed data" do
      LOOP_ITER.times do |i|
        data = "abcd #{i}"
        secret = "super secret"
        signer = Crypt::Signer.new(secret)

        signed_data = signer.sign(data)
        signed_data.should be_a(String)
        signed_data.should_not eq data
        signed_data.should_not eq secret

        signer.verify(signed_data).should eq data
      end
    end

    it "should verify signed data from another instance" do
      LOOP_ITER.times do |i|
        data = "abcd #{i}"
        secret = "super secret"
        signer = Crypt::Signer.new(secret)
        signed_data = signer.sign(data)

        signer2 = Crypt::Signer.new(secret)
        signer2.verify(signed_data).should eq data
      end
    end

    it "should be not valid when the secret is different." do
      data = "abcd"
      secret = "super secret"
      signer = Crypt::Signer.new(secret)
      signed_data = signer.sign(data)

      signer2 = Crypt::Signer.new("#{secret}0")

      expect_raises(Crypt::SignatureError, Crypt::Signer::INVALID_SIGN) do
        signer2.verify(signed_data)
      end
    end

    it "should raise if receive bad data" do
      signer = Crypt::Signer.new("secret")
      signed_data = signer.sign("abcd")
      altered_signature = signed_data.sub(0..2, "re1")

      # Altered signature
      expect_raises(Crypt::SignatureError, Crypt::Signer::INVALID_SIGN) do
        signer.verify(altered_signature)
      end

      # Bad data
      expect_raises(Crypt::SignatureError, Crypt::Signer::INVALID_SIGN) do
        signer.verify("ab#{SIGN_SEP}cd")
      end

      # Bad data format
      expect_raises(Crypt::SignatureError, Crypt::Signer::INVALID_SIGN) do
        signer.verify("abcd")
      end

      expect_raises(Crypt::SignatureError, Crypt::Signer::INVALID_SIGN) do
        signer.verify(Base64.encode("ab#{SIGN_SEP}hug"))
      end

      expect_raises(Crypt::SignatureError, Crypt::Signer::INVALID_SIGN) do
        signer.verify(Base64.encode("abhug"))
      end
    end

    it "should raise a custom message if receive bad data" do
      signer = Crypt::Signer.new("secret")

      expect_raises(Crypt::SignatureError, "Oops!") do
        signer.verify("ab#{SIGN_SEP}cd", "Oops!")
      end
    end
  end

  describe "#verify_raw" do
    it "should generate, read and verify signed data" do
      LOOP_ITER.times do |i|
        data = "abcd #{i}"
        secret = "super secret"
        signer = Crypt::Signer.new(secret)

        signed_data = signer.sign(data)
        signed_data.should be_a(String)
        signed_data.should_not eq data
        signed_data.should_not eq secret

        signer.verify_raw(signed_data).should eq data.to_slice
      end
    end

    it "should verify signed data from another instance" do
      LOOP_ITER.times do |i|
        data = "abcd #{i}"
        secret = "super secret"
        signer = Crypt::Signer.new(secret)
        signed_data = signer.sign(data)

        signer2 = Crypt::Signer.new(secret)
        signer2.verify_raw(signed_data).should eq data.to_slice
      end
    end

    it "should be not valid when the secret is different." do
      data = "abcd"
      secret = "super secret"
      signer = Crypt::Signer.new(secret)
      signed_data = signer.sign(data)

      signer2 = Crypt::Signer.new("#{secret}0")

      expect_raises(Crypt::SignatureError, Crypt::Signer::INVALID_SIGN) do
        signer2.verify_raw(signed_data)
      end
    end

    it "should raise if receive bad data" do
      signer = Crypt::Signer.new("secret")
      signed_data = signer.sign("abcd")
      altered_signature = signed_data.sub(0..2, "re1")

      # Altered signature
      expect_raises(Crypt::SignatureError, Crypt::Signer::INVALID_SIGN) do
        signer.verify_raw(altered_signature)
      end

      expect_raises(Crypt::SignatureError, Crypt::Signer::INVALID_SIGN) do
        signer.verify_raw("ab#{SIGN_SEP}cd")
      end

      expect_raises(Crypt::SignatureError, "IndexError: Index out of bounds") do
        signer.verify_raw("abcd")
      end

      expect_raises(Crypt::SignatureError, "IndexError: Index out of bounds") do
        signer.verify_raw(Base64.encode("ab#{SIGN_SEP}hug"))
      end

      expect_raises(Crypt::SignatureError, Crypt::Signer::INVALID_SIGN) do
        signer.verify_raw("ab#{SIGN_SEP}hug".to_slice)
      end

      expect_raises(Crypt::SignatureError, "IndexError: Index out of bounds") do
        signer.verify_raw("abhug".to_slice)
      end

      expect_raises(Crypt::SignatureError, "IndexError: Index out of bounds") do
        signer.verify_raw(Base64.encode("ab#{SIGN_SEP}hug").to_slice)
      end
    end

    it "should raise a custom message if receive bad data" do
      signer = Crypt::Signer.new("secret")

      expect_raises(Crypt::SignatureError, "Oops!") do
        signer.verify_raw("ab#{SIGN_SEP}cd", "Oops!")
      end
    end
  end

  describe "#verify_and_decode" do
    it "should generate, read and verify signed data" do
      LOOP_ITER.times do |i|
        data = "abcd #{i}"
        secret = "super secret"
        signer = Crypt::Signer.new(secret)

        signed_data = signer.sign(data)
        signed_data.should be_a(String)
        signed_data.should_not eq data
        signed_data.should_not eq secret

        signer.verify_and_decode(signed_data).should eq data
      end
    end

    it "should verify signed data from another instance" do
      LOOP_ITER.times do |i|
        data = "abcd #{i}"
        secret = "super secret"
        signer = Crypt::Signer.new(secret)
        signed_data = signer.sign(data)

        signer2 = Crypt::Signer.new(secret)
        signer2.verify_and_decode(signed_data).should eq data
      end
    end

    it "should be not valid when the secret is different." do
      data = "abcd"
      secret = "super secret"
      signer = Crypt::Signer.new(secret)
      signed_data = signer.sign(data)

      signer2 = Crypt::Signer.new("#{secret}0")
      signer2.verify_and_decode(signed_data).should eq nil
    end

    it "should return nil if receive bad data" do
      signer = Crypt::Signer.new("secret")
      signed_data = signer.sign("abcd")
      altered_signature = signed_data.sub(0..2, "re1")

      signer.verify_and_decode(altered_signature).should eq nil
      signer.verify_and_decode("ab#{SIGN_SEP}cd").should eq nil
      signer.verify_and_decode("abcd").should eq nil
      signer.verify_and_decode(Base64.encode("ab#{SIGN_SEP}hug")).should eq nil
    end
  end
end
