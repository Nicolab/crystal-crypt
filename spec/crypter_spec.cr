# This file is part of "crypt" module.
#
# This source code is licensed under the MIT license, please view the LICENSE
# file distributed with this source code. For the full
# information and documentation: https://github.com/Nicolab/crystal-crypt
# ------------------------------------------------------------------------------

require "./spec_helper"
require "../src/crypter"
require "../src/random"

describe "Crypt::Crypter" do
  Spec.after_each { GC.collect }

  describe "cipher/decipher with signed data" do
    context "String" do
      it "should encrypt and decrypt" do
        LOOP_ITER.times do |i|
          data = "abcd #{i}"
          secret = "#{i}#{Crypt.random_string(31)}"
          crypter = Crypt::Crypter.new(secret)

          signed_data = crypter.encrypt(data, :sign)
          signed_data.should_not eq data
          signed_data.should_not eq data.to_slice

          decrypted_bytes = crypter.decrypt(signed_data, :sign)
          decrypted_bytes.should eq data.to_slice
          String.new(decrypted_bytes).should eq data
        end
      end

      it "should encrypt and decrypt big data" do
        # 5 Mbs
        data = Crypt.random_string(5_000_000)
        secret = Crypt.random_string(32)
        crypter = Crypt::Crypter.new(secret)

        signed_data = crypter.encrypt(data, :sign)
        signed_data.should_not eq data
        signed_data.should_not eq data.to_slice

        decrypted_bytes = crypter.decrypt(signed_data, :sign)
        decrypted_bytes.should eq data.to_slice
        String.new(decrypted_bytes).should eq data
      end

      it "should decrypt data encrypted from another instance" do
        LOOP_ITER.times do |i|
          data = "abcd #{i}"
          secret = "#{i}#{Crypt.random_string(31)}"
          crypter = Crypt::Crypter.new(secret)
          signed_data = crypter.encrypt(data, :sign)

          crypter2 = Crypt::Crypter.new(secret)
          crypter2.decrypt(signed_data, :sign).should eq data.to_slice
        end
      end

      it "should be not valid when the secret is different." do
        LOOP_ITER.times do |i|
          data = "abcd #{i}"
          crypter = Crypt::Crypter.new("#{i}#{Crypt.random_string(31)}")
          signed_data = crypter.encrypt(data, :sign)

          crypter2 = Crypt::Crypter.new("#{i}#{Crypt.random_string(31)}")

          expect_raises(Crypt::SignatureError, Crypt::Signer::INVALID_SIGN) do
            crypter2.decrypt(signed_data, :sign)
          end
        end
      end

      it "should fail to decrypt unsigned data" do
        crypter = Crypt::Crypter.new(Crypt.random_string(32))

        expect_raises(Crypt::SignatureError, "IndexError: Index out of bounds") do
          crypter.decrypt(crypter.encrypt("abcd"), :sign)
        end

        expect_raises(Crypt::SignatureError, "IndexError: Index out of bounds") do
          crypter.decrypt(crypter.encrypt("ab#{SIGN_SEP}cd"), :sign)
        end

        expect_raises(Crypt::SignatureError, "IndexError: Index out of bounds") do
          crypter.decrypt("abcd", :sign)
        end

        expect_raises(Crypt::SignatureError, Crypt::Signer::INVALID_SIGN) do
          crypter.decrypt("ab#{SIGN_SEP}cd", :sign)
        end
      end

      it "should raise a custom message if receive bad data" do
        crypter = Crypt::Crypter.new(Crypt.random_string(32))

        expect_raises(Crypt::SignatureError, "Oops!") do
          crypter.decrypt("ab#{SIGN_SEP}cd", :sign, "Oops!")
        end
      end

      it "should raise Crypt::SecretKeyError with a too short secret (lesser than 32)" do
        expect_raises Crypt::SecretKeyError, /Key length too short: wanted 32, got 8/ do
          crypter = Crypt::Crypter.new(Crypt.random_string(8))
          crypter.encrypt("Hello", :sign)
        end
      end

      it "should be ok with a secret greater than 32" do
        crypter = Crypt::Crypter.new(Crypt.random_string(64))
        signed_data = crypter.encrypt("Hello", :sign)
        String.new(crypter.decrypt(signed_data, :sign)).should eq "Hello"
      end
    end

    context "Bytes" do
      it "should encrypt and decrypt" do
        LOOP_ITER.times do |i|
          data = "abcd #{i}".to_slice
          secret = "#{i}#{Crypt.random_string(31)}"
          crypter = Crypt::Crypter.new(secret)

          signed_data = crypter.encrypt(data, :sign)
          signed_data.should_not eq data
          signed_data.should_not eq String.new(data)

          decrypted_bytes = crypter.decrypt(signed_data, :sign)
          decrypted_bytes.should eq data
          String.new(decrypted_bytes).should eq String.new(data)
        end
      end

      it "should encrypt and decrypt big data" do
        # 5 Mbs
        data = Crypt.random_bytes(5_000_000)
        secret = Crypt.random_string(32)
        crypter = Crypt::Crypter.new(secret)

        signed_data = crypter.encrypt(data, :sign)
        signed_data.should_not eq data
        signed_data.should_not eq String.new(data)

        decrypted_bytes = crypter.decrypt(signed_data, :sign)
        decrypted_bytes.should eq data.to_slice
        String.new(decrypted_bytes).should eq String.new(data)
      end

      it "should decrypt data encrypted from another instance" do
        LOOP_ITER.times do |i|
          data = "abcd #{i}".to_slice
          secret = "#{i}#{Crypt.random_string(31)}"
          crypter = Crypt::Crypter.new(secret)
          signed_data = crypter.encrypt(data, :sign)

          crypter2 = Crypt::Crypter.new(secret)
          crypter2.decrypt(signed_data, :sign).should eq data
        end
      end

      it "should be not valid when the secret is different." do
        LOOP_ITER.times do |i|
          data = "abcd #{i}".to_slice
          crypter = Crypt::Crypter.new("#{i}#{Crypt.random_string(31)}")
          signed_data = crypter.encrypt(data, :sign)

          crypter2 = Crypt::Crypter.new("#{i}#{Crypt.random_string(31)}")

          expect_raises(Crypt::SignatureError, Crypt::Signer::INVALID_SIGN) do
            crypter2.decrypt(signed_data, :sign)
          end
        end
      end

      it "should fail to decrypt unsigned data" do
        crypter = Crypt::Crypter.new(Crypt.random_string(32))

        expect_raises(Crypt::SignatureError, "IndexError: Index out of bounds") do
          crypter.decrypt(crypter.encrypt("abcd").to_slice, :sign)
        end

        expect_raises(Crypt::SignatureError, "IndexError: Index out of bounds") do
          crypter.decrypt(crypter.encrypt("ab#{SIGN_SEP}cd").to_slice, :sign)
        end

        expect_raises(Crypt::SignatureError, "IndexError: Index out of bounds") do
          crypter.decrypt("abcd".to_slice, :sign)
        end

        expect_raises(Crypt::SignatureError, Crypt::Signer::INVALID_SIGN) do
          crypter.decrypt("ab#{SIGN_SEP}cd".to_slice, :sign)
        end
      end

      it "should raise a custom message if receive bad data" do
        crypter = Crypt::Crypter.new(Crypt.random_string(32))

        expect_raises(Crypt::SignatureError, "Oops!") do
          crypter.decrypt("ab#{SIGN_SEP}cd".to_slice, :sign, "Oops!")
        end
      end

      it "should raise Crypt::SecretKeyError with a too short secret (lesser than 32)" do
        expect_raises Crypt::SecretKeyError, /Key length too short: wanted 32, got 8/ do
          crypter = Crypt::Crypter.new(Crypt.random_string(8))
          crypter.encrypt("Hello".to_slice, :sign)
        end
      end

      it "should be ok with a secret greater than 32" do
        crypter = Crypt::Crypter.new(Crypt.random_string(64))
        signed_data = crypter.encrypt("Hello".to_slice, :sign)
        crypter.decrypt(signed_data, :sign).should eq "Hello".to_slice
        String.new(crypter.decrypt(signed_data, :sign)).should eq "Hello"
      end
    end
  end

  describe "cipher/decipher" do
    context "String" do
      it "should encrypt and decrypt" do
        LOOP_ITER.times do |i|
          data = "abcd #{i}"
          secret = "#{i}#{Crypt.random_string(31)}"
          crypter = Crypt::Crypter.new(secret)

          encrypted = crypter.encrypt(data)
          encrypted.should_not eq data
          encrypted.should_not eq data.to_slice

          decrypted_bytes = crypter.decrypt(encrypted)
          decrypted_bytes.should eq data.to_slice
          String.new(decrypted_bytes).should eq data
        end
      end

      it "should encrypt and decrypt big data" do
        # 5 Mbs
        data = Crypt.random_string(5_000_000)
        secret = Crypt.random_string(32)
        crypter = Crypt::Crypter.new(secret)

        encrypted = crypter.encrypt(data)
        encrypted.should_not eq data
        encrypted.should_not eq data.to_slice

        decrypted_bytes = crypter.decrypt(encrypted)
        decrypted_bytes.should eq data.to_slice
        String.new(decrypted_bytes).should eq data
      end

      it "should raise Crypt::SecretKeyError with a too short secret (lesser than 32)" do
        expect_raises Crypt::SecretKeyError, /Key length too short: wanted 32, got 8/ do
          crypter = Crypt::Crypter.new(Crypt.random_string(8))
          crypter.encrypt("Hello")
        end
      end

      it "should decrypt data encrypted from another instance" do
        LOOP_ITER.times do |i|
          data = "abcd #{i}"
          secret = "#{i}#{Crypt.random_string(31)}"
          crypter = Crypt::Crypter.new(secret)
          encrypted = crypter.encrypt(data)

          crypter2 = Crypt::Crypter.new(secret)
          crypter2.decrypt(encrypted).should eq data.to_slice
        end
      end

      it "should be not valid when the secret is different." do
        LOOP_ITER.times do |i|
          data = "abcd #{i}"
          crypter = Crypt::Crypter.new("#{i}#{Crypt.random_string(31)}")
          encrypted = crypter.encrypt(data)

          crypter2 = Crypt::Crypter.new("#{i}#{Crypt.random_string(31)}")

          expect_raises(OpenSSL::Cipher::Error) do
            crypter2.decrypt(encrypted)
          end
        end
      end

      it "should be ok with a secret greater than 32" do
        crypter = Crypt::Crypter.new(Crypt.random_string(64))
        encrypted = crypter.encrypt("Hello")
        String.new(crypter.decrypt(encrypted)).should eq "Hello"
      end
    end

    context "Bytes" do
      it "should encrypt and decrypt" do
        LOOP_ITER.times do |i|
          data = "abcd #{i}".to_slice
          secret = "#{i}#{Crypt.random_string(31)}"
          crypter = Crypt::Crypter.new(secret)

          encrypted = crypter.encrypt(data)
          encrypted.should_not eq data
          encrypted.should_not eq String.new(data)

          decrypted_bytes = crypter.decrypt(encrypted)
          decrypted_bytes.should eq data
          String.new(decrypted_bytes).should eq String.new(data)
        end
      end

      it "should encrypt and decrypt big data" do
        # 5 Mbs
        data = Crypt.random_bytes(5_000_000)
        secret = Crypt.random_string(32)
        crypter = Crypt::Crypter.new(secret)

        encrypted = crypter.encrypt(data)
        encrypted.should_not eq data
        encrypted.should_not eq String.new(data)

        decrypted_bytes = crypter.decrypt(encrypted)
        decrypted_bytes.should eq data
        String.new(decrypted_bytes).should eq String.new(data)
      end

      it "should raise Crypt::SecretKeyError with a too short secret (lesser than 32)" do
        expect_raises Crypt::SecretKeyError, /Key length too short: wanted 32, got 8/ do
          crypter = Crypt::Crypter.new(Crypt.random_string(8))
          crypter.encrypt("Hello".to_slice)
        end
      end

      it "should decrypt data encrypted from another instance" do
        LOOP_ITER.times do |i|
          data = "abcd #{i}".to_slice
          secret = "#{i}#{Crypt.random_string(31)}"
          crypter = Crypt::Crypter.new(secret)
          encrypted = crypter.encrypt(data)

          crypter2 = Crypt::Crypter.new(secret)
          crypter2.decrypt(encrypted).should eq data
        end
      end

      it "should be not valid when the secret is different." do
        LOOP_ITER.times do |i|
          data = "abcd #{i}".to_slice
          crypter = Crypt::Crypter.new("#{i}#{Crypt.random_string(31)}")
          encrypted = crypter.encrypt(data)

          crypter2 = Crypt::Crypter.new("#{i}#{Crypt.random_string(31)}")

          expect_raises(OpenSSL::Cipher::Error) do
            crypter2.decrypt(encrypted)
          end
        end
      end

      it "should be ok with a secret greater than 32" do
        crypter = Crypt::Crypter.new(Crypt.random_string(64))
        encrypted = crypter.encrypt("Hello".to_slice)
        crypter.decrypt(encrypted).should eq "Hello".to_slice
      end
    end
  end
end
