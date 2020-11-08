# This file is part of "crypt" module.
#
# This source code is licensed under the MIT license, please view the LICENSE
# file distributed with this source code. For the full
# information and documentation: https://github.com/Nicolab/crystal-crypt
# ------------------------------------------------------------------------------

require "./spec_helper"
require "../src/bcrypt"

describe "Bcrypt" do
  describe "Crypt.create_bcrypt_password" do
    it "should generate, read and verify Crypto::Bcrypt hashes" do
      password = Crypt.create_bcrypt_password("super secret")
      password.should be_a Crypto::Bcrypt::Password
      password.cost.should eq 11
      password.to_s.size.should eq 60
      password.verify("wrong secret").should be_false
      password.verify("super secret").should be_true

      password = Crypt.create_bcrypt_password("super secret", cost: 10)
      password.should be_a Crypto::Bcrypt::Password
      password.cost.should eq 10
      password.to_s.size.should eq 60
      password.verify("wrong secret").should be_false
      password.verify("super secret").should be_true
    end
  end

  describe "Crypt.load_bcrypt_password" do
    it "should load a Bcrypt password hash." do
      password = Crypt.create_bcrypt_password("super secret")
      password2 = Crypt.load_bcrypt_password("#{password}")
      password2.cost.should eq 11
      password2.should be_a Crypto::Bcrypt::Password
      password2.to_s.size.should eq 60
      password2.verify("wrong secret").should be_false
      password2.verify("super secret").should be_true

      password = Crypt.create_bcrypt_password("super secret", cost: 8)
      password2 = Crypt.load_bcrypt_password("#{password}")
      password2.cost.should eq 8
      password2.should be_a Crypto::Bcrypt::Password
      password2.to_s.size.should eq 60
      password2.verify("wrong secret").should be_false
      password2.verify("super secret").should be_true
    end
  end
end
