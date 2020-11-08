# Crypt

[![CI Status](https://github.com/Nicolab/crystal-crypt/workflows/CI/badge.svg?branch=master)](https://github.com/Nicolab/crystal-crypt/actions) [![GitHub release](https://img.shields.io/github/release/Nicolab/crystal-crypt.svg)](https://github.com/Nicolab/crystal-crypt/releases) [![Docs](https://img.shields.io/badge/docs-available-brightgreen.svg)](https://nicolab.github.io/crystal-crypt/)

Cryptographic utilities made easy for [Crystal lang](https://crystal-lang.org).

This module provides cryptographic features, with abstractions on top of OpenSSL
and Crypto (included in the Crystal standard-library).

## Installation

1. Add the dependency to your `shard.yml`:

```yaml
dependencies:
  crypt:
    github: nicolab/crystal-crypt
```

2. Run `shards install`

## Usage

To optimize the size of the final binary, features are decoupled,
so each module must be included when you need it.

### OpenSSL Cipher: Encrypt / Decrypt

> [API doc: Crypt::Crypter](https://nicolab.github.io/crystal-crypt/Crypt/Crypter.html)

```crystal
require "crypt"
require "crypt/crypter"
require "crypt/random"

data = "super secret data"
secret = Crypt.random_string(32)
crypter = Crypt::Crypter.new(secret)

# Data encrypted
encrypted = crypter.encrypt(data)

# Data decrypted
decrypted_bytes = crypter.decrypt(encrypted)

# Decrypted data (Bytes)
puts decrypted_bytes

# Convert Bytes to String
puts String.new(decrypted_bytes)
```

#### With signature

Encrypt with a crypto signature:

```crystal
require "crypt"
require "crypt/crypter"
require "crypt/random"

data = "super secret data"
secret = Crypt.random_string(32)
crypter = Crypt::Crypter.new(secret)

# Data encrypted and signed
encrypted = crypter.encrypt(data, :sign)

# Data verified and decrypted
decrypted_bytes = crypter.decrypt(encrypted, :sign)

# Decrypted data (Bytes)
puts decrypted_bytes

# Convert Bytes to String
puts String.new(decrypted_bytes)
```

### Signer

Sign and verify given data.

```crystal
require "crypt"
require "crypt/signer"

data = "Hello Crystal!"
secret = "super secret"
signer = Crypt::Signer.new(secret)

# Sign the data
signed_data = signer.sign(data)

# => Encoded String, URL and filename safe alphabet (RFC 4648).
puts signed_data

# Verify the data integrity and get it
puts signer.verify(signed_data)         # => "Hello Crystal!"
puts signer.verify(signed_data) == data # => true
```

> [API doc: Crypt::Signer](https://nicolab.github.io/crystal-crypt/Crypt/Signer.html)

### Bcrypt password

Generate, read and verify `Crypto::Bcrypt` hashes:

```crystal
require "crypt"
require "crypt/bcrypt"

password = Crypt.create_bcrypt_password("super secret", cost: 10)
# => $2a$10$rI4xRiuAN2fyiKwynO6PPuorfuoM4L2PVv6hlnVJEmNLjqcibAfHq

password.verify("wrong secret") # => false
password.verify("super secret") # => true
```

> [API doc: Crypt.create_bcrypt_password](https://nicolab.github.io/crystal-crypt/Crypt.html#create_bcrypt_password)

---

Loads a `Bcrypt` password hash.

```crystal
require "crypt"
require "crypt/bcrypt"

password = Crypt.load_bcrypt_password(
  "$2a$10$X6rw/jDiLBuzHV./JjBNXe8/Po4wTL0fhdDNdAdjcKN/Fup8tGCya"
)
password.version # => "2a"
password.salt    # => "X6rw/jDiLBuzHV./JjBNXe"
password.digest  # => "8/Po4wTL0fhdDNdAdjcKN/Fup8tGCya"

# password.verify("some secret")
```

> [API doc: Crypt.load_bcrypt_password](https://nicolab.github.io/crystal-crypt/Crypt.html#load_bcrypt_password)

### Secure random

```crystal
require "crypt"
require "crypt/random"
```

See API doc:

* [API doc: Crypt.random_string](https://nicolab.github.io/crystal-crypt/Crypt.html#random_string)
* [API doc: Crypt.random_bytes](https://nicolab.github.io/crystal-crypt/Crypt.html#random_bytes)
* [API doc: Crypt.random_bytes_string](https://nicolab.github.io/crystal-crypt/Crypt.html#random_bytes_string)

### Key derivation

Key derivation PKCS5/PBKDF2 (Password-Based Key Derivation Function 2)

```crystal
require "crypt"
require "crypt/key-deriv"
require "crypt/random"

password = "My password"
salt = Crypt.random_string(16)

# key size: 64
Crypt.key_deriv(password, salt)

# key size: 10
Crypt.key_deriv(password, salt, key_size: 10)

# iteration: 2000
Crypt.key_deriv(password, salt, iter: 2000)

# algo: sha256
Crypt.key_deriv(password, salt, algo: :sha256)
```

> [API doc: Crypt.key_deriv](https://nicolab.github.io/crystal-crypt/Crypt.html#key_deriv)

## Contributing

1. Fork it (<https://github.com/nicolab/crystal-crypt/fork>)
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request

### Development

One line:

```sh
./scripts/develop
```

or splitted:

Terminal 1:

```sh
docker-compose up
```

Terminal 2:

```sh
# host
docker-compose exec app bash

# container
just develop
```

When you are done, clean and check the code:

```sh
# container
just format

# host
./scripts/check
```

## LICENSE

[MIT](https://github.com/Nicolab/crystal-crypt/blob/master/LICENSE) (c) 2020, Nicolas Talle.

## Author

| [![Nicolas Tallefourtane - Nicolab.net](https://www.gravatar.com/avatar/d7dd0f4769f3aa48a3ecb308f0b457fc?s=64)](https://github.com/sponsors/Nicolab) |
|---|
| [Nicolas Talle](https://github.com/sponsors/Nicolab) |
| [![Make a donation via Paypal](https://www.paypalobjects.com/en_US/i/btn/btn_donate_SM.gif)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=PGRH4ZXP36GUC) |
