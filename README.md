# Node PasswordHash module

A port of Wordpress wp-includes/class-phpass.php class used to hash passwords.

See original PHP class PHPass at [https://www.openwall.com/phpass/](https://www.openwall.com/phpass/).

# Installation

`npm install node-phpass`

# Password hash

```js
const PasswordHash = require('node-phpass').PasswordHash;
const CRYPT_BLOWFISH = require('node-phpass').CRYPT_BLOWFISH;
const CRYPT_EXT_DES = require('node-phpass').CRYPT_EXT_DES;
// or
// const { PasswordHash, CRYPT_BLOWFISH, CRYPT_EXT_DES } = require('node-phpass')

const len = 8;
const portable = true;
// major PHP version, 5 or 7, as it is a port of PHPass PHP class we rely
// on php version on gensalt_private() method, it is an optional constructor 
// argument wich defaults to 7
const phpversion = 7; 

const hasher = new PasswordHash(len, portable, phpversion);
console.log('Hashing 123456 string');
hasher.HashPassword('123456').then(hash => console.log('Private hash: ', hash));
hasher.HashPassword('123456', CRYPT_BLOWFISH).then(hash => console.log('BCrypt hash: ', hash));
hasher.HashPassword('123456', CRYPT_EXT_DES).then(hash => console.log('DES hash: ', hash));
```

# Verify a hash

```js
const PasswordHash = require('node-phpass').PasswordHash;
// or
// const { PasswordHash } = require('node-phpass')

const len = 8;
const portable = true;
// major PHP version, 5 or 7, as it is a port of PHPass PHP class we rely
// on php version on gensalt_private() method, it is an optional constructor 
// argument wich defaults to 7
const phpversion = 7; 

const hasher = new PasswordHash(len, portable, phpversion);

const storedhash = '$P$BVaXtDXwf/ceSVp8VpLKx8bS2Y4O5F/';
const storedhash2 = '$P$BVaXtDXwf/ceSVp8VpLKx8bS2Y4O5E/';
const password = '123456';
const valid = hasher.CheckPassword(password, storedhash);
const invalid = hasher.CheckPassword(password, storedhash2);

console.log(valid ? 'OK' : 'INVALID');
console.log(invalid ? 'OK' : 'INVALID');
```

# Contributing

Any help on testing and improvements in this class is welcome. Fork the repo and send a PR.

# License

THE MIT LICENSE

Copyright (c) 2018 Glauber Portella glauberportella@gmail.com

Permission is hereby granted, free of charge, to any person obtaining a 
copy of this software and associated documentation files (the "Software"), 
to deal in the Software without restriction, including without limitation 
the rights to use, copy, modify, merge, publish, distribute, sublicense, 
and/or sell copies of the Software, and to permit persons to whom the 
Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included 
in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS 
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, 
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS 
IN THE SOFTWARE. 
