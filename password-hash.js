/**
 * Node.js PasswordHash port
 * 
 * @see https://www.openwall.com/phpass/ Original PHP class
 * 
 * @author Glauber Portella <glauberportella@gmail.com>
 * 
 * LICENSE
 * 
 * THE MIT LICENSE
 * 
 * Copyright (c) 2018 Glauber Portella glauberportella@gmail.com
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a 
 * copy of this software and associated documentation files (the "Software"), 
 * to deal in the Software without restriction, including without limitation 
 * the rights to use, copy, modify, merge, publish, distribute, sublicense, 
 * and/or sell copies of the Software, and to permit persons to whom the 
 * Software is furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included 
 * in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS 
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, 
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS 
 * IN THE SOFTWARE. 
 */

const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const cryptoJS = require('crypto-js');

// PHP Javscript ported functions
const { chr, ord, strpos } = require('locutus/php/strings');
const { uniqid } = require('locutus/php/misc');
const { rand } = require('locutus/php/math');
const { microtime } = require('locutus/php/datetime');

const CRYPT_BLOWFISH = 1;
const CRYPT_EXT_DES = 2;

class PasswordHash {
    constructor(iteration_count_log2, portable_hashes, php_major_version) {
        this.php_major_version = php_major_version || 7;

        this.itoa64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

        if (iteration_count_log2 < 4 || iteration_count_log2 > 31)
            iteration_count_log2 = 8;

        this.iteration_count_log2 = iteration_count_log2;

        this.portable_hashes = portable_hashes;

        const mtime = microtime();
        const uniq = uniqid(rand(), true);

        this.random_state = `${mtime}${uniq}`;
    }

    /**
     * Get cryptographically strong pseudorandom bytes 
     *
     * @param {integer} count
     * @return {Promise}
     */
    get_random_bytes(count) {
      return new Promise((resolve, reject) => {
           crypto.randomBytes(count, function (err, buff) {
               if (err) {
                   reject(err);
               } else {
                   resolve(buff.toString('binary'));
               }
           });
       });
    }

    encode64(input, count) {
        let output = '';
        let i = 0, value;
        let v;

        do {
            value = ord(input.charAt(i++));
            v = value & 0x3F;
            output = `${output}${this.itoa64.charAt(v)}`;
            if (i < count) {
                value |= ord(input.charAt(i)) << 8;
            }
            v = (value >> 6) & 0x3F;
            output = `${output}${this.itoa64.charAt(v)}`;
            if (i++ >= count) {
                break;
            }
            if (i < count) {
                value |= ord(input.charAt(i)) << 16;
            }
            v = (value >> 12) & 0x3F;
            output = `${output}${this.itoa64.charAt(v)}`;
            if (i++ >= count) {
                break;
            }
            v = (value >> 18) & 0x3F;
            output = `${output}${this.itoa64.charAt(v)}`;
        } while (i < count);

        return output;
    }

    gensalt_private(input) {
        let output = '$P$';

        // INFO: sum 5 for PHP >= 5 or sum 3 otherwise
        const inc = this.php_major_version >= 5 ? 5 : 3;
        const index = Math.min(this.iteration_count_log2 + inc, 30);
        const char = this.itoa64.charAt(index);
        const encoded = this.encode64(input, 6);
        output = `${output}${char}`;
        output = `${output}${encoded}`;

        return output;
    }

    crypt_private(password, setting) {
        let output = '*0';

        if (setting.substr(0, 2) == output)
            output = '*1';

        const id = setting.substr(0, 3);
        // We use "$P$", phpBB3 uses "$H$" for the same thing
        if (id != '$P$' && id != '$H$')
            return output;

        const count_log2 = strpos(this.itoa64, setting.charAt(3));
        if (count_log2 < 7 || count_log2 > 30)
            return output;

        let count = 1 << count_log2;

        const salt = setting.substr(4, 8);
        if (salt.length != 8) {
            return output;
        }

        let hash = crypto.createHash('md5').update(`${salt}${password}`, 'binary').digest('binary');
        do {
            hash = crypto.createHash('md5').update(`${hash}${password}`, 'binary').digest('binary');
        } while (--count);
        output = setting.substr(0, 12);
        output = `${output}${this.encode64(hash, 16)}`;

        return output;
    }

    gensalt_extended(input) {
        let count_log2 = Math.min(this.iteration_count_log2 + 8, 24);
        // This should be odd to not reveal weak DES keys, and the
        // maximum valid value is (2**24 - 1) which is odd anyway.
        let count = (1 << count_log2) - 1;

        let output = '_';
        output = `${output}${this.itoa64.charAt(count & 0x3F)}`;
        output = `${output}${this.itoa64.charAt((count >> 6) & 0x3F)}`;
        output = `${output}${this.itoa64.charAt((count >> 12) & 0x3F)}`;
        output = `${output}${this.itoa64.charAt((count >> 18) & 0x3F)}`;

        output = `${output}${this.encode64(input, 3)}`;

        return output;
    }

    gensalt_blowfish(input) {
        // This one needs to use a different order of characters and a
        // different encoding scheme from the one in encode64() above.
        // We care because the last character in our encoded string will
        // only represent 2 bits.  While two known implementations of
        // bcrypt will happily accept and correct a salt string which
        // has the 4 unused bits set to non-zero, we do not want to take
        // chances and we also do not want to waste an additional byte
        // of entropy.
        const itoa64 = './ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

        let output = '$2a$';
        output = `${output}${chr(ord('0') + this.iteration_count_log2 / 10)}`;
        output = `${output}${chr(ord('0') + this.iteration_count_log2 % 10)}`;
        output = output + '$';

        let i = 0;
        do {
            let c1 = ord(input.charAt(i++));
            output = `${output}${itoa64.charAt(c1 >> 2)}`;
            c1 = (c1 & 0x03) << 4;
            if (i >= 16) {
                output = `${output}${itoa64.charAt(c1)}`;
                break;
            }

            let c2 = ord(input.charAt(i++));
            c1 |= c2 >> 4;
            output = `${output}${itoa64.charAt(c1)}`;
            c1 = (c2 & 0x0f) << 2;

            c2 = ord(input.charAt(i++));
            c1 |= c2 >> 6;
            output = `${output}${itoa64.charAt(c1)}`;
            output = `${output}${itoa64.charAt(c2 & 0x3F)}`;
        } while (1);

        return output;
    }

    /**
     * @TODO port crypt() PHP function to Javascript
     * 
     * @param {string} password
     * @param {integer} algorithm Bitwise options CRYPT_BLOWFISH | CRYPT_EXT_DES | 0
     * @return {Promise} 
     */
    HashPassword(password, algorithm) {
        algorithm = algorithm || 0;

        if (password.length > 4096) {
            return '*';
        }

        let random = '';

        if ((algorithm & CRYPT_BLOWFISH) && !this.portable_hashes) {
            return this._hashWithBcrypt(password);
        } else if ((algorithm & CRYPT_EXT_DES) && !this.portable_hashes) {
            return this._hashWithDes(random, password);
        } else {
            return this._hashWithCryptPrivate(random, password);
        }
    }

    /**
     * 
     * @param {string} random
     * @param {string} password
     * @return {Promise} 
     */
    _hashWithBcrypt(password) {
        return new Promise((resolve, reject) => {
            this.get_random_bytes(16)
                .then(random => {
                    bcrypt.hash(password, this.gensalt_blowfish(random), (err, hash) => {
                        if (err) {
                            reject(err);
                        } else {
                            if (hash.length == 60) {
                                resolve(hash);
                            } else {
                                // try with DES
                                this._hashWithDes(random, password)
                                    .then(hash => resolve(hash))
                                    .catch(error => reject(error));
                            }
                        }
                    });
                })
                .catch(error => reject(error));
        });
    }

    /**
     * 
     * @param {string} random
     * @param {string} password
     * @return {Promise} 
     */
    _hashWithDes(random, password) {
        return new Promise((resolve, reject) => {
            if (random.length < 3) {
                return this.get_random_bytes(3)
                    .then(random => {
                        let hash =
                            cryptoJS.TripleDES.encrypt(password, this.gensalt_extended(random));
                        if (hash.length == 20) {
                            resolve(hash);
                        } else {
                            this._hashWithCryptPrivate(random, password)
                                .then(hash => resolve(hash))
                                .catch(error => reject(error));
                        }
                    })
                    .catch(error => reject(error));
            } else {
                let hash =
                    cryptoJS.TripleDES.encrypt(password, this.gensalt_extended(random));
                if (hash.length == 20) {
                    resolve(hash);
                } else {
                    this._hashWithCryptPrivate(random, password)
                        .then(hash => resolve(hash))
                        .catch(error => reject(error));
                }
            }
        });
    }

    /**
     * 
     * @param {string} random
     * @param {string} password
     * @return {Promise} 
     */
    _hashWithCryptPrivate(random, password) {
        // Returning '*' on error is safe here, but would _not_ be safe
        // in a crypt(3)-like function used _both_ for generating new
        // hashes and for validating passwords against existing hashes.
        return new Promise((resolve, reject) => {
            if (random.length < 6) {
                this.get_random_bytes(6)
                    .then(random => {
                        let hash =
                            this.crypt_private(password,
                                this.gensalt_private(random));
                        if (hash.length == 34) {
                            resolve(hash);
                        } else {
                            resolve('*');
                        }
                    })
                    .catch(error => reject(error));
            } else {
                let hash =
                    this.crypt_private(password, this.gensalt_private(random));
                if (hash.length == 34) {
                    resolve(hash);
                } else {
                    // Returning '*' on error is safe here, but would _not_ be safe
                    // in a crypt(3)-like function used _both_ for generating new
                    // hashes and for validating passwords against existing hashes.
                    resolve('*');
                }
            }
        });
    }

    CheckPassword(password, stored_hash) {
        if (password.length > 4096) {
            return false;
        }

        let hash = this.crypt_private(password, stored_hash);
        if (hash.charAt(0) == '*')
            hash = cryptoJS.TripleDES.encrypt(password, stored_hash);

        return hash === stored_hash;
    }
}

module.exports.CRYPT_BLOWFISH = CRYPT_BLOWFISH;
module.exports.CRYPT_EXT_DES = CRYPT_EXT_DES;
module.exports.PasswordHash = PasswordHash;
