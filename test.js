/**
 * To test use:
 * 
 * For password hash generator: 
 * 
 * node test.js <password>
 * 
 * For password check:
 * 
 * node test.js <password> '<hash>'
 * 
 * Wrap <hash> in single quotes (hash can have $ chars)
 */
const { PasswordHash, CRYPT_BLOWFISH, CRYPT_EXT_DES } = require('./password-hash');

const args = process.argv.slice(2);

let password, storedHash;

if (args.length < 2) {
    password = args[0] ? args[0] : '123456';
} else if (args.length >= 2) {
    password = args[0];
    storedHash = args[1];
}

const hasher = new PasswordHash(8, true);
console.info(hasher);

if (storedHash) {
    console.log('check password = ', hasher.CheckPassword(password, storedHash) ? 'OK' : 'NOT OK');
} else {
    hasher.HashPassword(password, CRYPT_BLOWFISH)
        .then(hash => console.log('Hash (Blowfish) = ', hash))
        .catch(error => console.error(error));
    
    hasher.HashPassword(password, CRYPT_EXT_DES)
        .then(hash => console.log('Hash (DES) = ', hash))
        .catch(error => console.error(error));
    
    hasher.HashPassword(password)
        .then(hash => console.log('Hash (Private) = ', hash))
        .catch(error => console.error(error));
}

