-- AES CBC/GCM tests --
-- Keyring in the format { key_id(16) || key(32) || key_id || key || ... }
-- decode('ae197f65469ba949935bd22be24991c272eccd3de76ed7db3ebcd2bad7a32fd808cae53880b4324489ee2287db588efa', 'hex')
-- AES/CBC {magic_number(4) || key_id(16) || iv(16) || cipher_text}
-- '1e27f0dfae197f65469ba949935bd22be24991c21e27f0dfae197f65469ba949935bd22be24991c2369f2c9834f7a47c5b141db128023d721df20ee86bac929f60afb71b63b0d4b0bf94c18ec6e956d1b713db420126b72c'
-- AES/GCM {magic_number(4) || key_id(16) || iv(16) || cipher_text || tag}
-- placeholder, add a proper gcm hex string 
-- '1e27f0dfae197f65469ba949935bd22be24991c21e27f0dfae197f65469ba949935bd22be24991c2369f2c9834f7a47c5b141db128023d721df20ee86bac929f60afb71b63b0d4b0bf94c18ec6e956d1b713db420126b72c'

-- CBC 'Jackie_Mayer41@yahoo.com'
select dpdecrypt(
    decode('ae197f65469ba949935bd22be24991c272eccd3de76ed7db3ebcd2bad7a32fd808cae53880b4324489ee2287db588efa', 'hex'), 
    decode('1e27f0dfae197f65469ba949935bd22be24991c21e27f0dfae197f65469ba949935bd22be24991c2369f2c9834f7a47c5b141db128023d721df20ee86bac929f60afb71b63b0d4b0bf94c18ec6e956d1b713db420126b72c', 'hex')
    ) as cbc_decrypt_valid;

-- GCM 'Jackie_Mayer41@yahoo.com'
select dpdecrypt(
    decode('ae197f65469ba949935bd22be24991c272eccd3de76ed7db3ebcd2bad7a32fd808cae53880b4324489ee2287db588efa', 'hex'), 
    decode('1e27f0dfae197f65469ba949935bd22be24991c21e27f0dfae197f65469ba949935bd22be24991c2369f2c9834f7a47c5b141db128023d721df20ee86bac929f60afb71b63b0d4b0bf94c18ec6e956d1b713db420126b72c', 'hex')
    ) as gcm_decrypt_valid;

-- Add some invalid tests for, tag, keyring, iv, cipher_text etc.
