CREATE EXTENSION IF NOT EXISTS pgcrypto;

DROP FUNCTION IF EXISTS decrypt_aes_gcm_udf(cipher_key bytea, cipher_text bytea);

-- This function calculates the AES Mode GCM using the base pgcrypto library
-- It prioritizes readability over speed. 
CREATE OR REPLACE FUNCTION
    decrypt_aes_gcm_udf(cipher_key bytea, cipher_text bytea)
    RETURNS bytea
    LANGUAGE PLPGSQL
    IMMUTABLE
    PARALLEL SAFE
    STRICT
AS
$func$
DECLARE
    -- CONSTANTS (INLINE THESE IF NECESSARY)
    IV_SIZE         int := 12;
    TAG_SIZE        int := 16;
    AES_BLOCK_SIZE  int := 16;
    COUNTER_OFFSET  int := 2;

    -- Variables
    iv              bytea;
    cipher_len      int;
    pad_size        int;
    block_total     int;
    block_idx       int;
    o               int; -- offset for bitwise 
    -- Used during for each block decrypt

    block           bytea;
    block_iv        bytea;
    block_offset    int;
    block_keystream bytea;
    block_stream    varbit;

    -- The plain text of the decrypted blocks go here
    out_buff        bytea;
BEGIN
    out_buff := '';
    iv := substring(cipher_text, 1, IV_SIZE);

    -- Discard the authorization tag, no verification in this impl.
    cipher_text := substring(cipher_text, IV_SIZE + 1, length(cipher_text) - (IV_SIZE + TAG_SIZE));

    -- Get the total AES_BLOCKS (16 bytes) excluding the iv and auth_tag
    cipher_len := length(cipher_text);
    block_total := (cipher_len / AES_BLOCK_SIZE) + 1;

    -- 	Ensure the final block is padded. 
    pad_size := (AES_BLOCK_SIZE - (cipher_len % AES_BLOCK_SIZE) - 1);
    FOR o IN 0..pad_size
        LOOP
            cipher_text := cipher_text || '\x00'::bytea;
        END LOOP;

    -- AES CTR Mode w/ (2 used as initial counter value) 
    FOR block_idx IN 0..block_total
        LOOP
            block_offset := (block_idx * AES_BLOCK_SIZE) + 1;

            block := substring(cipher_text, block_offset, AES_BLOCK_SIZE);
            block_iv := iv || int4send(block_idx + COUNTER_OFFSET);

            -- CTR AES method
            block_keystream := encrypt(block_iv, cipher_key, 'aes-ecb/pad:none');

            -- XOR operation between keystream and block data.
            block_stream := (right(block_keystream::text, -1)::bit(128) # right(block::text, -1)::bit(128));

            -- Append decrypted block to output buffer
            out_buff := out_buff || substring(varbit_send(block_stream), 5);
        END LOOP;

    RETURN substring(out_buff, 1, cipher_len);
END
$func$;

-- "this is dark"
-- SELECT decrypt_aes_gcm_udf(
--                'abc$#128djdyAgbjau&YAnmcbagryt5x'::bytea,
--                decode('f798b96a2105f2006f55fe29969d56434f15c4f03c8228a9643c1e8ffa49e1456a5ad07cfdea362e', 'hex')) AS examples
-- UNION
-- -- "this is dark. this is dark. this is dark. this is dark. this is dark. this is dark. this is dark. this is dark. this is dark. this is dark. this is dark. this is dark. this is dark. this is dark. this is dark. this is dark. this is dark. this is dark. this is dark. this is dark. this is dark. this is dark. this is dark. this is dark. this is dark. this is dark. this is dark. this is dark. this is dark. this is dark. "
-- SELECT decrypt_aes_gcm_udf(
--                'abc$#128djdyAgbjau&YAnmcbagryt5x'::bytea,
--                decode('13993854ec05669617edeaab197abc550c525da2c26fc3f791ee7e9f92ac75e61f8ca4d1575d02cba8e4f12674c195a13d22707d017c42a2954bade49368388dabd4197d47efc3a4abb4a24371e2c29c7dcb5142ee500def05b03bf4e5920248853cb9180ace53e9b521a4c97bb3d4fdbb4dc90977b9b992dda6a12f2748b9e97783293acbd55a6929d367a0978acf76506b4cac0844added993a87a1301b4130408f55d0e18ab1ffe23957fc47336f4bbb42ae27409d3777c24a3b97a01917bb009d91a265b6015fa6b0aae56b1e5a9a4aa3acd53464198e9a947c56641317cb883e117ecffc3b64cc808a78473fe3c9b0be68f22b268640ce95877c125a31150bf3009515f5ca1fac78aa55bdaa67b65830d62864ca08e4af606cc31a6e248649bbd29ddae550563d0666268cdf1841a63ea7a384b88b0ec07a093728a4bc302fc36605336340b122f5b0e31deab5a7704c5d592442d00bbbeb1b9d0dd974b4ab4edc1b2fc8366c9d431a392e338fe696f71897b1566d4c02b2d5ee814c8e622e3c07fbb3782f613d008bea16cb84cf3eab0a273a70664c6c503e138f8f99cdadec7c32f49ae9740238afad29ecf87950585ee87cb2fcefdafca22246b08f3', 'hex')
--        );
-- This function takes a keyring in the format  { key_id(16) || key(32) || key_id || key || ... } <-- repeating fixed length without a delimiter
-- and a cipher text in the format              { magic_number || key_id || cipher_text }
DROP FUNCTION IF EXISTS dp_decrypt_udf(cipher_keys bytea, cipher_text bytea);
CREATE OR REPLACE FUNCTION
    dp_decrypt_udf(cipher_keys bytea, cipher_text bytea)
    RETURNS bytea
    LANGUAGE PLPGSQL
    IMMUTABLE
    PARALLEL SAFE
    STRICT
AS
$func$
DECLARE
    -- CONSTANTS (INLINE THESE IF NECESSARY)
    MAGIC_NUMBER_SIZE       int := 4;
    KEY_ID_SIZE             int := 16;
    KEY_SIZE                int := 32;
    IV_SIZE                 int := 16;
    ENCRYPTED_START_GCM     int := MAGIC_NUMBER_SIZE + KEY_ID_SIZE + 1;
    ENCRYPTED_START_CBC     int := MAGIC_NUMBER_SIZE + KEY_ID_SIZE + IV_SIZE + 1;
    -- HMAC_SIZE            int := 32;

    -- Variables
    magic_number            int;
    cipher_key              bytea;
    cipher_iv               bytea;
    key_id                  bytea;
    key_ring_length         int;
BEGIN
    magic_number := ('x' || right(substring(cipher_text, 1, MAGIC_NUMBER_SIZE)::text, 8))::bit(32)::int;
    key_id := substring(cipher_text, MAGIC_NUMBER_SIZE + 1, KEY_ID_SIZE);
    -- Handle extracting the key from the keyring
    -- { key_id(16) || key(32) || key_id || key || ... }
    -- Get the length of the key_id + key + key_id + key, this will let us know how many keys are in the keyring
    key_ring_length := length(cipher_keys) / (KEY_ID_SIZE + KEY_SIZE);
    -- Next, search the key_ring_list for the key_id
    FOR i IN 0..key_ring_length
        LOOP
            IF key_id = substring(cipher_keys, (i * (KEY_ID_SIZE + KEY_SIZE)) + 1, KEY_ID_SIZE)
                THEN
                    cipher_key := substring(cipher_keys, (i * (KEY_ID_SIZE + KEY_SIZE)) + KEY_ID_SIZE + 1, KEY_SIZE);
                    EXIT;
            END IF;
        END LOOP;
    -- If the key_id is not found, raise an exception
    IF cipher_key IS NULL
        THEN RAISE EXCEPTION 'Key not found in keyring';
    END IF;
    -- Decrypt the cipher text based on the magic number
    CASE magic_number
        WHEN 0x1e27f0de THEN
            RETURN decrypt_aes_gcm_udf(
                    cipher_key, 
                    substring(cipher_text, ENCRYPTED_START_GCM)
                   );
        WHEN 0x1e27f0df THEN
            cipher_iv := substring(cipher_text, ENCRYPTED_START_GCM, IV_SIZE);
            RETURN decrypt_iv(substring(cipher_text, ENCRYPTED_START_CBC), 
                              cipher_key, 
                              cipher_iv,
                              'aes-cbc/pad:pkcs'
                   );
        ELSE RAISE EXCEPTION 'Invalid magic number';
        END CASE;
END
$func$;

SELECT 
    -- Convert binary back to text
    convert_from(
        -- UDF to decrypt the cipher text
        dp_decrypt_udf(
            -- Keyring in the format { key_id(16) || key(32) || key_id || key || ... }
                decode(
                        'ae197f65469ba949935bd22be24991c272eccd3de76ed7db3ebcd2bad7a32fd808cae53880b4324489ee2287db588efa',
                        'hex'),
            -- Cipher text in the format { magic_number || key_id || cipher_text }
                decode(
                        '1e27f0dfae197f65469ba949935bd22be24991c2b198e0b891dd8550af88fd8284839189a03c4a23ee9a948460ba866f2c19f50bf8da32ae2b31336bc6527300401e1b66',
                        'hex')
        ), 'utf8'
    );

-- '908c8eaf9750da92a119f24c02822960cdb30544d7b4716e160314cdcd477e7cd1bd81d947fc5b4e9703f053b4ba0c85729ab1'

-- AES/CBC {magic_number(4) || key_id(16) || iv(16) || cipher_text}
-- '1e27f0dfae197f65469ba949935bd22be24991c21e27f0dfae197f65469ba949935bd22be24991c2369f2c9834f7a47c5b141db128023d721df20ee86bac929f60afb71b63b0d4b0bf94c18ec6e956d1b713db420126b72c'
