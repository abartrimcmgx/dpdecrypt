\echo Use "CREATE EXTENSION pgcrypsi" to load this file. \quit
CREATE FUNCTION dp_decrypt(bytea, bytea) RETURNS bytea
AS 'MODULE_PATHNAME', 'dp_decrypt' 
LANGUAGE C COST 100 IMMUTABLE STRICT PARALLEL SAFE;