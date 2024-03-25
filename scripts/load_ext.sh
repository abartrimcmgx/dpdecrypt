set -e

psql -v ON_ERROR_STOP=1 --username postgres --dbname sorting_test <<-EOSQL
  CREATE EXTENSION IF NOT EXISTS "dpdecrypt";
  select extname FROM pg_extension;
EOSQL