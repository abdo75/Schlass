#!/bin/bash
set -e

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    CREATE ROLE schlass_migrations WITH LOGIN PASSWORD 'schlass_migrations';
    CREATE ROLE schlass_app WITH LOGIN PASSWORD 'schlass_app';

    GRANT ALL PRIVILEGES ON DATABASE $POSTGRES_DB TO schlass_migrations;
    GRANT CREATE ON SCHEMA public TO schlass_migrations;
    GRANT CONNECT ON DATABASE $POSTGRES_DB TO schlass_app;
    GRANT USAGE ON SCHEMA public TO schlass_app;
EOSQL
