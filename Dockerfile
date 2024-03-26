FROM postgres:14

# docker is only used for integration testing, so ignoring security is acceptable

ENV POSTGRES_USER postgres
ENV POSTGRES_PASSWORD password

RUN apt-get update && apt-get install -y build-essential \ 
    # && apt-get install -y gcc-multilib \
    && apt-get install -y libpq-dev \
    && apt-get install -y postgresql-server-dev-14 \
    && apt-get upgrade -y

RUN mkdir -p /usr/src/dpdecrypt
COPY . /usr/src/dpdecrypt

RUN cd /usr/src/dpdecrypt && make USE_PGXS=1 install

COPY ./scripts/init.sql /docker-entrypoint-initdb.d/
COPY ./scripts/load_ext.sh /docker-entrypoint-initdb.d/
