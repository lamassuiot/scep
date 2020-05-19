CREATE TABLE ca_store(
    status CHAR(1),
    expirationDate TEXT,
    revocationDate TEXT,
    serial NUMERIC,
    dn TEXT,
    certPath TEXT
);

\set enroller_scep_password `echo "$ENROLLER_SCEP_PASSWORD"`

CREATE USER enroller_scep WITH PASSWORD :'enroller_scep_password';

GRANT SELECT, UPDATE(status), UPDATE(revocationDate) ON ca_store TO enroller_scep;
