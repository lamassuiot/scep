CREATE TABLE ca_store (
    status CHAR(1),
    expirationDate TEXT,
    revocationDate TEXT,
    serial TEXT,
    dn TEXT,
    certPath TEXT,
    key TEXT,
    keySize INTEGER
);