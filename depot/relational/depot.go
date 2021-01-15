package relational

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"

	_ "github.com/lib/pq"
)

type relationalDB struct {
	db      *sql.DB
	dirPath string
	logger  log.Logger
}

type file struct {
	Info os.FileInfo
	Data []byte
}

const (
	rsaPrivateKeyPEMBlockType = "RSA PRIVATE KEY"
	certificatePEMBlockType   = "CERTIFICATE"
)

func NewRelationalDepot(driverName string, dataSourceName string, logger log.Logger) (*relationalDB, error) {
	db, err := sql.Open(driverName, dataSourceName)
	if err != nil {
		return nil, err
	}
	err = checkDBAlive(db)
	for err != nil {
		level.Warn(logger).Log("msg", "Trying to connect to signed certificates database")
		err = checkDBAlive(db)
	}

	return &relationalDB{db: db, logger: logger}, nil
}

func checkDBAlive(db *sql.DB) error {
	sqlStatement := `
	SELECT WHERE 1=0`
	_, err := db.Query(sqlStatement)
	return err
}

func (rlDB *relationalDB) Put(cn string, crt *x509.Certificate) error {
	if crt == nil || crt.Raw == nil {
		err := errors.New("Certificate is empty")
		level.Error(rlDB.logger).Log("err", err)
		return err
	}

	if _, err := rlDB.HasCN(cn, 0, crt, true); err != nil {
		return err
	}
	level.Info(rlDB.logger).Log("msg", "Certificate with CN "+cn+" does not exist in database. Inserting new one.")

	data := crt.Raw
	dn := makeDn(crt)
	expirationDate := makeOpenSSLTime(crt.NotAfter)
	serialHex := fmt.Sprintf("%x", crt.SerialNumber)
	name := rlDB.path(cn) + "." + serialHex + ".pem"

	key := crt.PublicKeyAlgorithm.String()
	var keySize int
	switch key {
	case "RSA":
		keySize = crt.PublicKey.(*rsa.PublicKey).N.BitLen()
	case "ECDSA":
		keySize = crt.PublicKey.(*ecdsa.PublicKey).Params().BitSize
	}

	sqlStatement := `

	INSERT INTO ca_store(status, expirationDate, revocationDate, serial, dn, key, keySize, certPath)
	VALUES($1, $2, $3, $4, $5, $6, $7, $8)
	RETURNING serial;
	`
	var serial string

	err := rlDB.db.QueryRow(sqlStatement, "V", expirationDate, "", serialHex, dn, key, keySize, name).Scan(&serial)

	if err != nil {
		level.Error(rlDB.logger).Log("err", err, "msg", "Could not insert certificate with serial "+serialHex+" and DN "+dn+" in database")
		return err
	}
	level.Info(rlDB.logger).Log("msg", "Certificate with serial "+serial+" and DN "+dn+" inserted in database")

	file, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0444)
	if err != nil {
		level.Error(rlDB.logger).Log("err", err, "msg", "Could not insert certificate with serial "+serialHex+" and DN "+dn+" in file system")
		return err
	}
	defer file.Close()

	if _, err := file.Write(pemCert(data)); err != nil {
		level.Error(rlDB.logger).Log("err", err, "msg", "Could not parse certificate with serial "+serialHex+" and DN "+dn+", removing from file system")
		os.Remove(name)
		return err
	}
	level.Info(rlDB.logger).Log("msg", "Certificate with serial "+serial+" and DN "+dn+" inserted in file system")

	return nil
}

// This function is not used with Vault (Take care because serial is string in database)
func (rlDB *relationalDB) Serial() (*big.Int, error) {
	var serial string

	sqlStatement := `
	SELECT serial
	FROM ca_store
	ORDER BY serial DESC
	LIMIT 1;
	`

	row := rlDB.db.QueryRow(sqlStatement)
	err := row.Scan(&serial)

	//If there are not certificates stored, the serial does not exist, so create new one.
	if err != nil {
		level.Info(rlDB.logger).Log("msg", "Database is empty, starting new serial counter")
		return big.NewInt(2), nil
	}

	s, _ := new(big.Int).SetString(serial, 16)
	s = s.Add(s, big.NewInt(1))

	return s, nil
}

func (rlDB *relationalDB) HasCN(cn string, allowTime int, cert *x509.Certificate, revokeOldCertificate bool) (bool, error) {
	dn := makeDn(cert)

	sqlStatement := `
	SELECT *
	FROM ca_store
	WHERE dn = $1
	`

	type caItem struct {
		status         string
		expirationDate string
		revocationDate string
		serial         string
		dn             string
		certPath       string
		key            string
		keySize        int
	}

	rows, err := rlDB.db.Query(sqlStatement, dn)
	if err != nil {
		level.Error(rlDB.logger).Log("err", err, "msg", "Could not query database to find CN: "+cn+" certificate")
		return false, err
	}
	defer rows.Close()

	for rows.Next() {
		var caItem caItem
		err := rows.Scan(&caItem.status, &caItem.expirationDate, &caItem.revocationDate, &caItem.serial, &caItem.dn, &caItem.certPath, &caItem.key, &caItem.keySize)
		if err != nil {
			level.Error(rlDB.logger).Log("err", err, "msg", "Could not read certificate database row finding certificate with CN: "+cn)
			return false, err
		}
		if caItem.status == "V" {
			issueDate, err := strconv.ParseInt(strings.Replace(caItem.expirationDate, "Z", "", 1), 10, 64)
			if err != nil {
				level.Error(rlDB.logger).Log("err", err, "msg", "Could not get expiry date from certificate with serial "+caItem.serial)
				return false, err
			}
			minimalRenewDate, err := strconv.ParseInt(strings.Replace(makeOpenSSLTime(time.Now().AddDate(0, 0, allowTime).UTC()), "Z", "", 1), 10, 64)

			if minimalRenewDate < issueDate && allowTime > 0 {
				err = errors.New("Certificate with DN " + dn + " already exists")
				level.Error(rlDB.logger).Log("err", err)
				return false, err
			}
			if revokeOldCertificate {
				level.Info(rlDB.logger).Log("msg", "Revoking certificate with serial "+caItem.serial+" from DB. Recreation of CRL needed")
				err = rlDB.revokeCertificate(caItem.serial, caItem.dn)
				if err != nil {
					return false, err
				}
				level.Info(rlDB.logger).Log("msg", "Certificate with serial "+caItem.serial+" succesfully revoked. Recreation of CRL needed")
			}
		}
	}
	return true, nil
}

func (rlDB *relationalDB) revokeCertificate(serial string, dn string) error {
	sqlStatement := `
	UPDATE ca_store
	SET status = 'R', revocationDate = $1
	WHERE serial = $2 AND dn = $3;
	`

	res, err := rlDB.db.Exec(sqlStatement, makeOpenSSLTime(time.Now()), serial, dn)

	if err != nil {
		level.Error(rlDB.logger).Log("err", err, "msg", "Could not revoke certificate with serial "+serial+" and DN "+dn)
		return err
	}

	rowsAffected, err := res.RowsAffected()

	if err != nil {
		level.Error(rlDB.logger).Log("err", err, "msg", "Could not revoke certificate with serial "+serial+" and DN "+dn)
		return err
	}

	if rowsAffected <= 0 {
		err = errors.New("No rows have been updated in database")
		level.Error(rlDB.logger).Log("err", err)
		return err
	}

	return nil
}

func (rlDB *relationalDB) path(name string) string {
	return filepath.Join(rlDB.dirPath, name)
}

func makeDn(cert *x509.Certificate) string {
	var dn bytes.Buffer

	if len(cert.Subject.Country) > 0 && len(cert.Subject.Country[0]) > 0 {
		dn.WriteString("/C=" + cert.Subject.Country[0])
	}
	if len(cert.Subject.Province) > 0 && len(cert.Subject.Province[0]) > 0 {
		dn.WriteString("/ST=" + cert.Subject.Province[0])
	}
	if len(cert.Subject.Locality) > 0 && len(cert.Subject.Locality[0]) > 0 {
		dn.WriteString("/L=" + cert.Subject.Locality[0])
	}
	if len(cert.Subject.Organization) > 0 && len(cert.Subject.Organization[0]) > 0 {
		dn.WriteString("/O=" + cert.Subject.Organization[0])
	}
	if len(cert.Subject.OrganizationalUnit) > 0 && len(cert.Subject.OrganizationalUnit[0]) > 0 {
		dn.WriteString("/OU=" + cert.Subject.OrganizationalUnit[0])
	}
	if len(cert.Subject.CommonName) > 0 {
		dn.WriteString("/CN=" + cert.Subject.CommonName)
	}
	if len(cert.EmailAddresses) > 0 {
		dn.WriteString("/emailAddress=" + cert.EmailAddresses[0])
	}
	return dn.String()
}

func pemCert(derBytes []byte) []byte {
	pemBlock := &pem.Block{
		Type:    certificatePEMBlockType,
		Headers: nil,
		Bytes:   derBytes,
	}
	out := pem.EncodeToMemory(pemBlock)
	return out
}

func makeOpenSSLTime(t time.Time) string {
	y := (int(t.Year()) % 100)
	validDate := fmt.Sprintf("%02d%02d%02d%02d%02d%02dZ", y, t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second())
	return validDate
}
