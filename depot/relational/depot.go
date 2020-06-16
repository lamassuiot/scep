package relational

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	_ "github.com/lib/pq"
	"github.com/micromdm/scep/secrets"
)

type relationalDB struct {
	db      *sql.DB
	dirPath string
	secrets secrets.Secrets
}

type file struct {
	Info os.FileInfo
	Data []byte
}

const (
	rsaPrivateKeyPEMBlockType = "RSA PRIVATE KEY"
	certificatePEMBlockType   = "CERTIFICATE"
)

func NewRelationalDepot(driverName string, dataSourceName string, secrets secrets.Secrets) (*relationalDB, error) {
	db, err := sql.Open(driverName, dataSourceName)
	if err != nil {
		return nil, err
	}
	err = checkDBAlive(db)
	for err != nil {
		fmt.Println("Trying to connect to DB")
		err = checkDBAlive(db)
	}

	return &relationalDB{db: db, secrets: secrets}, nil
}

func checkDBAlive(db *sql.DB) error {
	sqlStatement := `
	SELECT WHERE 1=0`
	_, err := db.Query(sqlStatement)
	return err
}

func (rlDB *relationalDB) CA(pass []byte) ([]*x509.Certificate, *rsa.PrivateKey, error) {
	err := rlDB.secrets.Login()
	if err != nil {
		return nil, nil, err
	}
	cert, key, err := rlDB.secrets.GetSecret("ca")
	if err != nil {
		return nil, nil, err
	}
	return []*x509.Certificate{cert}, key, nil
}

func (rlDB *relationalDB) Put(cn string, crt *x509.Certificate) error {
	if crt == nil {
		return errors.New("crt is nil")
	}
	if crt.Raw == nil {
		return errors.New("data is nil")
	}
	if _, err := rlDB.HasCN(cn, 0, crt, true); err != nil {
		return err
	}

	data := crt.Raw
	dn := makeDn(crt)
	expirationDate := makeOpenSSLTime(crt.NotAfter)
	name := rlDB.path(cn) + "." + crt.SerialNumber.String() + ".pem"

	sqlStatement := `

	INSERT INTO ca_store(status, expirationDate, revocationDate, serial, dn, certPath)
	VALUES($1, $2, $3, $4, $5, $6)
	RETURNING serial;
	`
	serial := 0

	err := rlDB.db.QueryRow(sqlStatement, "V", expirationDate, "", crt.SerialNumber.Int64(), dn, name).Scan(&serial)

	if err != nil {
		return err
	}

	file, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0444)
	if err != nil {
		return err
	}
	defer file.Close()

	if _, err := file.Write(pemCert(data)); err != nil {
		os.Remove(name)
		return err
	}

	return nil
}

func (rlDB *relationalDB) Serial() (*big.Int, error) {
	var serial int64

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
		fmt.Println(err)
		return big.NewInt(2), nil
	}

	s := big.NewInt(serial)
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
		serial         *big.Int
		dn             string
		certPath       string
	}

	rows, err := rlDB.db.Query(sqlStatement, dn)
	if err != nil {
		return false, err
	}
	defer rows.Close()

	for rows.Next() {
		var caItem caItem
		var serial int64
		err := rows.Scan(&caItem.status, &caItem.expirationDate, &caItem.revocationDate, &serial, &caItem.dn, &caItem.certPath)
		if err != nil {
			return false, err
		}
		caItem.serial = big.NewInt(serial)
		if caItem.status == "V" {
			issueDate, err := strconv.ParseInt(strings.Replace(caItem.expirationDate, "Z", "", 1), 10, 64)
			if err != nil {
				return false, errors.New("Could not get expiry date from ca db")
			}
			minimalRenewDate, err := strconv.ParseInt(strings.Replace(makeOpenSSLTime(time.Now().AddDate(0, 0, allowTime).UTC()), "Z", "", 1), 10, 64)

			if minimalRenewDate < issueDate && allowTime > 0 {
				return false, errors.New("DN " + dn + " already exists")
			}
			if revokeOldCertificate {
				fmt.Println("Revoking certificate with serial " + strconv.FormatInt(caItem.serial.Int64(), 10) + " from DB. Recreation of CRL needed.")
				err = rlDB.revokeCertificate(caItem.serial, caItem.dn)
				if err != nil {
					return false, err
				}
			}
		}
	}
	return true, nil
}

func (rlDB *relationalDB) revokeCertificate(serial *big.Int, dn string) error {
	sqlStatement := `
	UPDATE ca_store
	SET status = 'R', revocationDate = $1
	WHERE serial = $2 AND dn = $3;
	`

	res, err := rlDB.db.Exec(sqlStatement, makeOpenSSLTime(time.Now()), serial.Int64(), dn)

	if err != nil {
		return err
	}

	rowsAffected, err := res.RowsAffected()

	if err != nil {
		return err
	}

	if rowsAffected <= 0 {
		return errors.New("No rows updated")
	}

	return nil
}

// load an encrypted private key from disk
func loadKey(data []byte, password []byte) (*rsa.PrivateKey, error) {
	pemBlock, _ := pem.Decode(data)
	if pemBlock == nil {
		return nil, errors.New("PEM decode failed")
	}
	if pemBlock.Type != rsaPrivateKeyPEMBlockType {
		return nil, errors.New("unmatched type or headers")
	}

	b, err := x509.DecryptPEMBlock(pemBlock, password)
	if err != nil {
		return nil, err
	}
	return x509.ParsePKCS1PrivateKey(b)
}

// load an encrypted private key from disk
func loadCert(data []byte) (*x509.Certificate, error) {
	pemBlock, _ := pem.Decode(data)
	if pemBlock == nil {
		return nil, errors.New("PEM decode failed")
	}
	if pemBlock.Type != certificatePEMBlockType {
		return nil, errors.New("unmatched type or headers")
	}

	return x509.ParseCertificate(pemBlock.Bytes)
}

func (rlDB *relationalDB) getFile(path string) (*file, error) {
	// Vault KV call

	if err := rlDB.check(path); err != nil {
		return nil, err
	}
	fi, err := os.Stat(rlDB.path(path))
	if err != nil {
		return nil, err
	}
	b, err := ioutil.ReadFile(rlDB.path(path))
	return &file{fi, b}, err
}

func (rlDB *relationalDB) path(name string) string {
	return filepath.Join(rlDB.dirPath, name)
}

func (rlDB *relationalDB) check(path string) error {
	name := rlDB.path(path)
	_, err := os.Stat(name)
	if err != nil {
		return err
	}
	return nil
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
