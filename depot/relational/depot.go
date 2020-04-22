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
	"time"

	_ "github.com/lib/pq"
)

type relationalDB struct {
	db      *sql.DB
	dirPath string
}

func NewRelationalDepot(driverName string, dataSourceName string, dirPath string) (*relationalDB, error) {
	db, err := sql.Open(driverName, dataSourceName)
	if err != nil {
		return nil, err
	}
	err = checkDBAlive(db)
	for err != nil {
		fmt.Println("Trying to connect to DB")
		err = checkDBAlive(db)
	}

	return &relationalDB{db: db, dirPath: dirPath}, nil
}

func checkDBAlive(db *sql.DB) error {
	sqlStatement := `
	SELECT WHERE 1=0`
	_, err := db.Query(sqlStatement)
	return err
}

func (rlDB *relationalDB) CA(pass []byte) ([]*x509.Certificate, *rsa.PrivateKey, error) {
	caPEM, err := rlDB.getFile("ca.pem")
	if err != nil {
		return nil, nil, err
	}
	cert, err := loadCert(caPEM.Data)
	if err != nil {
		return nil, nil, err
	}
	keyPEM, err := rlDB.getFile("ca.key")
	if err != nil {
		return nil, nil, err
	}
	key, err := loadKey(keyPEM.Data, pass)
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

	data := crt.Raw
	cert := pemCert(data)
	dn := makeDn(crt)
	expirationDate := makeOpenSSLTime(crt.NotAfter)

	sqlStatement := `

	INSERT INTO ca_store(status, expirationDate, revocationDate, serial, dn, cert)
	VALUES($1, $2, $3, $4, $5);
	`
	err := rlDB.QueryRow(sqlStatement, expirationDate, nil, dn, crt.SerialNumber, string(cert))
	i
	
	f err != nil {
		return err
	}
	return nil
}

func (rlDB *relationalDB) Serial() (*big.Int, error) {
	s := big.NewInt(2)

	sqlStatement := `
	SELECT serial
	FROM ca_store
	ORDER BY serial DESC
	LIMIT 1;
	`
	row := rlDB.QueryRow(sqlStatement)
	err := row.Scan(&s)

	if err != nil {
		nil, err
	}

	return s, err
}

func (rlDB *relationalDB) HasCN(cn string, allowTime int, cert *x509.Certificate, revokeOldCertificate bool) (bool, error) {
	dn := makeDn(cert)

	sqlStatement := `
	SELECT *
	FROM ca_store
	WHERE dn = $1
	`

	type caItem struct {
		status string
		expirationDate string
		revocationDate string
		serial *big.Int
		dn string
		cert string
	}
	
	candidates := make(map[string]string)
	rows, err := rlDB.Query(sqlStatement, dn)
	if err != nil {
		nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var caItem caItem
		err := rows.Scan(&caItem.status, &caItem.expirationDate, &caItem.revocationDate, &caItem.serial, &caItem.dn, &caItem.cert)
		if caItem.status == "V" {
			issueDate, err := strconv.ParseInt(strings.Replace(caItem.expirationDate, "Z", "", 1), 10, 64)
			if err != nil {
				return false, errors.New("Could not get expiry date from ca db")
			}
			minimalRenewDate, err := strconv.ParseInt(strings.Replace(makeOpenSSLTime(time.Now().AddDate(0, 0, allowTime).UTC()), "Z", "", 1), 10, 64)
			
			if minimalRenewDate < issueDate && allowTime > 0 {
				return false, errors.New("DN " + dn + " already exists")
			} else {
				if revokeOldCertificate {
					rlDB.revokeCertificate(caItem.serial, caItem.dn)
				}
			}	
		}
	}
}

func (rlDB *relationalDB) revokeCertificate(serial *big.Int, dn string) error{
	sqlStatement := `
	UPDATE ca_store
	SET status = "R"
	WHERE serial = $1 AND dn = $2;
	`

	res, err := rlDB.Exec(sqlStatement, serial, dn)

	if err != nil {
		return err
	}

	if res.RowsAffected() <= 0 {
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
