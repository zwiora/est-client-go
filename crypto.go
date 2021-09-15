package est

import (
    "bytes"
    "crypto/rand"
    "crypto/rsa"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/pem"
    "errors"

    "github.com/fullsailor/pkcs7"
)

// PKCS7ToPEM converts PKCS7 formatted data to PEM formatted data.
func PKCS7ToPEM(data []byte) ([]byte, error) {

    var d []byte
    prefix := []byte{'-', '-', '-', '-', '-', 'B', 'E', 'G', 'I', 'N'}
    if bytes.HasPrefix(data, prefix) {
        result, _ := pem.Decode([]byte(data))
        d = result.Bytes
    } else {
        d = data
    }

    p7, err := pkcs7.Parse(d)

    if err != nil {
        return nil, err
    }

    var certsPem []byte
    for _, cert := range p7.Certificates {
        block := pem.Block{
            Type: "CERTIFICATE",
            Bytes: cert.Raw,
        }
        certsPem = append(certsPem, pem.EncodeToMemory(&block)...)
    }

    return certsPem, err
}

// CreateCsr generates a key pair, creates a CSR and returns the private key
// and CSR in PEM format.
func CreateCsr(commonName string, country string, state string, city string,
               organization string, organizationalUnit string,
               emailAddress string) ([]byte, []byte, error) {

    priv, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        return nil, nil, err
    }

    template := x509.CertificateRequest{
            Subject: pkix.Name{
                CommonName:         commonName,
                Country:            []string{country},
                Province:           []string{state},
                Locality:           []string{city},
                Organization:       []string{organization},
                OrganizationalUnit: []string{organizationalUnit},
            },
            SignatureAlgorithm: x509.SHA256WithRSA,
            EmailAddresses:     []string{emailAddress},
    }

    random := rand.Reader
    csrBytes, err := x509.CreateCertificateRequest(random, &template, priv)
    if err != nil {
        return nil, nil, err
    }

    block := pem.Block{
        Type: "CERTIFICATE REQUEST",
        Bytes: csrBytes,
    }
    certPem := pem.EncodeToMemory(&block)

    block = pem.Block{
        Type: "RSA PRIVATE KEY",
        Bytes: x509.MarshalPKCS1PrivateKey(priv),
    }
    privPem := pem.EncodeToMemory(&block)

    return privPem, certPem, nil
}

func ParseRsaPrivateKeyFromPemStr(privPEM string) (*rsa.PrivateKey, error) {
    block, _ := pem.Decode([]byte(privPEM))
    if block == nil {
        return nil, errors.New("failed to parse PEM block containing the key")
    }

    priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
    if err != nil {
        return nil, err
    }

    return priv, nil
}

func CreateCsrFromKey(commonName string, country string, state string, city string,
    organization string, organizationalUnit string,
    emailAddress string, privKey string) ([]byte, error) {

    priv, err := ParseRsaPrivateKeyFromPemStr(privKey)
    if err != nil {
        return nil, err
    }

    template := x509.CertificateRequest{
        Subject: pkix.Name{
            CommonName:         commonName,
            Country:            []string{country},
            Province:           []string{state},
            Locality:           []string{city},
            Organization:       []string{organization},
            OrganizationalUnit: []string{organizationalUnit},
        },
        SignatureAlgorithm: x509.SHA256WithRSA,
        EmailAddresses:     []string{emailAddress},
    }

    random := rand.Reader
    csrBytes, err := x509.CreateCertificateRequest(random, &template, priv)
    if err != nil {
        return nil, err
    }

    block := pem.Block{
        Type: "CERTIFICATE REQUEST",
        Bytes: csrBytes,
    }
    certPem := pem.EncodeToMemory(&block)

    return certPem, nil
}
