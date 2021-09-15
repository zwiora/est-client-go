est-client-go
=================

EST client - RFC 7030 - Enrollment over Secure Transport

Authentication via Username/Password

```go
// EST client.  Username and password will be used for basic auth.
// serverCert contains the EST server certificate in PEM format.
client := est.Client{
            URLPrefix: "https://testrfc7030.cisco.com:8443",
            Username: "estuser",
            Password: "estpwd",
            ServerCert: serverCert}

// Get EST server CA certs in PEM format.
caCerts, err := client.CaCerts()

// Create CSR.  CreateCsr returns the CSR and the private key generated
// in PEM format.
commonName := "Test"
country := "FR"
state := "Guadeloupe"
city := "Anse Bananier"
organization := "Relax"
organizationalUnit := "Secret"
emailAddress := "test@example.com"
priv, csr, err := est.CreateCsr(commonName, country, state, city,
                                organization, organizationalUnit,
                                emailAddress)

// Enroll using the CSR.  SimpleEnroll returns the signed cert in PEM format.
cert, err = client.SimpleEnroll(csr)

// Reenroll using the CSR.
cert, err = client.SimpleReenroll(csr, nil, nil)

// Reenroll using the CSR and the client cert/key for authentication.
cert, err = client.SimpleReenroll(csr, cert, priv)
```

Authentication via previously obtained Certificate
```go
keyFile, err1 := os.ReadFile("client_priv.pem")
certFile, err2 := os.ReadFile("client_cert.pem")

if err1 != nil || err2 != nil {
	return errors.New("problem with client_priv.pem and client_cert.pem files. For generating them use port 8443")
}

client, err := setClient("9443", "", "")

if err != nil {
	return err
}

commonName := "Test"
country := "FR"
state := "Guadeloupe"
city := "Anse Bananier"
organization := "Relax"
organizationalUnit := "Secret"
emailAddress := "test@example.com"

csr, err := est.CreateCsrFromKey(commonName, country, state, city,
	organization, organizationalUnit,
	emailAddress, string(keyFile))

if err != nil {
	return err
}

cert, err := client.SimpleEnroll9443(csr, certFile, keyFile)
log.Printf("Using:\n%v", string(certFile))

if err != nil {
	return err
}

log.Println(string(cert))
```

Out of Scope:

  - §3.3.3 - Certificate-less TLS Mutual Authentication.
  - §3.5 - Linking Identity and PoP information.
  - §4.3 - CMC.
  - §4.4 - Server-side key generation.
  - §4.5 - CSR attributes.
