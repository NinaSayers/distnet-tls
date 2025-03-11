package tlsgen

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/pem"
    "math/big"
    "os"
    "path/filepath"
    "time"
)

// Generar CA raíz (solo una vez)
func GenerateRootCA(commonName string, certPath string, keyPath string) error {
    caPrivKey, _ := rsa.GenerateKey(rand.Reader, 4096)

    caCert := &x509.Certificate{
        SerialNumber: big.NewInt(2024),
        Subject: pkix.Name{
            CommonName: commonName,
        },
        NotBefore:             time.Now(),
        NotAfter:              time.Now().AddDate(10, 0, 0),
        IsCA:                  true,
        KeyUsage:             x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
        BasicConstraintsValid: true,
    }

    caBytes, _ := x509.CreateCertificate(rand.Reader, caCert, caCert, &caPrivKey.PublicKey, caPrivKey)

    // Crear directorios si no existen
    os.MkdirAll(filepath.Dir(certPath), 0700)
    os.MkdirAll(filepath.Dir(keyPath), 0700)

    // Guardar certificado CA
    certFile, _ := os.Create(certPath)
    pem.Encode(certFile, &pem.Block{
        Type:  "CERTIFICATE",
        Bytes: caBytes,
    })
    certFile.Close()

    // Guardar clave CA
    keyFile, _ := os.Create(keyPath)
    pem.Encode(keyFile, &pem.Block{
        Type:  "RSA PRIVATE KEY",
        Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey),
    })
    keyFile.Close()

    return nil
}

// Generar certificado para un servidor/nodo
func GenerateCert(commonName string, ips []string, dnsNames []string, caCertPath string, caKeyPath string, outputDir string) error {
    // Cargar CA
    caCertPEM, _ := os.ReadFile(caCertPath)
    block, _ := pem.Decode(caCertPEM)
    caCert, _ := x509.ParseCertificate(block.Bytes)

    caKeyPEM, _ := os.ReadFile(caKeyPath)
    block, _ = pem.Decode(caKeyPEM)
    caKey, _ := x509.ParsePKCS1PrivateKey(block.Bytes)

    // Generar clave privada
    privKey, _ := rsa.GenerateKey(rand.Reader, 2048)

    // Plantilla de certificado
    cert := &x509.Certificate{
        SerialNumber: big.NewInt(1658),
        Subject: pkix.Name{
            CommonName: commonName,
        },
        NotBefore:    time.Now(),
        NotAfter:     time.Now().AddDate(1, 0, 0),
        KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
        ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
        IPAddresses:  parseIPs(ips),
        DNSNames:     dnsNames,
    }

    certBytes, _ := x509.CreateCertificate(rand.Reader, cert, caCert, &privKey.PublicKey, caKey)

    // Crear directorio de salida
    os.MkdirAll(outputDir, 0700)

    // Guardar certificado
    certFile, _ := os.Create(filepath.Join(outputDir, "server.crt"))
    pem.Encode(certFile, &pem.Block{
        Type:  "CERTIFICATE",
        Bytes: certBytes,
    })
    certFile.Close()

    // Guardar clave
    keyFile, _ := os.Create(filepath.Join(outputDir, "server.key"))
    pem.Encode(keyFile, &pem.Block{
        Type:  "RSA PRIVATE KEY",
        Bytes: x509.MarshalPKCS1PrivateKey(privKey),
    })
    keyFile.Close()

    return nil
}

func parseIPs(ips []string) []net.IP {
    var parsed []net.IP
    for _, ip := range ips {
        parsed = append(parsed, net.ParseIP(ip))
    }
    return parsed
}