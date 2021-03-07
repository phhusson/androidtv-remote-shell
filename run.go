package main

import (
    "bufio"
    "crypto/rsa"
    "crypto/tls"
    "crypto/x509"
    "crypto/sha256"
    "encoding/base64"
    "encoding/binary"
    "encoding/hex"
    "encoding/json"
    "math/big"
    "math/rand"
    "fmt"
    "log"
    "os"
)

const(
    PAIRING_PHASE_PAIRING_REQUEST = 10
    PAIRING_PHASE_PAIRING_REQUEST_ACK = 11
    // Sent by both side
    PAIRING_PHASE_OPTIONS = 20
    // This is the "merge" of OPTIONS from both client and server to decide one final protocol
    PAIRING_PHASE_CONFIGURE = 30
    PAIRING_PHASE_SECRET = 40
)

func writeJsonSized(conn *tls.Conn, str string) {
    var buf = make([]byte, 4)
    binary.BigEndian.PutUint32(buf, uint32(len(str)))
    buf = append(buf, []byte(str)...)
    conn.Write(buf)
}

func readJsonSized(conn *tls.Conn) string {
    lenbuf := make([]byte, 4)
    conn.Read(lenbuf)
    l := binary.BigEndian.Uint32(lenbuf)
    fmt.Println("Received json of len", l)

    buf := make([]byte, l)
    conn.Read(buf)
    return string(buf)
}

func trimNullBytes(b []byte) []byte {
    var nNullBytes = 0
    for i := 0; b[i] == 0; i++ { nNullBytes++ }
    return b[nNullBytes:]
}

func main() {
    var serverCert *x509.Certificate
    customVerify := func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
        for _, rawCert := range rawCerts {

            c, _ := x509.ParseCertificate(rawCert)
            fmt.Println("Received certificate subject = ", c.Subject)
            serverCert = c
        }
        return nil

    }

    // TODO: Generate keypair if it doesn't exist
    myCert, err := tls.LoadX509KeyPair("cert.pem", "key.pem")
    if err != nil {
        log.Fatal(err)
    }

    pairingConn, err := tls.Dial("tcp",
        fmt.Sprintf("%s:6467", "192.168.1.34"),
        &tls.Config{
            VerifyPeerCertificate: customVerify,
            InsecureSkipVerify: true,
            Certificates: []tls.Certificate{myCert},
        })
    if err != nil {
        panic("Failed to connect " + err.Error())
    }
    var result map[string]interface{}

    writeJsonSized(pairingConn, `{"status":200,"type":10, "payload": {"service_name": "phh", "client_name": "Phh"}}`)
    json.Unmarshal([]byte(readJsonSized(pairingConn)), &result)
    fmt.Println("Got status", result["status"])
    fmt.Println("Got result", result)

    writeJsonSized(pairingConn, `{"status":200,"type":20, "payload": {"input_encodings":[{"type":1,"symbol_length":10}], "output_encodings":[{"type":1,"symbol_length":10}], "preferred_role":1}}`)
    json.Unmarshal([]byte(readJsonSized(pairingConn)), &result)
    fmt.Println("Got status", result["status"])
    fmt.Println("Got result", result)

    writeJsonSized(pairingConn, `{"status":200,"type":30, "payload": {"encoding": {"type":3, "symbol_length":4}, "client_role":1}}`)
    json.Unmarshal([]byte(readJsonSized(pairingConn)), &result)
    fmt.Println("Got status", result["status"])
    fmt.Println("Got result", result)

    var code []byte
    if true {
        scanner := bufio.NewScanner(os.Stdin)

        fmt.Println("Code?")
        scanner.Scan()
        codeStr := scanner.Text()
        codeA, err := hex.DecodeString(codeStr)
        if err != nil {
            panic("Failed to connect " + err.Error())
        }
        code = codeA
    } else {
        code = make([]byte, 2)
        code[0] = 0
        code[1] = byte(rand.Intn(255))
    }

    myPubCert, _ := x509.ParseCertificate(myCert.Certificate[0])
    myPubkey, _ := myPubCert.PublicKey.(*rsa.PublicKey)
    otherPubkey, _ := serverCert.PublicKey.(*rsa.PublicKey)

    var a *big.Int = big.NewInt(int64(0))
    a.Abs(myPubkey.N)
    myModulo := trimNullBytes(a.Bytes())
    a.Abs(big.NewInt(int64(myPubkey.E)))
    myExponent := trimNullBytes(a.Bytes())

    a.Abs(otherPubkey.N)
    otherModulo := trimNullBytes(a.Bytes())
    a.Abs(big.NewInt(int64(otherPubkey.E)))
    otherExponent := trimNullBytes(a.Bytes())

    h := sha256.New()
    h.Write(myModulo)
    h.Write(myExponent)
    h.Write(otherModulo)
    h.Write(otherExponent)
    h.Write(code[len(code)/2:])

    fmt.Println("Result hash is: ", hex.EncodeToString(h.Sum(nil)))

    b64 := base64.StdEncoding.EncodeToString(h.Sum(nil))

    req := fmt.Sprintf(`{"status":200,"type":40, "payload": {"secret":"%s"}}`, b64)
    fmt.Println("Request is ", req)
    writeJsonSized(pairingConn, req)

    json.Unmarshal([]byte(readJsonSized(pairingConn)), &result)
    fmt.Println("Got status", result["status"])
    fmt.Println("Got result", result)

    pairingConn.Close()

    status, _ := result["status"].(float64)
    if status == 200 {
        os.Exit(0)
    } else {
        os.Exit(1)
    }

}

