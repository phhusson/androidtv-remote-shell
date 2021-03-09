package main

import (
    "crypto/tls"
    "crypto/x509"
    "encoding/binary"
    "fmt"
    "log"
)

func send(conn *tls.Conn, cmdId byte, buf []byte) {
    header := make([]byte, 4)
    header[0] = 1
    header[1] = cmdId
    binary.BigEndian.PutUint16(header[2:], uint16(len(buf)))

    packet := append(header, buf...)
    fmt.Println("Writing packet ", len(packet))
    conn.Write(packet)
}

func readString(buf []byte) []byte {
    if buf[0] == 1 {
        fmt.Println("Empty string")
        return buf[1:]
    } else {
        length := binary.BigEndian.Uint32(buf[1:])
        fmt.Println("Got string ", string(buf[5:5+length]))
        return buf[5+length:]
    }
}

func recv(conn *tls.Conn) {
    header := make([]byte, 4)
    conn.Read(header)
    version := header[0]
    cmdid := header[1]

    length := binary.BigEndian.Uint16(header[2:])
    var buf []byte
    if length > 0 {
        buf = make([]byte, length)
        conn.Read(buf)
    }

    fmt.Println("Received command", cmdid, " of length ", length, "version ", version)
    // Configure succeeded
    if cmdid == 7 {
        controllerNumber := binary.BigEndian.Uint32(buf)
        fmt.Println("Received configure succeeded ", controllerNumber)
        var pos []byte
        pos = readString(buf[4:]) // hash
        pos = readString(pos) // fingerprint
        pos = readString(pos) // id
        pos = readString(pos) // manufacturer
        pos = readString(pos) // model

        sdkInt := binary.BigEndian.Uint32(pos)
        fmt.Println("   sdk ", sdkInt)
    }
}

func configure(conn *tls.Conn, width int, height int, nPointers int, inputMode int) {
    packet := make([]byte, 12)
    binary.BigEndian.PutUint32(packet[0:], uint32(width))
    binary.BigEndian.PutUint32(packet[4:], uint32(height))
    packet[8] = byte(nPointers)
    packet[9] = byte(inputMode)

    send(conn, 0, packet)
    recv(conn)
}

func sendKeyevent(conn *tls.Conn, keyAction int, keyCode int) {
    packet := make([]byte, 16)
    //Timestamp, ignored
    binary.BigEndian.PutUint64(packet[0:], uint64(0))
    binary.BigEndian.PutUint32(packet[8:], uint32(keyAction))
    binary.BigEndian.PutUint32(packet[12:], uint32(keyCode))

    send(conn, 2, packet)
    recv(conn)
}

func pressKey(conn *tls.Conn, keyCode int) {
    sendKeyevent(conn, 1, keyCode)
    sendKeyevent(conn, 0, keyCode)
}

func sendIntent(conn *tls.Conn, intent string) {
    send(conn, 16, []byte(intent))
}

func main() {
    //TODO: verify servert cert
    customVerify := func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
        for _, rawCert := range rawCerts {
            c, _ := x509.ParseCertificate(rawCert)
            fmt.Println("Received certificate subject = ", c.Subject)
        }
        return nil

    }

    // TODO: Generate keypair and pair if it doesn't exist
    myCert, err := tls.LoadX509KeyPair("cert.pem", "key.pem")
    if err != nil {
        log.Fatal(err)
    }

    conn, err := tls.Dial("tcp",
        fmt.Sprintf("%s:6466", "192.168.1.34"),
        &tls.Config{
            VerifyPeerCertificate: customVerify,
            InsecureSkipVerify: true,
            Certificates: []tls.Certificate{myCert},
        })
    if err != nil {
        panic("Failed to connect " + err.Error())
    }

    recv(conn)
    configure(conn, 1024, 1024, 1, 2)
    // Key 3 = HOME
    pressKey(conn, 3)
    //sendIntent(conn, "android-app://com.android.tv.settings/#Intent;action=android.settings.SETTINGS;end")
}
