// Copyright 2016 The kingshard Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"): you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations
// under the License.

package backend

import (
	"bytes"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/flike/kingshard/mysql"
)

var (
	pingPeriod = int64(time.Second * 16)
)

//proxy <-> mysql server
type Conn struct {
	mysql.BaseConn

	addr string
	db   string

	collation mysql.CollationId
	charset   string
	salt      []byte

	pushTimestamp int64

	allowAllFiles           bool // Allow all files to be used with LOAD DATA LOCAL INFILE
	allowCleartextPasswords bool // Allows the cleartext client side plugin
	allowNativePasswords    bool // Allows the native password authentication method
	allowOldPasswords       bool // Allows the old insecure password method
	checkConnLiveness       bool // Check connections for liveness before using them
	clientFoundRows         bool // Return number of matching rows instead of rows changed
	columnsWithAlias        bool // Prepend table alias to column names
	interpolateParams       bool // Interpolate placeholders into query string
	maxAllowedPacket        int
	maxWriteSize            int
	multiStatements         bool        // Allow multiple statements in one query
	parseTime               bool        // Parse time values to time.Time
	rejectReadOnly          bool        // Reject read-only connections
	tls                     *tls.Config // TLS configuration
	tlsConfig               string      // TLS configuration name default preferred
}

func (c *Conn) Connect(addr string, user string, password string, db string) error {
	c.addr = addr
	c.Username = user
	c.Password = password
	c.db = db

	//use utf8
	c.collation = mysql.DEFAULT_COLLATION_ID
	c.charset = mysql.DEFAULT_CHARSET

	return c.ReConnect()
}

func (c *Conn) ReConnect() error {
	if c.C != nil {
		c.C.Close()
	}

	n := "tcp"
	if strings.Contains(c.addr, "/") {
		n = "unix"
	}

	netConn, err := net.Dial(n, c.addr)
	if err != nil {
		return err
	}

	c.Network = n
	tcpConn := netConn.(*net.TCPConn)

	//SetNoDelay controls whether the operating system should delay packet transmission
	// in hopes of sending fewer packets (Nagle's algorithm).
	// The default is true (no delay),
	// meaning that data is sent as soon as possible after a Write.
	//I set this option false.
	tcpConn.SetNoDelay(false)
	tcpConn.SetKeepAlive(true)
	c.C = tcpConn

	// copy config
	connConfig := &mysql.ConnConfig{
		Username:                c.Username,
		Password:                c.Password,
		Pubkey:                  c.Pubkey,
		AllowAllFiles:           c.allowAllFiles,
		AllowCleartextPasswords: c.allowCleartextPasswords,
		AllowNativePasswords:    c.allowNativePasswords,
		AllowOldPasswords:       c.allowOldPasswords,
		EnableTls:               c.EnableTls,
		Tls:                     c.tls,
		TlsConfig:               c.tlsConfig,
	}
	c.Pkg = mysql.NewPacketIO(tcpConn, connConfig)

	authData, plugin, err := c.readInitialHandshake()
	c.salt = authData
	if err != nil {
		c.C.Close()
		return err
	}

	// set default
	if plugin == "" {
		plugin = mysql.AuthPlugin
	}

	// Send Client Authentication Packet
	authResp, err := c.Pkg.Auth(authData, plugin)
	if err != nil {
		// try the default auth plugin, if using the requested plugin failed
		mysql.ErrLog.Print("could not use requested auth plugin '"+plugin+"': ", err.Error())
		plugin = mysql.AuthPlugin
		authResp, err = c.Pkg.Auth(authData, plugin)
		if err != nil {
			c.C.Close()
			return err
		}
	}

	if err = c.writeAuthHandshake(authResp, plugin); err != nil {
		c.C.Close()
		return err
	}
	if err = c.HandleAuthResult(authData, plugin); err != nil {
		c.C.Close()
		return err
	}

	//we must always use autocommit
	if !c.IsAutoCommit() {
		if _, err := c.exec("set autocommit = 1"); err != nil {
			c.C.Close()
			return err
		}
	}

	return nil
}

func (c *Conn) Close() error {
	if c.C != nil {
		c.C.Close()
		c.C = nil
		c.salt = nil
		c.PkgErr = nil
	}

	return nil
}

func (c *Conn) readPacket() ([]byte, error) {
	d, err := c.Pkg.ReadPacket()
	c.PkgErr = err
	return d, err
}

func (c *Conn) writePacket(data []byte) error {
	err := c.Pkg.WritePacket(data)
	c.PkgErr = err
	return err
}

func (c *Conn) readInitialHandshake() (data []byte, plugin string, err error) {
	data, err = c.readPacket()
	if err != nil {
		return
	}

	if data[0] == mysql.ERR_HEADER {
		return nil, "", mysql.ErrReadInitHandshake
	}

	if data[0] < mysql.MinProtocolVersion {
		return nil, "", fmt.Errorf("invalid protocol version %d, must >= 10", data[0])
	}

	//skip mysql version and connection id
	//mysql version end with 0x00
	//connection id length is 4
	pos := 1 + bytes.IndexByte(data[1:], 0x00) + 1 + 4

	authData := data[pos : pos+8]

	//skip filter
	pos += 8 + 1

	//capability lower 2 bytes
	c.Capability = uint32(binary.LittleEndian.Uint16(data[pos : pos+2]))
	if c.Capability&mysql.CLIENT_PROTOCOL_41 == 0 {
		return nil, "", mysql.ErrOldProtocol
	}

	if c.Capability&mysql.CLIENT_SSL == 0 && c.tls != nil {
		if c.tlsConfig == "preferred" {
			c.tls = nil
		} else {
			return nil, "", mysql.ErrNoTLS
		}
	}

	pos += 2

	if len(data) > pos {
		//skip server charset
		//c.charset = data[pos]
		pos += 1

		c.Status = binary.LittleEndian.Uint16(data[pos : pos+2])
		pos += 2

		c.Capability = uint32(binary.LittleEndian.Uint16(data[pos:pos+2]))<<16 | c.Capability

		pos += 2

		//skip auth data len or [00]
		//skip reserved (all [00])
		pos += 10 + 1

		// The documentation is ambiguous about the length.
		// The official Python library uses the fixed length 12
		// mysql-proxy also use 12
		// which is not documented but seems to work.
		authData = append(authData, data[pos:pos+12]...)
		pos += 13

		// EOF if version (>= 5.5.7 and < 5.5.10) or (>= 5.6.0 and < 5.6.2)
		// \NUL otherwise
		if end := bytes.IndexByte(data[pos:], 0x00); end != -1 {
			plugin = string(data[pos : pos+end])
		} else {
			plugin = string(data[pos:])
		}

		// make a memory safe copy of the cipher slice
		var b [20]byte
		copy(b[:], authData)
		return b[:], plugin, nil
	}

	// make a memory safe copy of the cipher slice
	var b [8]byte
	copy(b[:], authData)
	return b[:], plugin, nil
}

func (c *Conn) writeAuthHandshake(authResp []byte, plugin string) error {
	// Adjust client capability flags based on server support
	capability := mysql.CLIENT_PROTOCOL_41 | mysql.CLIENT_SECURE_CONNECTION |
		mysql.CLIENT_LONG_PASSWORD | mysql.CLIENT_TRANSACTIONS | mysql.CLIENT_LOCAL_FILES |
		mysql.CLIENT_PLUGIN_AUTH | mysql.CLIENT_MULTI_RESULTS | c.Capability&mysql.CLIENT_LONG_FLAG
	/*capability := mysql.CLIENT_PROTOCOL_41 | mysql.CLIENT_SECURE_CONNECTION |
	mysql.CLIENT_LONG_PASSWORD | mysql.CLIENT_TRANSACTIONS | mysql.CLIENT_LONG_FLAG*/
	capability &= c.Capability

	//packet length
	//capbility 4
	//max-packet size 4
	//charset 1
	//reserved all[0] 23
	//username

	if c.clientFoundRows {
		capability |= mysql.CLIENT_FOUND_ROWS
	}

	if c.EnableTls {
		capability |= mysql.CLIENT_SSL
	}

	if c.multiStatements {
		capability |= mysql.CLIENT_MULTI_STATEMENTS
	}

	var authRespLEIBuf [9]byte
	authRespLEI := mysql.AppendLengthEncodedInteger(authRespLEIBuf[:0], uint64(len(authResp)))
	if len(authRespLEI) > 1 {
		// if the length can not be written in 1 byte, it must be written as a
		// length encoded integer
		capability |= mysql.CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA
	}

	pktLen := 4 + 4 + 1 + 23 + len(c.Username) + 1 + len(authRespLEI) + len(authResp) + 21 + 1

	if n := len(c.db); n > 0 {
		capability |= mysql.CLIENT_CONNECT_WITH_DB
		pktLen += n + 1
	}

	c.Capability = capability
	data := make([]byte, pktLen+4)

	//capability [32 bit]
	data[4] = byte(capability)
	data[5] = byte(capability >> 8)
	data[6] = byte(capability >> 16)
	data[7] = byte(capability >> 24)

	//MaxPacketSize [32 bit] (none)
	data[8] = 0x00
	data[9] = 0x00
	data[10] = 0x00
	data[11] = 0x00

	// Charset [1 byte]
	data[12] = byte(c.collation)
	found := mysql.Collations[c.collation] != ""
	if !found {
		// Note possibility for false negatives:
		// could be triggered  although the collation is valid if the
		// collations map does not contain entries the server supports.
		return mysql.ErrUnknownCollation
	}

	// Filler [23 bytes] (all 0x00)
	pos := 13
	for ; pos < 13+23; pos++ {
		data[pos] = 0
	}

	// SSL Connection Request Packet
	// http://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::SSLRequest
	if c.EnableTls {
		// Send TLS / SSL request packet
		if err := c.writePacket(data[:(4+4+1+23)+4]); err != nil {
			return err
		}

		// Switch to TLS
		tlsConn := tls.Client(c.C, c.tls)
		if err := tlsConn.Handshake(); err != nil {
			return err
		}
		c.C = tlsConn
	}

	// User [null terminated string]
	if len(c.Username) > 0 {
		pos += copy(data[pos:], c.Username)
	}
	data[pos] = 0x00
	pos++

	// Auth Data [length encoded integer]
	pos += copy(data[pos:], authRespLEI)
	pos += copy(data[pos:], authResp)

	// Databasename [null terminated string]
	if len(c.db) > 0 {
		pos += copy(data[pos:], c.db)
		data[pos] = 0x00
		pos++
	}

	pos += copy(data[pos:], plugin)
	data[pos] = 0x00
	pos++

	// Send Auth packet
	return c.writePacket(data[:pos])
}

func (c *Conn) writeCommand(command byte) error {
	c.Pkg.Sequence = 0

	return c.writePacket([]byte{
		0x01, //1 bytes long
		0x00,
		0x00,
		0x00, //sequence
		command,
	})
}

func (c *Conn) writeCommandBuf(command byte, arg []byte) error {
	c.Pkg.Sequence = 0

	length := len(arg) + 1

	data := make([]byte, length+4)

	data[4] = command

	copy(data[5:], arg)

	return c.writePacket(data)
}

func (c *Conn) writeCommandStr(command byte, arg string) error {
	c.Pkg.Sequence = 0

	length := len(arg) + 1

	data := make([]byte, length+4)

	data[4] = command

	copy(data[5:], arg)

	return c.writePacket(data)
}

func (c *Conn) writeCommandUint32(command byte, arg uint32) error {
	c.Pkg.Sequence = 0

	return c.writePacket([]byte{
		0x05, //5 bytes long
		0x00,
		0x00,
		0x00, //sequence

		command,

		byte(arg),
		byte(arg >> 8),
		byte(arg >> 16),
		byte(arg >> 24),
	})
}

func (c *Conn) writeCommandStrStr(command byte, arg1 string, arg2 string) error {
	c.Pkg.Sequence = 0

	data := make([]byte, 4, 6+len(arg1)+len(arg2))

	data = append(data, command)
	data = append(data, arg1...)
	data = append(data, 0)
	data = append(data, arg2...)

	return c.writePacket(data)
}

func (c *Conn) Ping() error {
	if err := c.writeCommand(mysql.COM_PING); err != nil {
		return err
	}

	if _, _, err := c.readOK(); err != nil {
		return err
	}

	c.pushTimestamp = time.Now().Unix()

	return nil
}

func (c *Conn) UseDB(dbName string) error {
	if c.db == dbName || len(dbName) == 0 {
		return nil
	}

	if err := c.writeCommandStr(mysql.COM_INIT_DB, dbName); err != nil {
		return err
	}

	if _, _, err := c.readOK(); err != nil {
		return err
	}

	c.db = dbName
	return nil
}

func (c *Conn) GetDB() string {
	return c.db
}

func (c *Conn) GetAddr() string {
	return c.addr
}

func (c *Conn) Execute(command string, args ...interface{}) (*mysql.Result, error) {
	if len(args) == 0 {
		return c.exec(command)
	} else {
		if s, err := c.Prepare(command); err != nil {
			return nil, err
		} else {
			var r *mysql.Result
			r, err = s.Execute(args...)
			s.Close()
			return r, err
		}
	}
}

func (c *Conn) ClosePrepare(id uint32) error {
	return c.writeCommandUint32(mysql.COM_STMT_CLOSE, id)
}

func (c *Conn) Begin() error {
	_, err := c.exec("begin")
	return err
}

func (c *Conn) Commit() error {
	_, err := c.exec("commit")
	return err
}

func (c *Conn) Rollback() error {
	_, err := c.exec("rollback")
	return err
}

func (c *Conn) SetAutoCommit(n uint8) error {
	if n == 0 {
		if _, err := c.exec("set autocommit = 0"); err != nil {
			c.C.Close()

			return err
		}
	} else {
		if _, err := c.exec("set autocommit = 1"); err != nil {
			c.C.Close()

			return err
		}
	}
	return nil
}

func (c *Conn) SetCharset(charset string, collation mysql.CollationId) error {
	charset = strings.Trim(charset, "\"'`")

	if collation == 0 {
		collation = mysql.CollationNames[mysql.Charsets[charset]]
	}

	if c.charset == charset && c.collation == collation {
		return nil
	}

	_, ok := mysql.CharsetIds[charset]
	if !ok {
		return fmt.Errorf("invalid charset %s", charset)
	}

	_, ok = mysql.Collations[collation]
	if !ok {
		return fmt.Errorf("invalid collation %s", collation)
	}

	if _, err := c.exec(fmt.Sprintf("SET NAMES %s COLLATE %s", charset, mysql.Collations[collation])); err != nil {
		return err
	} else {
		c.collation = collation
		c.charset = charset
		return nil
	}
}

func (c *Conn) FieldList(table string, wildcard string) ([]*mysql.Field, error) {
	if err := c.writeCommandStrStr(mysql.COM_FIELD_LIST, table, wildcard); err != nil {
		return nil, err
	}

	data, err := c.readPacket()
	if err != nil {
		return nil, err
	}

	fs := make([]*mysql.Field, 0, 4)
	var f *mysql.Field
	if data[0] == mysql.ERR_HEADER {
		return nil, c.handleErrorPacket(data)
	} else {
		for {
			if data, err = c.readPacket(); err != nil {
				return nil, err
			}

			// EOF Packet
			if c.isEOFPacket(data) {
				return fs, nil
			}

			if f, err = mysql.FieldData(data).Parse(); err != nil {
				return nil, err
			}
			fs = append(fs, f)
		}
	}
	return nil, fmt.Errorf("field list error")
}

func (c *Conn) exec(query string) (*mysql.Result, error) {
	if err := c.writeCommandStr(mysql.COM_QUERY, query); err != nil {
		return nil, err
	}

	return c.readResult(false)
}

func (c *Conn) readResultset(data []byte, binary bool) (*mysql.Result, error) {
	result := &mysql.Result{
		Status:       0,
		InsertId:     0,
		AffectedRows: 0,

		Resultset: &mysql.Resultset{},
	}

	// column count
	count, _, n := mysql.LengthEncodedInt(data)

	if n-len(data) != 0 {
		return nil, mysql.ErrMalformPacket
	}

	result.Fields = make([]*mysql.Field, count)
	result.FieldNames = make(map[string]int, count)

	if err := c.readResultColumns(result); err != nil {
		return nil, err
	}

	if err := c.readResultRows(result, binary); err != nil {
		return nil, err
	}

	return result, nil
}

func (c *Conn) readResultColumns(result *mysql.Result) (err error) {
	var i int = 0
	var data []byte

	for {
		data, err = c.readPacket()
		if err != nil {
			return
		}

		// EOF Packet
		if c.isEOFPacket(data) {
			if c.Capability&mysql.CLIENT_PROTOCOL_41 > 0 {
				//result.Warnings = binary.LittleEndian.Uint16(data[1:])
				//todo add strict_mode, warning will be treat as error
				result.Status = binary.LittleEndian.Uint16(data[3:])
				c.Status = result.Status
			}

			if i != len(result.Fields) {
				err = mysql.ErrMalformPacket
			}

			return
		}

		result.Fields[i], err = mysql.FieldData(data).Parse()
		if err != nil {
			return
		}

		result.FieldNames[string(result.Fields[i].Name)] = i

		i++
	}
}

func (c *Conn) readResultRows(result *mysql.Result, isBinary bool) (err error) {
	var data []byte

	for {
		data, err = c.readPacket()

		if err != nil {
			return
		}

		// EOF Packet
		if c.isEOFPacket(data) {
			if c.Capability&mysql.CLIENT_PROTOCOL_41 > 0 {
				//result.Warnings = binary.LittleEndian.Uint16(data[1:])
				//todo add strict_mode, warning will be treat as error
				result.Status = binary.LittleEndian.Uint16(data[3:])
				c.Status = result.Status
			}

			break
		}

		result.RowDatas = append(result.RowDatas, data)
	}

	result.Values = make([][]interface{}, len(result.RowDatas))

	for i := range result.Values {
		result.Values[i], err = result.RowDatas[i].Parse(result.Fields, isBinary)

		if err != nil {
			return err
		}
	}

	return nil
}

func (c *Conn) readUntilEOF() (err error) {
	var data []byte

	for {
		data, err = c.readPacket()

		if err != nil {
			return
		}

		// EOF Packet
		if c.isEOFPacket(data) {
			return
		}
	}
	return
}

func (c *Conn) isEOFPacket(data []byte) bool {
	return data[0] == mysql.EOF_HEADER && len(data) <= 5
}

func (c *Conn) handleOKPacket(data []byte) (*mysql.Result, error) {
	var n int
	var pos int = 1

	r := new(mysql.Result)

	r.AffectedRows, _, n = mysql.LengthEncodedInt(data[pos:])
	pos += n
	r.InsertId, _, n = mysql.LengthEncodedInt(data[pos:])
	pos += n

	if c.Capability&mysql.CLIENT_PROTOCOL_41 > 0 {
		r.Status = binary.LittleEndian.Uint16(data[pos:])
		c.Status = r.Status
		pos += 2

		//todo:strict_mode, check warnings as error
		//Warnings := binary.LittleEndian.Uint16(data[pos:])
		//pos += 2
	} else if c.Capability&mysql.CLIENT_TRANSACTIONS > 0 {
		r.Status = binary.LittleEndian.Uint16(data[pos:])
		c.Status = r.Status
		pos += 2
	}

	//info
	return r, nil
}

func (c *Conn) handleErrorPacket(data []byte) error {
	e := new(mysql.SqlError)

	var pos int = 1

	e.Code = binary.LittleEndian.Uint16(data[pos:])
	pos += 2

	if c.Capability&mysql.CLIENT_PROTOCOL_41 > 0 {
		//skip '#'
		pos++
		e.State = string(data[pos : pos+5])
		pos += 5
	}

	e.Message = string(data[pos:])

	return e
}

func (c *Conn) readOK() (string, *mysql.Result, error) {
	data, err := c.readPacket()
	if err != nil {
		return "", nil, err
	}

	if data[0] == mysql.OK_HEADER {
		ret, err := c.handleOKPacket(data)
		return "", ret, err
	} else if data[0] == mysql.OK_AUTH_MORE {
		return "", nil, c.checkAuthResult(data[1:], "caching_sha2_password")
	} else if data[0] == mysql.EOF_HEADER {
		if len(data) == 1 {
			// https://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::OldAuthSwitchRequest
			return "mysql_old_password", nil, nil
		}
		pluginEndIndex := bytes.IndexByte(data, 0x00)
		if pluginEndIndex < 0 {
			return "", nil, mysql.ErrMalformPacket
		}
		plugin := string(data[1:pluginEndIndex])
		authData := data[pluginEndIndex+1:]
		fmt.Printf("authData:%s", authData)
		return plugin, nil, nil
	} else {
		return "", nil, errors.New(string(data))
	}
}

func (c *Conn) checkAuthResult(authData []byte, plugin string) error {
	switch plugin {
	case "caching_sha2_password":
		switch len(authData) {
		case 0:
			return nil
		case 1:
			fmt.Printf("data[0]:%d\n", authData[0])
			switch authData[0] {
			case mysql.CachingSha2PasswordFastAuthSuccess:
				if err := c.ReadResultOk(); err == nil {
					return nil
				}
			case mysql.CachingSha2PasswordPerformFullAuthentication:
				// not support tls
				fmt.Printf("network:%s\n", c.Network)
				if c.Network == "unix" {
					err := c.WriteAuthSwitchPacket(append([]byte(c.Password), 0))
					if err != nil {
						return err
					}
				} else {
					pubKey := c.Pubkey
					if pubKey == nil {
						var err error
						data := make([]byte, 4+1)
						data[4] = mysql.CachingSha2PasswordRequestPublicKey
						c.writePacket(data)

						// parse public key
						data, err = c.readPacket()
						fmt.Printf("data:%s\n", data)
						if err != nil {
							return err
						}
						block, rest := pem.Decode(data[1:])
						if block == nil {
							return fmt.Errorf("No Pem data found, data: %s", rest)
						}
						pkix, err := x509.ParsePKIXPublicKey(block.Bytes)
						if err != nil {
							return err
						}
						pubKey = pkix.(*rsa.PublicKey)
					}
					err := c.SendEncryptedPassword(authData, pubKey)
					if err != nil {
						return err
					}
				}
				return c.ReadResultOk()
			default:
				return errors.New("malformed packet")
			}
			break
		default:
			return errors.New("malformed packet")
		}
	}
	return nil
}

func (c *Conn) readResult(binary bool) (*mysql.Result, error) {
	data, err := c.readPacket()
	if err != nil {
		return nil, err
	}

	if data[0] == mysql.OK_HEADER {
		return c.handleOKPacket(data)
	} else if data[0] == mysql.ERR_HEADER {
		return nil, c.handleErrorPacket(data)
	} else if data[0] == mysql.LocalInFile_HEADER {
		return nil, mysql.ErrMalformPacket
	}

	return c.readResultset(data, binary)
}

func (c *Conn) IsAutoCommit() bool {
	return c.Status&mysql.SERVER_STATUS_AUTOCOMMIT > 0
}

func (c *Conn) IsInTransaction() bool {
	return c.Status&mysql.SERVER_STATUS_IN_TRANS > 0
}

func (c *Conn) GetCharset() string {
	return c.charset
}
