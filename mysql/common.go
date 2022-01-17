package mysql

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"net"
)

type BaseConn struct {
	Pkg *PacketIO

	PkgErr error

	C net.Conn

	Salt []byte

	Capability   uint32
	ConnectionId uint32

	Status uint16

	Charset  string
	Network  string // tcp or unix
	Username string
	Password string

	EnableTls bool // enable tls default false

	Pubkey *rsa.PublicKey
}

func (c *BaseConn) CheckClientAuth(oldAuthData []byte, plugin string) ([]byte, error) {
	//cpPlugin := AuthPlugin8
	if plugin == "" || plugin == AuthPlugin {
		authResp, err := c.Pkg.Auth(c.Salt, plugin)
		if err != nil {
			return nil, err
		} else if !arrayEqual(authResp, oldAuthData) {
			return nil, ErrNativePassword
		} else {
			return authResp, nil
		}
	}
	return c.Pkg.Auth(c.Salt, plugin)
}

// HandleAuthResult handle client auth result
func (c *BaseConn) HandleAuthResult(oldAuthData []byte, plugin string) error {
	// Read Result Packet
	authData, newPlugin, err := c.ReadAuthResult()
	if err != nil {
		return err
	}

	// handle auth plugin switch, if requested
	if newPlugin != "" {
		// If CLIENT_PLUGIN_AUTH capability is not supported, no new cipher is
		// sent and we have to keep using the cipher sent in the init packet.
		if authData == nil {
			authData = oldAuthData
		} else {
			// copy data from read buffer to owned slice
			copy(oldAuthData, authData)
		}

		plugin = newPlugin

		authResp, err := c.Pkg.Auth(authData, plugin)
		if err != nil {
			return err
		}
		if err = c.WriteAuthSwitchPacket(authResp); err != nil {
			return err
		}

		// Read Result Packet
		authData, newPlugin, err = c.ReadAuthResult()
		if err != nil {
			return err
		}

		// Do not allow to change the auth plugin more than once
		if newPlugin != "" {
			return ErrMalformPkt
		}
	}

	switch plugin {

	// https://insidemysql.com/preparing-your-community-connector-for-mysql-8-part-2-sha256/
	case "caching_sha2_password":
		switch len(authData) {
		case 0:
			return nil // auth successful
		case 1:
			switch authData[0] {
			case CachingSha2PasswordFastAuthSuccess:
				if err = c.ReadResultOk(); err == nil {
					return nil // auth successful
				}

			case CachingSha2PasswordPerformFullAuthentication:
				if c.EnableTls || c.Network == "unix" {
					// write cleartext auth packet
					err = c.WriteAuthSwitchPacket(append([]byte(c.Password), 0))
					if err != nil {
						return err
					}
				} else {
					pubKey := c.Pubkey
					if pubKey == nil {
						var err error
						// request public key from server
						data := make([]byte, 4+1)
						if err != nil {
							return err
						}
						data[4] = CachingSha2PasswordRequestPublicKey
						c.WritePacket(data)

						// parse public key
						if data, err = c.readPacket(); err != nil {
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

					// send encrypted password
					err = c.SendEncryptedPassword(oldAuthData, pubKey)
					if err != nil {
						return err
					}
				}
				return c.ReadResultOk()

			default:
				return ErrMalformPkt
			}
		default:
			return ErrMalformPkt
		}

	case "sha256_password":
		switch len(authData) {
		case 0:
			return nil // auth successful
		default:
			block, _ := pem.Decode(authData)
			pub, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				return err
			}

			// send encrypted password
			err = c.SendEncryptedPassword(oldAuthData, pub.(*rsa.PublicKey))
			if err != nil {
				return err
			}
			return c.ReadResultOk()
		}

	default:
		return nil // auth successful
	}

	return err
}

func (c *BaseConn) SendEncryptedPassword(seed []byte, pub *rsa.PublicKey) error {
	enc, err := EncryptPassword(c.Password, seed, pub)
	if err != nil {
		return err
	}
	return c.WriteAuthSwitchPacket(enc)
}

func (c *BaseConn) WriteAuthSwitchPacket(authData []byte) error {
	pktLen := 4 + len(authData)
	data := make([]byte, pktLen)
	// Add the auth data [EOF]
	copy(data[4:], authData)
	return c.WritePacket(data)
}

func (c *BaseConn) readPacket() ([]byte, error) {
	d, err := c.Pkg.ReadPacket()
	c.PkgErr = err
	return d, err
}

func (c *BaseConn) ReadResultOk() error {
	data, err := c.Pkg.ReadPacket()
	if err != nil {
		return err
	}
	if data[0] == OK_HEADER {
		_, err1 := c.HandleOkPacket(data)
		return err1
	}
	return c.HandleErrorPacket(data)
}

func (c *BaseConn) WritePacket(data []byte) error {
	err := c.Pkg.WritePacket(data)
	c.PkgErr = err
	return err
}

func (c *BaseConn) ReadAuthResult() ([]byte, string, error) {
	data, err := c.Pkg.ReadPacket()
	if err != nil {
		return nil, "", err
	}

	// packet indicator
	switch data[0] {

	case OK_HEADER:
		_, err = c.HandleOkPacket(data)
		return nil, "", err

	case OK_AUTH_MORE:
		return data[1:], "", err

	case EOF_HEADER:
		if len(data) == 1 {
			// https://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::OldAuthSwitchRequest
			return nil, "mysql_old_password", nil
		}
		pluginEndIndex := bytes.IndexByte(data, 0x00)
		if pluginEndIndex < 0 {
			return nil, "", ErrMalformPkt
		}
		plugin := string(data[1:pluginEndIndex])
		authData := data[pluginEndIndex+1:]
		return authData, plugin, nil

	default: // Error otherwise
		return nil, "", c.HandleErrorPacket(data)
	}
}

func (c *BaseConn) HandleOkPacket(data []byte) (*Result, error) {
	var n int
	var pos = 1

	r := new(Result)

	r.AffectedRows, _, n = LengthEncodedInt(data[pos:])
	pos += n
	r.InsertId, _, n = LengthEncodedInt(data[pos:])
	pos += n

	if c.Capability&CLIENT_PROTOCOL_41 > 0 {
		r.Status = binary.LittleEndian.Uint16(data[pos:])
		c.Status = r.Status
		pos += 2

		//todo:strict_mode, check warnings as error
		//Warnings := binary.LittleEndian.Uint16(data[pos:])
		//pos += 2
	} else if c.Capability&CLIENT_TRANSACTIONS > 0 {
		r.Status = binary.LittleEndian.Uint16(data[pos:])
		c.Status = r.Status
		pos += 2
	}

	//info
	return r, nil
}

func (c *BaseConn) HandleErrorPacket(data []byte) error {
	e := new(SqlError)

	var pos int = 1

	e.Code = binary.LittleEndian.Uint16(data[pos:])
	pos += 2

	if c.Capability&CLIENT_PROTOCOL_41 > 0 {
		//skip '#'
		pos++
		e.State = string(data[pos : pos+5])
		pos += 5
	}

	e.Message = string(data[pos:])

	return e
}

func arrayEqual(s, v []byte) bool {
	if len(s) != len(v) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] != v[i] {
			return false
		}
	}
	return true
}
