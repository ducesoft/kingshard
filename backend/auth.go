// Go MySQL Driver - A MySQL-Driver for Go's database/sql package
//
// Copyright 2018 The Go-MySQL-Driver Authors. All rights reserved.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this file,
// You can obtain one at http://mozilla.org/MPL/2.0/.

package backend

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/flike/kingshard/mysql"
	"sync"
)

// server pub keys registry
var (
	serverPubKeyLock     sync.RWMutex
	serverPubKeyRegistry map[string]*rsa.PublicKey
)

// RegisterServerPubKey registers a server RSA public key which can be used to
// send data in a secure manner to the server without receiving the public key
// in a potentially insecure way from the server first.
// Registered keys can afterwards be used adding serverPubKey=<name> to the DSN.
//
// Note: The provided rsa.PublicKey instance is exclusively owned by the driver
// after registering it and may not be modified.
//
//  data, err := ioutil.ReadFile("mykey.pem")
//  if err != nil {
//  	log.Fatal(err)
//  }
//
//  block, _ := pem.Decode(data)
//  if block == nil || block.Type != "PUBLIC KEY" {
//  	log.Fatal("failed to decode PEM block containing public key")
//  }
//
//  pub, err := x509.ParsePKIXPublicKey(block.Bytes)
//  if err != nil {
//  	log.Fatal(err)
//  }
//
//  if rsaPubKey, ok := pub.(*rsa.PublicKey); ok {
//  	mysql.RegisterServerPubKey("mykey", rsaPubKey)
//  } else {
//  	log.Fatal("not a RSA public key")
//  }
//
func RegisterServerPubKey(name string, pubKey *rsa.PublicKey) {
	serverPubKeyLock.Lock()
	if serverPubKeyRegistry == nil {
		serverPubKeyRegistry = make(map[string]*rsa.PublicKey)
	}

	serverPubKeyRegistry[name] = pubKey
	serverPubKeyLock.Unlock()
}

// DeregisterServerPubKey removes the public key registered with the given name.
func DeregisterServerPubKey(name string) {
	serverPubKeyLock.Lock()
	if serverPubKeyRegistry != nil {
		delete(serverPubKeyRegistry, name)
	}
	serverPubKeyLock.Unlock()
}

func getServerPubKey(name string) (pubKey *rsa.PublicKey) {
	serverPubKeyLock.RLock()
	if v, ok := serverPubKeyRegistry[name]; ok {
		pubKey = v
	}
	serverPubKeyLock.RUnlock()
	return
}

// Hash password using pre 4.1 (old password) method
// https://github.com/atcurtis/mariadb/blob/master/mysys/my_rnd.c
type myRnd struct {
	seed1, seed2 uint32
}

const myRndMaxVal = 0x3FFFFFFF

// Pseudo random number generator
func newMyRnd(seed1, seed2 uint32) *myRnd {
	return &myRnd{
		seed1: seed1 % myRndMaxVal,
		seed2: seed2 % myRndMaxVal,
	}
}

// Tested to be equivalent to MariaDB's floating point variant
// http://play.golang.org/p/QHvhd4qved
// http://play.golang.org/p/RG0q4ElWDx
func (r *myRnd) NextByte() byte {
	r.seed1 = (r.seed1*3 + r.seed2) % myRndMaxVal
	r.seed2 = (r.seed1 + r.seed2 + 33) % myRndMaxVal

	return byte(uint64(r.seed1) * 31 / myRndMaxVal)
}

// Generate binary hash from byte string using insecure pre 4.1 method
func pwHash(password []byte) (result [2]uint32) {
	var add uint32 = 7
	var tmp uint32

	result[0] = 1345345333
	result[1] = 0x12345671

	for _, c := range password {
		// skip spaces and tabs in password
		if c == ' ' || c == '\t' {
			continue
		}

		tmp = uint32(c)
		result[0] ^= (((result[0] & 63) + add) * tmp) + (result[0] << 8)
		result[1] += (result[1] << 8) ^ result[0]
		add += tmp
	}

	// Remove sign bit (1<<31)-1)
	result[0] &= 0x7FFFFFFF
	result[1] &= 0x7FFFFFFF

	return
}

// Hash password using insecure pre 4.1 method
func scrambleOldPassword(scramble []byte, password string) []byte {
	scramble = scramble[:8]

	hashPw := pwHash([]byte(password))
	hashSc := pwHash(scramble)

	r := newMyRnd(hashPw[0]^hashSc[0], hashPw[1]^hashSc[1])

	var out [8]byte
	for i := range out {
		out[i] = r.NextByte() + 64
	}

	mask := r.NextByte()
	for i := range out {
		out[i] ^= mask
	}

	return out[:]
}

// Hash password using MySQL 8+ method (SHA256)
func scrambleSHA256Password(scramble []byte, password string) []byte {
	if len(password) == 0 {
		return nil
	}

	// XOR(SHA256(password), SHA256(SHA256(SHA256(password)), scramble))

	crypt := sha256.New()
	crypt.Write([]byte(password))
	message1 := crypt.Sum(nil)

	crypt.Reset()
	crypt.Write(message1)
	message1Hash := crypt.Sum(nil)

	crypt.Reset()
	crypt.Write(message1Hash)
	crypt.Write(scramble)
	message2 := crypt.Sum(nil)

	for i := range message1 {
		message1[i] ^= message2[i]
	}

	return message1
}

func encryptPassword(password string, seed []byte, pub *rsa.PublicKey) ([]byte, error) {
	plain := make([]byte, len(password)+1)
	copy(plain, password)
	for i := range plain {
		j := i % len(seed)
		plain[i] ^= seed[j]
	}
	sha1 := sha1.New()
	return rsa.EncryptOAEP(sha1, rand.Reader, pub, plain, nil)
}

func (c *Conn) sendEncryptedPassword(seed []byte, pub *rsa.PublicKey) error {
	enc, err := encryptPassword(c.password, seed, pub)
	if err != nil {
		return err
	}
	return c.writeAuthSwitchPacket(enc)
}

func (c *Conn) auth(authData []byte, plugin string) ([]byte, error) {
	switch plugin {
	case "caching_sha2_password":
		authResp := scrambleSHA256Password(authData, c.password)
		return authResp, nil

	case "mysql_old_password":
		if !c.allowOldPasswords {
			return nil, mysql.ErrOldPassword
		}
		if len(c.password) == 0 {
			return nil, nil
		}
		// Note: there are edge cases where this should work but doesn't;
		// this is currently "wontfix":
		// https://github.com/go-sql-driver/mysql/issues/184
		authResp := append(scrambleOldPassword(authData[:8], c.password), 0)
		return authResp, nil

	case "mysql_clear_password":
		if !c.allowCleartextPasswords {
			return nil, mysql.ErrCleartextPassword
		}
		// http://dev.mysql.com/doc/refman/5.7/en/cleartext-authentication-plugin.html
		// http://dev.mysql.com/doc/refman/5.7/en/pam-authentication-plugin.html
		return append([]byte(c.password), 0), nil

	case "mysql_native_password":
		/*if !mc.cfg.AllowNativePasswords {
			return nil, ErrNativePassword
		}*/
		// https://dev.mysql.com/doc/internals/en/secure-password-authentication.html
		// Native password authentication only need and will need 20-byte challenge.
		authResp := mysql.ScramblePassword(authData[:20], []byte(c.password))
		return authResp, nil

	case "sha256_password":
		if len(c.password) == 0 {
			return []byte{0}, nil
		}
		// unlike caching_sha2_password, sha256_password does not accept
		// cleartext password on unix transport.
		if c.tls != nil {
			// write cleartext auth packet
			return append([]byte(c.password), 0), nil
		}

		pubKey := c.pubkey
		if pubKey == nil {
			// request public key from server
			return []byte{1}, nil
		}

		// encrypted password
		enc, err := encryptPassword(c.password, authData, pubKey)
		return enc, err

	default:
		mysql.ErrLog.Print("unknown auth plugin:", plugin)
		return nil, mysql.ErrUnknownPlugin
	}
}

func (mc *Conn) readAuthResult() ([]byte, string, error) {
	data, err := mc.readPacket()
	if err != nil {
		return nil, "", err
	}

	// packet indicator
	switch data[0] {

	case mysql.OK_HEADER:
		_, err = mc.handleOKPacket(data)
		return nil, "", err

	case mysql.OK_AUTH_MORE:
		return data[1:], "", err

	case mysql.EOF_HEADER:
		if len(data) == 1 {
			// https://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::OldAuthSwitchRequest
			return nil, "mysql_old_password", nil
		}
		pluginEndIndex := bytes.IndexByte(data, 0x00)
		if pluginEndIndex < 0 {
			return nil, "", mysql.ErrMalformPkt
		}
		plugin := string(data[1:pluginEndIndex])
		authData := data[pluginEndIndex+1:]
		return authData, plugin, nil

	default: // Error otherwise
		return nil, "", mc.handleErrorPacket(data)
	}
}

func (c *Conn) handleAuthResult(oldAuthData []byte, plugin string) error {
	// Read Result Packet
	authData, newPlugin, err := c.readAuthResult()
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

		authResp, err := c.auth(authData, plugin)
		if err != nil {
			return err
		}
		if err = c.writeAuthSwitchPacket(authResp); err != nil {
			return err
		}

		// Read Result Packet
		authData, newPlugin, err = c.readAuthResult()
		if err != nil {
			return err
		}

		// Do not allow to change the auth plugin more than once
		if newPlugin != "" {
			return mysql.ErrMalformPkt
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
			case mysql.CachingSha2PasswordFastAuthSuccess:
				if err = c.readResultOk(); err == nil {
					return nil // auth successful
				}

			case mysql.CachingSha2PasswordPerformFullAuthentication:
				if c.tls != nil || c.network == "unix" {
					// write cleartext auth packet
					err = c.writeAuthSwitchPacket(append([]byte(c.password), 0))
					if err != nil {
						return err
					}
				} else {
					pubKey := c.pubkey
					if pubKey == nil {
						var err error
						// request public key from server
						data := make([]byte, 4+1)
						if err != nil {
							return err
						}
						data[4] = mysql.CachingSha2PasswordRequestPublicKey
						c.writePacket(data)

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
					err = c.sendEncryptedPassword(oldAuthData, pubKey)
					if err != nil {
						return err
					}
				}
				return c.readResultOk()

			default:
				return mysql.ErrMalformPkt
			}
		default:
			return mysql.ErrMalformPkt
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
			err = c.sendEncryptedPassword(oldAuthData, pub.(*rsa.PublicKey))
			if err != nil {
				return err
			}
			return c.readResultOk()
		}

	default:
		return nil // auth successful
	}

	return err
}
