package mysql

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
)

func (p *PacketIO) Auth(authData []byte, plugin string) ([]byte, error) {
	switch plugin {
	case "caching_sha2_password":
		authResp := p.ScrambleSHA256Password(authData, p.connConfig.Password)
		return authResp, nil

	case "mysql_old_password":
		if !p.connConfig.AllowNativePasswords {
			return nil, ErrOldPassword
		}
		if len(p.connConfig.Password) == 0 {
			return nil, nil
		}
		// Note: there are edge cases where this should work but doesn't;
		// this is currently "wontfix":
		// https://github.com/go-sql-driver/mysql/issues/184
		authResp := append(ScrambleOldPassword(authData[:8], p.connConfig.Password), 0)
		return authResp, nil

	case "mysql_clear_password":
		if !p.connConfig.AllowCleartextPasswords {
			return nil, ErrCleartextPassword
		}
		// http://dev.mysql.com/doc/refman/5.7/en/cleartext-authentication-plugin.html
		// http://dev.mysql.com/doc/refman/5.7/en/pam-authentication-plugin.html
		return append([]byte(p.connConfig.Password), 0), nil

	case "mysql_native_password":
		if !p.connConfig.AllowNativePasswords {
			return nil, ErrNativePassword
		}
		// https://dev.mysql.com/doc/internals/en/secure-password-authentication.html
		// Native password authentication only need and will need 20-byte challenge.
		authResp := ScramblePassword(authData[:20], []byte(p.connConfig.Password))
		return authResp, nil

	case "sha256_password":
		if len(p.connConfig.Password) == 0 {
			return []byte{0}, nil
		}
		// unlike caching_sha2_password, sha256_password does not accept
		// cleartext password on unix transport.
		if p.connConfig.EnableTls {
			// write cleartext auth packet
			return append([]byte(p.connConfig.Password), 0), nil
		}

		pubKey := p.connConfig.Pubkey
		if pubKey == nil {
			// request public key from server
			return []byte{1}, nil
		}

		// encrypted password
		enc, err := EncryptPassword(p.connConfig.Password, authData, pubKey)
		return enc, err

	default:
		ErrLog.Print("unknown auth plugin:", plugin)
		return nil, ErrUnknownPlugin
	}
}

// ScrambleSHA256Password Hash password using MySQL 8+ method (SHA256)
func (p *PacketIO) ScrambleSHA256Password(scramble []byte, password string) []byte {
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

// ScrambleOldPassword Hash password using insecure pre 4.1 method
func ScrambleOldPassword(scramble []byte, password string) []byte {
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

func EncryptPassword(password string, seed []byte, pub *rsa.PublicKey) ([]byte, error) {
	plain := make([]byte, len(password)+1)
	copy(plain, password)
	for i := range plain {
		j := i % len(seed)
		plain[i] ^= seed[j]
	}
	sha1 := sha1.New()
	return rsa.EncryptOAEP(sha1, rand.Reader, pub, plain, nil)
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
