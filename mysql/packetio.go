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

package mysql

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"github.com/flike/kingshard/core/errors"
	"io"
	"net"
)

const (
	defaultReaderSize = 8 * 1024
)

type PacketIO struct {
	rb *bufio.Reader
	wb io.Writer

	Sequence uint8
}

func NewPacketIO(conn net.Conn) *PacketIO {
	p := new(PacketIO)

	p.rb = bufio.NewReaderSize(conn, defaultReaderSize)
	p.wb = conn

	p.Sequence = 0

	return p
}

func (p *PacketIO) readNext(length int) ([]byte, error) {
	data := make([]byte, length)
	_, err := p.rb.Read(data)
	return data, err
}

func (p *PacketIO) ReadPacket() ([]byte, error) {
	var prevData []byte
	for {
		// read packet header
		data, err := p.readNext(4)
		fmt.Printf("data,%d,%d,%d,%d\n", data[0], data[1], data[2], data[3])
		if err != nil {
			data, _ = io.ReadAll(p.rb)
			fmt.Printf("hex:%s\n", hex.EncodeToString(data))
			return nil, ErrBadConn
		}

		// packet length [24 bit]
		pktLen := int(uint32(data[0]) | uint32(data[1])<<8 | uint32(data[2])<<16)

		// check packet sync [8 bit]
		if data[3] != p.Sequence {
			if data[3] > p.Sequence {
				return nil, ErrPktSyncMul
			}
			return nil, fmt.Errorf("invalid sequence %d != %d", data[3], p.Sequence)
		}
		p.Sequence++

		// packets with length 0 terminate a previous packet which is a
		// multiple of (2^24)-1 bytes long
		if pktLen == 0 {
			// there was no previous packet
			if prevData == nil {
				return nil, errors.ErrInvalidConn
			}

			return prevData, nil
		}

		// read packet body [pktLen bytes]
		data, err = p.readNext(pktLen)
		if err != nil {
			return nil, errors.ErrInvalidConn
		}

		// return data if this was the last packet
		if pktLen < MaxPayloadLen {
			// zero allocations for non-split packets
			if prevData == nil {
				return data, nil
			}
			return append(prevData, data...), nil
		}
		prevData = append(prevData, data...)
	}
}

//WritePacket data already have header
func (p *PacketIO) WritePacket(data []byte) error {
	pktLen := len(data) - 4

	for {
		var size int
		if pktLen >= MaxPayloadLen {
			data[0] = 0xff
			data[1] = 0xff
			data[2] = 0xff
			size = MaxPayloadLen
		} else {
			data[0] = byte(pktLen)
			data[1] = byte(pktLen >> 8)
			data[2] = byte(pktLen >> 16)
			size = pktLen
		}
		data[3] = p.Sequence

		n, err := p.wb.Write(data[:4+size])
		if err == nil && n == size+4 {
			p.Sequence++
			if size != MaxPayloadLen {
				return nil
			}
			pktLen -= size
			data = data[size:]
			continue
		}
		// Handle error
		if err == nil { // n != len(data)
			print(errors.ErrMalformPkt)
		} else {
			if n == 0 && pktLen == len(data)-4 {
				// only for the first loop iteration when nothing was written yet
				return ErrBadConn
			}
			print(err)
		}
		return errors.ErrInvalidConn
	}
}

func (p *PacketIO) WritePacketBatch(total, data []byte, direct bool) ([]byte, error) {
	if data == nil {
		//only flush the buffer
		if direct == true {
			n, err := p.wb.Write(total)
			if err != nil {
				return nil, ErrBadConn
			}
			if n != len(total) {
				return nil, ErrBadConn
			}
		}
		return total, nil
	}

	length := len(data) - 4
	for length >= MaxPayloadLen {

		data[0] = 0xff
		data[1] = 0xff
		data[2] = 0xff

		data[3] = p.Sequence
		total = append(total, data[:4+MaxPayloadLen]...)

		p.Sequence++
		length -= MaxPayloadLen
		data = data[MaxPayloadLen:]
	}

	data[0] = byte(length)
	data[1] = byte(length >> 8)
	data[2] = byte(length >> 16)
	data[3] = p.Sequence

	total = append(total, data...)
	p.Sequence++

	if direct {
		if n, err := p.wb.Write(total); err != nil {
			return nil, ErrBadConn
		} else if n != len(total) {
			return nil, ErrBadConn
		}
	}
	return total, nil
}
