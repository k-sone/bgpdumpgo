package bgpdumpgo

import (
	"compress/bzip2"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime/debug"
	"time"
)

type MrtType uint16

const (
	TABLE_DUMP    MrtType = 12
	TABLE_DUMP_V2 MrtType = 13
)

type MrtSubType uint16

type Header struct {
	Timestamp time.Time
	Type      MrtType
	Subtype   MrtSubType
	Length    int
}

type Entry struct {
	Header *Header
	Body   interface{}
}

type Error struct {
	Message string
	Stack   []byte
}

func (e Error) Error() string {
	return fmt.Sprintf("%s\n%s", e.Message, string(e.Stack))
}

type scanner struct {
	buf []byte
	pos int
	err error
}

func (s *scanner) fill(rd io.Reader, n int) error {
	s.expand(n)

	var count, start int
	for i := 0; i < 2; i++ {
		buf := s.buf[start:n]
		m, err := rd.Read(buf)
		if m > 0 {
			count += m
			start += m
		}
		if err != nil {
			return err
		}
		if n == count {
			s.pos = 0
			s.err = nil
			return nil
		}
	}
	return fmt.Errorf("Failed to fill the buffer, request [%d], actual [%d]", n, count)
}

func (s *scanner) expand(n int) {
	if n > len(s.buf) {
		buf := make([]byte, n)
		copy(buf, s.buf)
		s.buf = buf
	}
}

func (s *scanner) readable() bool {
	return len(s.buf) > s.pos && s.err == nil
}

func (s *scanner) check(n int) bool {
	if s.err != nil {
		return false
	}
	if len(s.buf) < s.pos+n {
		s.err = Error{
			Message: fmt.Sprintf(
				"Failed to get data from the buffer, range [%d:%d], length [%d]",
				s.pos, s.pos+n, len(s.buf)),
			Stack: debug.Stack(),
		}
		return false
	}
	return true
}

func (s *scanner) get(n int) []byte {
	if !s.check(n) {
		return nil
	}
	pos := s.pos
	s.pos += n
	return s.buf[pos:s.pos]
}

func (s *scanner) getC() byte {
	if !s.check(1) {
		return 0
	}
	pos := s.pos
	s.pos += 1
	return s.buf[pos]
}

func (s *scanner) getW() uint16 {
	if !s.check(2) {
		return 0
	}
	pos := s.pos
	s.pos += 2
	return binary.BigEndian.Uint16(s.buf[pos:s.pos])
}

func (s *scanner) getL() uint32 {
	if !s.check(4) {
		return 0
	}
	pos := s.pos
	s.pos += 4
	return binary.BigEndian.Uint32(s.buf[pos:s.pos])
}

func (s *scanner) getIP(nlen, mlen int) net.IP {
	ip := net.IP(make([]byte, mlen))
	if s.check(nlen) {
		pos := s.pos
		s.pos += nlen
		copy(ip, s.buf[pos:s.pos])
	}
	return ip
}

func (s *scanner) getIPv4() net.IP {
	return s.getIP(net.IPv4len, net.IPv4len)
}

func (s *scanner) getIPv6() net.IP {
	return s.getIP(net.IPv6len, net.IPv6len)
}

type Parser struct {
	fd *os.File
	rd io.Reader
	sc *scanner
}

func (p *Parser) Next() (*Entry, error) {
	if p.rd == nil {
		return nil, errors.New("Parser is closed")
	}

	header, err := p.parseHeader()
	if err != nil {
		return nil, err
	}
	if p.sc.err != nil {
		return nil, p.sc.err
	}

	var body interface{}
	switch header.Type {
	case TABLE_DUMP_V2:
		body, err = p.parseTableDumpV2(header)
	default:
		err = fmt.Errorf("Unsupported MRT Type: %d", header.Type)
	}
	if err != nil {
		return nil, err
	}
	if p.sc.err != nil {
		return nil, p.sc.err
	}

	return &Entry{
		Header: header,
		Body:   body,
	}, nil
}

func (p *Parser) Close() {
	if p.fd != nil {
		p.fd.Close()
		p.fd = nil
	}
	p.rd = nil
}

//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                           Timestamp                           |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |             Type              |            Subtype            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                             Length                            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
func (p *Parser) parseHeader() (*Header, error) {
	if err := p.sc.fill(p.rd, 12); err != nil {
		return nil, err
	}
	return &Header{
		Timestamp: time.Unix(int64(p.sc.getL()), 0),
		Type:      MrtType(p.sc.getW()),
		Subtype:   MrtSubType(p.sc.getW()),
		Length:    int(p.sc.getL()),
	}, nil
}

func New(rd io.Reader) *Parser {
	sc := &scanner{}
	sc.expand(4096)
	p := &Parser{rd: rd, sc: sc}
	return p
}

func NewPath(path string) (*Parser, error) {
	fd, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	parser := New(fd)
	parser.fd = fd
	return parser, nil
}

func NewBzip2(path string) (*Parser, error) {
	fd, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	parser := New(bzip2.NewReader(fd))
	parser.fd = fd
	return parser, nil
}
