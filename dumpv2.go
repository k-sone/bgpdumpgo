package bgpdumpgo

import (
	"fmt"
	"net"
	"time"
)

const (
	TABLE_DUMP_V2_PEER_INDEX_TABLE MrtSubType = 1 + iota
	TABLE_DUMP_V2_RIB_IPV4_UNICAST
	TABLE_DUMP_V2_RIB_IPV4_MULTICAST
	TABLE_DUMP_V2_RIB_IPV6_UNICAST
	TABLE_DUMP_V2_RIB_IPV6_MULTICAST
	TABLE_DUMP_V2_RIB_GENERIC
)

type TableDumpV2PeerIndexTable struct {
	CollectorBgpID net.IP
	ViewName       string
	PeerEntries    []*TableDumpV2PeerIndexTableEntry
}

type TableDumpV2PeerIndexTableEntry struct {
	PeerType      byte
	PeerBgpID     net.IP
	PeerIPAddress net.IP
	PeerAs        uint32
}

type TableDumpV2Prefix struct {
	SequenceNumber uint32
	Prefix         *net.IPNet
	RibEntries     []*TableDumpV2RibEntry
}

type TableDumpV2RibEntry struct {
	PeerIndex      uint16
	OriginatedTime time.Time
	Attribute      *BgpAttribute
}

func (p *Parser) parseTableDumpV2(header *Header) (body interface{}, err error) {
	if err = p.sc.fill(p.rd, header.Length); err != nil {
		return nil, err
	}

	switch header.Subtype {
	case TABLE_DUMP_V2_PEER_INDEX_TABLE:
		body = p.parseTableDumpV2PeerIndexTable()
	case TABLE_DUMP_V2_RIB_IPV4_UNICAST:
		body, err = p.parseTableDumpV2Prefix(net.IPv4len)
	case TABLE_DUMP_V2_RIB_IPV6_UNICAST:
		body, err = p.parseTableDumpV2Prefix(net.IPv6len)
	default:
		return nil, fmt.Errorf("Unsupported TABLE_DUMP_V2 Type: %d", header.Subtype)
	}
	return
}

//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                      Collector BGP ID                         |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |       View Name Length        |     View Name (variable)      |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |          Peer Count           |    Peer Entries (variable)    |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
func (p *Parser) parseTableDumpV2PeerIndexTable() *TableDumpV2PeerIndexTable {
	ret := &TableDumpV2PeerIndexTable{}
	ret.CollectorBgpID = p.sc.getIPv4()

	viewNameLength := int(p.sc.getW())
	ret.ViewName = string(p.sc.get(viewNameLength))

	peerCount := int(p.sc.getW())
	peerEntries := make([]TableDumpV2PeerIndexTableEntry, peerCount)
	ret.PeerEntries = make([]*TableDumpV2PeerIndexTableEntry, peerCount)
	for i := 0; i < peerCount; i++ {
		p.parseTableDumpV2PeerIndexTableEntry(&peerEntries[i])
		ret.PeerEntries[i] = &peerEntries[i]
	}

	return ret
}

//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |   Peer Type   |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                         Peer BGP ID                           |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                   Peer IP Address (variable)                  |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                        Peer AS (variable)                     |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
func (p *Parser) parseTableDumpV2PeerIndexTableEntry(obj *TableDumpV2PeerIndexTableEntry) {
	obj.PeerType = p.sc.getC()
	obj.PeerBgpID = p.sc.getIPv4()

	if obj.PeerType&0x01 == 0 {
		obj.PeerIPAddress = p.sc.getIPv4()
	} else {
		obj.PeerIPAddress = p.sc.getIPv6()
	}

	if obj.PeerType&0x02 == 0 {
		obj.PeerAs = uint32(p.sc.getW())
	} else {
		obj.PeerAs = p.sc.getL()
	}
}

//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                         Sequence Number                       |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | Prefix Length |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                        Prefix (variable)                      |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |         Entry Count           |  RIB Entries (variable)       |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
func (p *Parser) parseTableDumpV2Prefix(iplen int) (*TableDumpV2Prefix, error) {
	ret := &TableDumpV2Prefix{}
	ret.SequenceNumber = p.sc.getL()

	prefixLength := int(p.sc.getC())
	ret.Prefix = &net.IPNet{
		IP:   p.sc.getIP((prefixLength+7)>>3, iplen),
		Mask: net.CIDRMask(prefixLength, iplen*8),
	}

	ribCount := int(p.sc.getW())
	ribEntries := make([]TableDumpV2RibEntry, ribCount)
	ret.RibEntries = make([]*TableDumpV2RibEntry, ribCount)
	for i := 0; i < ribCount; i++ {
		if err := p.parseTableDumpV2RibEntry(&ribEntries[i]); err != nil {
			return nil, err
		}
		ret.RibEntries[i] = &ribEntries[i]
	}

	return ret, nil
}

// 0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |         Peer Index            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                         Originated Time                       |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |      Attribute Length         |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                    BGP Attributes... (variable)
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
func (p *Parser) parseTableDumpV2RibEntry(obj *TableDumpV2RibEntry) (err error) {
	obj.PeerIndex = p.sc.getW()
	obj.OriginatedTime = time.Unix(int64(p.sc.getL()), 0)

	attrLength := int(p.sc.getW())
	obj.Attribute, err = p.parseBgpAttribute(attrLength, ASN32_LEN)
	return
}
