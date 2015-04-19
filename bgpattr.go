package bgpdumpgo

import (
	"fmt"
	"net"
	"runtime/debug"
	"strconv"
)

const (
	_BGP_ATTR_FLAG_EXTLEN = 0x10
)

const (
	_BGP_ATTR_ORIGIN = 1 + iota
	_BGP_ATTR_AS_PATH
	_BGP_ATTR_NEXT_HOP
	_BGP_ATTR_MULTI_EXIT_DISC
	_BGP_ATTR_LOCAL_PREF
	_BGP_ATTR_ATOMIC_AGGREGATE
	_BGP_ATTR_AGGREGATOR
	_BGP_ATTR_COMMUNITIES
	_BGP_ATTR_ORIGINATOR_ID
	_BGP_ATTR_CLUSTER_LIST
	_BGP_ATTR_DPA
	_BGP_ATTR_ADVERTISER
	_BGP_ATTR_RCID_PATH
	_BGP_ATTR_MP_REACH_NLRI
	_BGP_ATTR_MP_UNREACH_NLRI
	_BGP_ATTR_EXT_COMMUNITIES
	_BGP_ATTR_NEW_AS_PATH
	_BGP_ATTR_NEW_AGGREGATOR
)

type AsnLen int

const (
	ASN16_LEN AsnLen = 2
	ASN32_LEN AsnLen = 4
)

type BgpOrigin int

const (
	IGP BgpOrigin = iota
	EGP
	INCOMPLETE
)

type BgpAsPathType int

const (
	AS_SET BgpAsPathType = 1 + iota
	AS_SEQUENCE
	AS_CONFED_SEQUENCE
	AS_CONFED_SET
)

func (t BgpAsPathType) Valid() bool {
	return t >= AS_SET && t <= AS_CONFED_SET
}

type BgpCommunity uint32

const (
	COMMUNITY_NO_EXPORT BgpCommunity = 0xFFFFFF01 + iota
	COMMUNITY_NO_ADVERTISE
	COMMUNITY_NO_EXPORT_SUBCONFED
	COMMUNITY_LOCAL_AS
)

func (c BgpCommunity) String() string {
	switch c {
	case COMMUNITY_NO_EXPORT:
		return "NOrEXPORT"
	case COMMUNITY_NO_ADVERTISE:
		return "NO-ADVERTISE"
	case COMMUNITY_NO_EXPORT_SUBCONFED:
		return "NO-EXPORT-SUBCONFED"
	case COMMUNITY_LOCAL_AS:
		return "LOCAL-AS"
	default:
		a := strconv.Itoa(int((c >> 16) & 0xFFFF))
		v := strconv.Itoa(int(c & 0xFFFF))
		return a + ":" + v
	}
}

type BgpAttrAfi uint16

const (
	AFI_IPv4 BgpAttrAfi = 1 + iota
	AFI_IPv6
)

func (a BgpAttrAfi) Valid() bool {
	return a == AFI_IPv4 || a == AFI_IPv6
}

type BgpAttrSubAfi byte

const (
	SUB_AFI_UNICAST BgpAttrSubAfi = 1 + iota
	SUB_AFI_MULTICAST
)

func (s BgpAttrSubAfi) Valid() bool {
	return s == SUB_AFI_UNICAST || s == SUB_AFI_MULTICAST
}

type BgpAttrAsSegment struct {
	AsnLen AsnLen
	Type   BgpAsPathType
	As     []uint32
}

type BgpAttrMpReacheableNlri struct {
	Afi        BgpAttrAfi
	SubAfi     BgpAttrSubAfi
	NextHopLen int
	NextHop    net.IP
	Reserved   byte
	Nlri       []*net.IPNet
}

type BgpAttrMpUnreacheableNlri struct {
	Afi       BgpAttrAfi
	SubAfi    BgpAttrSubAfi
	Withdrawn []*net.IPNet
}

type BgpAttribute struct {
	Origin             BgpOrigin
	AsPath             []*BgpAttrAsSegment
	NextHop            net.IP
	MultiExtDisc       uint32
	LocalPref          uint32
	AggregatorAs       uint32
	AggregatorAddr     net.IP
	Community          []BgpCommunity
	OriginatorID       net.IP
	Cluster            []net.IP
	MpReacheableNlri   *BgpAttrMpReacheableNlri
	MpUnreacheableNlri *BgpAttrMpUnreacheableNlri
	NewAsPath          []*BgpAttrAsSegment
	NewAggregatorAs    uint32
	NewAggregatorAddr  net.IP
	UnknownAttr        bool
}

func (p *Parser) parseBgpAttribute(attrLen int, asnLen AsnLen) (*BgpAttribute, error) {
	obj := &BgpAttribute{}
	for attrLen += p.sc.pos; p.sc.pos < attrLen; {
		bgpFlag := p.sc.getC()
		bgpType := p.sc.getC()

		var sc *scanner
		if bgpFlag&_BGP_ATTR_FLAG_EXTLEN == 0 {
			sc = &scanner{buf: p.sc.get(int(p.sc.getC()))}
		} else {
			sc = &scanner{buf: p.sc.get(int(p.sc.getW()))}
		}
		if p.sc.err != nil {
			return nil, p.sc.err
		}

		var err error
		switch bgpType {
		case _BGP_ATTR_ORIGIN:
			obj.Origin = BgpOrigin(sc.getC())
		case _BGP_ATTR_AS_PATH:
			obj.AsPath, err = parseBgpAttrAsPath(sc, asnLen)
		case _BGP_ATTR_NEXT_HOP:
			obj.NextHop = sc.getIPv4()
		case _BGP_ATTR_MULTI_EXIT_DISC:
			obj.MultiExtDisc = sc.getL()
		case _BGP_ATTR_LOCAL_PREF:
			obj.LocalPref = sc.getL()
		case _BGP_ATTR_ATOMIC_AGGREGATE:
			// pass
		case _BGP_ATTR_AGGREGATOR:
			obj.AggregatorAs, obj.AggregatorAddr = parseBgpAttrAggregate(sc, asnLen)
		case _BGP_ATTR_COMMUNITIES:
			obj.Community = make([]BgpCommunity, len(sc.buf)/4)
			for i := 0; i < len(obj.Community); i++ {
				obj.Community[i] = BgpCommunity(sc.getL())
			}
		case _BGP_ATTR_ORIGINATOR_ID:
			obj.OriginatorID = sc.getIPv4()
		case _BGP_ATTR_CLUSTER_LIST:
			obj.Cluster = make([]net.IP, len(sc.buf)/net.IPv4len)
			for i := 0; i < len(obj.Cluster); i++ {
				obj.Cluster[i] = sc.getIPv4()
			}
		case _BGP_ATTR_MP_REACH_NLRI:
			obj.MpReacheableNlri, err = parseBgpAttrMpReacheableNlri(sc)
		case _BGP_ATTR_MP_UNREACH_NLRI:
			obj.MpUnreacheableNlri, err = parseBgpAttrMpUnreacheableNlri(sc)
		case _BGP_ATTR_NEW_AS_PATH:
			obj.NewAsPath, err = parseBgpAttrAsPath(sc, ASN32_LEN)
		case _BGP_ATTR_NEW_AGGREGATOR:
			obj.NewAggregatorAs, obj.NewAggregatorAddr = parseBgpAttrAggregate(sc, ASN32_LEN)
		default:
			obj.UnknownAttr = true
		}

		if err != nil {
			return nil, err
		}
		if sc.err != nil {
			return nil, sc.err
		}
	}
	return obj, nil
}

func parseBgpAttrAsPath(sc *scanner, asnLen AsnLen) ([]*BgpAttrAsSegment, error) {
	asp := make([]*BgpAttrAsSegment, 0, 1)
	for i := 0; sc.readable(); i++ {
		t := BgpAsPathType(sc.getC())
		if !t.Valid() {
			return nil, Error{
				Message: fmt.Sprintf("Invalid the type of BgpAttrAsPath [%d]", t),
				Stack:   debug.Stack(),
			}
		}

		l := int(sc.getC())
		asp = append(asp, &BgpAttrAsSegment{
			AsnLen: asnLen,
			Type:   t,
			As:     make([]uint32, l),
		})

		for j := 0; j < l; j++ {
			if asnLen == ASN16_LEN {
				asp[i].As[j] = uint32(sc.getW())
			} else {
				asp[i].As[j] = sc.getL()
			}
		}
	}
	return asp, nil
}

func parseBgpAttrAggregate(sc *scanner, asnLen AsnLen) (uint32, net.IP) {
	var as uint32
	if asnLen == ASN16_LEN {
		as = uint32(sc.getW())
	} else {
		as = sc.getL()
	}
	return as, sc.getIPv4()
}

// RFC4760
// +---------------------------------------------------------+
// | Address Family Identifier (2 octets)                    |
// +---------------------------------------------------------+
// | Subsequent Address Family Identifier (1 octet)          |
// +---------------------------------------------------------+
// | Length of Next Hop Network Address (1 octet)            |
// +---------------------------------------------------------+
// | Network Address of Next Hop (variable)                  |
// +---------------------------------------------------------+
// | Reserved (1 octet)                                      |
// +---------------------------------------------------------+
// | Network Layer Reachability Information (variable)       |
// +---------------------------------------------------------+
func parseBgpAttrMpReacheableNlri(sc *scanner) (*BgpAttrMpReacheableNlri, error) {
	afi := BgpAttrAfi(sc.getW())
	if !afi.Valid() {
		return nil, Error{
			Message: fmt.Sprintf("Unknown AFI [%d] of BgpAttrMpReacheableNlri [%d]", afi),
			Stack:   debug.Stack(),
		}
	}

	safi := BgpAttrSubAfi(sc.getC())
	if safi.Valid() {
		return nil, Error{
			Message: fmt.Sprintf("Unknown SAFI [%d] of BgpAttrMpReacheableNlri [%d]", safi),
			Stack:   debug.Stack(),
		}
	}

	nlen := int(sc.getC())
	var ip net.IP
	if afi == AFI_IPv4 {
		ip = sc.getIP(nlen, net.IPv4len)
	} else {
		ip = sc.getIP(nlen, net.IPv6len)
	}

	reserved := sc.getC()
	nlri := parseBgpAttrNlri(sc, afi)

	return &BgpAttrMpReacheableNlri{
		Afi:        afi,
		SubAfi:     safi,
		NextHopLen: nlen,
		NextHop:    ip,
		Reserved:   reserved,
		Nlri:       nlri,
	}, nil
}

// +---------------------------------------------------------+
// | Address Family Identifier (2 octets)                    |
// +---------------------------------------------------------+
// | Subsequent Address Family Identifier (1 octet)          |
// +---------------------------------------------------------+
// | Withdrawn Routes (variable)                             |
// +---------------------------------------------------------+
func parseBgpAttrMpUnreacheableNlri(sc *scanner) (*BgpAttrMpUnreacheableNlri, error) {
	afi := BgpAttrAfi(sc.getW())
	if !afi.Valid() {
		return nil, Error{
			Message: fmt.Sprintf("Unknown AFI [%d] of BgpAttrMpUnreacheableNlri [%d]", afi),
			Stack:   debug.Stack(),
		}
	}

	safi := BgpAttrSubAfi(sc.getC())
	if safi.Valid() {
		return nil, Error{
			Message: fmt.Sprintf("Unknown SAFI [%d] of BgpAttrMpUnreacheableNlri [%d]", safi),
			Stack:   debug.Stack(),
		}
	}

	nlri := parseBgpAttrNlri(sc, afi)

	return &BgpAttrMpUnreacheableNlri{
		Afi:       afi,
		SubAfi:    safi,
		Withdrawn: nlri,
	}, nil
}

// +---------------------------+
// |   Length (1 octet)        |
// +---------------------------+
// |   Prefix (variable)       |
// +---------------------------+
func parseBgpAttrNlri(sc *scanner, afi BgpAttrAfi) []*net.IPNet {
	var iplen int
	if afi == AFI_IPv4 {
		iplen = net.IPv4len
	} else {
		iplen = net.IPv6len
	}

	nlri := make([]*net.IPNet, 0, 1)
	for sc.readable() {
		nlen := int(sc.getC())
		nlri = append(nlri, &net.IPNet{
			IP:   sc.getIP((nlen+7)>>3, iplen),
			Mask: net.CIDRMask(nlen, iplen*8),
		})
	}
	return nlri
}
