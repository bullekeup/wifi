//+build linux

package wifi

import (
	"bytes"
	"errors"
	"math"
	"net"
	"os"
	"time"
	"unicode/utf8"

	"github.com/mdlayher/netlink"
	"github.com/mdlayher/netlink/genetlink"
	"github.com/mdlayher/netlink/nlenc"
	"github.com/mdlayher/wifi/internal/nl80211"
)

// Errors which may occur when interacting with generic netlink.
var (
	errMultipleMessages     = errors.New("expected only one generic netlink message")
	errInvalidCommand       = errors.New("invalid generic netlink response command")
	errInvalidFamilyVersion = errors.New("invalid generic netlink response family version")
	errInvalidMcastGrp      = errors.New("invalid multicast group")
)

var _ osClient = &client{}

// A client is the Linux implementation of osClient, which makes use of
// netlink, generic netlink, and nl80211 to provide access to WiFi device
// actions and statistics.
type client struct {
	c               genl
	familyID        uint16
	familyVersion   uint8
	groups				  []genetlink.MulticastGroup
	subscribedgrps	map[string]uint32
}

// genl is an interface over generic netlink, so netlink interactions can
// be stubbed in tests.
type genl interface {
	Close() error
	GetFamily(name string) (genetlink.Family, error)
	Execute(m genetlink.Message, family uint16, flags netlink.HeaderFlags) ([]genetlink.Message, error)
	ExecuteNoSeqCheck(m genetlink.Message, family uint16, flags netlink.HeaderFlags) ([]genetlink.Message, error)
	JoinGroup(ID uint32) error
	LeaveGroup(ID uint32) error
	Receive() ([]genetlink.Message, []netlink.Message, error)
}

// newClient dials a generic netlink connection and verifies that nl80211
// is available for use by this package.
func newClient() (*client, error) {
	c, err := genetlink.Dial(nil)
	if err != nil {
		return nil, err
	}

	g := &sysGENL{Conn: c}
	return initClient(g)
}

// initClient is the internal constructor for a client, used in tests.
func initClient(c genl) (*client, error) {
	family, err := c.GetFamily(nl80211.GenlName)
	if err != nil {
		// Ensure the genl socket is closed on error to avoid leaking file
		// descriptors.
		_ = c.Close()
		return nil, err
	}

	return &client{
		c:              c,
		familyID:       family.ID,
		familyVersion:  family.Version,
    groups:	        family.Groups,
		subscribedgrps: make(map[string]uint32),
	}, nil
}

func (c *client) GetGroups() map[string]uint32 {
	ret := make(map[string]uint32)
	for _, group := range c.groups {
		ret[group.Name] = group.ID
	}
	return ret
}

func (c *client) ResolveGroupName(name string) (uint32, error) {
	for _, group := range c.groups {
		if name == group.Name {
			return group.ID, nil
		}
	}
	return 0, errInvalidMcastGrp
}

func (c *client) JoinGroup(ID uint32) error {
	return c.c.JoinGroup(ID)
}

func (c *client) LeaveGroup(ID uint32) error {
	return c.c.LeaveGroup(ID)
}

// Close closes the client's generic netlink connection.
func (c *client) Close() error {
	return c.c.Close()
}

// Interfaces requests that nl80211 return a list of all WiFi interfaces present
// on this system.
func (c *client) Interfaces() ([]*Interface, error) {
	// Ask nl80211 to dump a list of all WiFi interfaces
	req := genetlink.Message{
		Header: genetlink.Header{
			Command: nl80211.CmdGetInterface,
			Version: c.familyVersion,
		},
	}

	flags := netlink.HeaderFlagsRequest | netlink.HeaderFlagsDump
	msgs, err := c.c.Execute(req, c.familyID, flags)
	if err != nil {
		return nil, err
	}

	if err := c.checkMessages(msgs, nl80211.CmdNewInterface); err != nil {
		return nil, err
	}

	return parseInterfaces(msgs)
}

// BSS requests that nl80211 return the BSS for the specified Interface.
func (c *client) BSS(ifi *Interface) (*BSS, error) {
	msgs, err := c.BSSNoParse(ifi)
	if err != nil {
		return nil, err
	}

	return parseBSS(msgs)
}

func (c *client) BSSNoParse(ifi *Interface) ([]genetlink.Message, error) {
	b, err := netlink.MarshalAttributes(ifi.idAttrs())
	if err != nil {
		return nil, err
	}

	// Ask nl80211 to retrieve BSS information for the interface specified
	// by its attributes
	req := genetlink.Message{
		Header: genetlink.Header{
			Command: nl80211.CmdGetScan,
			Version: c.familyVersion,
		},
		Data: b,
	}

	flags := netlink.HeaderFlagsRequest | netlink.HeaderFlagsDump
	msgs, err := c.c.Execute(req, c.familyID, flags)
	if err != nil {
		return nil, err
	}

	if err := c.checkMessages(msgs, nl80211.CmdNewScanResults); err != nil {
		return nil, err
	}

	return msgs, nil
}

// StationInfo requests that nl80211 return station info for the specified
// Interface.
func (c *client) StationInfo(ifi *Interface) (*StationInfo, error) {
	b, err := netlink.MarshalAttributes(ifi.idAttrs())
	if err != nil {
		return nil, err
	}

	// Ask nl80211 to retrieve station info for the interface specified
	// by its attributes
	req := genetlink.Message{
		Header: genetlink.Header{
			// From nl80211.h:
			//  * @NL80211_CMD_GET_STATION: Get station attributes for station identified by
			//  * %NL80211_ATTR_MAC on the interface identified by %NL80211_ATTR_IFINDEX.
			Command: nl80211.CmdGetStation,
			Version: c.familyVersion,
		},
		Data: b,
	}

	flags := netlink.HeaderFlagsRequest | netlink.HeaderFlagsDump
	msgs, err := c.c.Execute(req, c.familyID, flags)
	if err != nil {
		return nil, err
	}

	switch len(msgs) {
	case 0:
		return nil, os.ErrNotExist
	case 1:
		break
	default:
		return nil, errMultipleMessages
	}

	if err := c.checkMessages(msgs, nl80211.CmdNewStation); err != nil {
		return nil, err
	}

	return parseStationInfo(msgs[0].Data)
}

// Scan request a new scan for available networks to the kernel.
// We must have subscribed to groups sending back scan triggered and results available
func (c *client) Scan(ifi *Interface) (*ScanResult, error) {
	grps := make(map[string]uint32)
	grps["config"] = 0
	grps["scan"] = 0

	// Subscribe to groups config and scan to be able to retrieve when scan has ended
	// and results are available
	for grp, _ := range grps {
		if _, subsd := c.subscribedgrps[grp]; !subsd {
			grpid, err := c.ResolveGroupName(grp)
			grps[grp] = grpid
			if err != nil {
				return nil, err
			}
			err = c.JoinGroup(grps[grp])
			if err != nil {
				return nil, err
			}
			defer c.LeaveGroup(grps[grp])
		}
	}

	// Send a trigger scan command for the requested interface to the kernel
	b, err := netlink.MarshalAttributes(ifi.idAttrs())
	if err != nil {
		return nil, err
	}

	req := genetlink.Message{
		Header: genetlink.Header{
			// From nl80211h:
			//  * @NL80211_CMD_TRIGGER_SCAN: trigger a new scan
			//  * Note that we don't use any options,
			//  * just perform an active scan for all available networks
			//  *
			Command: nl80211.CmdTriggerScan,
			Version: c.familyVersion,
		},
		Data: b,
	}
	flags := netlink.HeaderFlagsRequest
	msgs, err := c.c.ExecuteNoSeqCheck(req, c.familyID, flags)
	if err != nil {
		return nil, err
	}
	if err := c.checkMessages(msgs, nl80211.CmdTriggerScan); err != nil {
		return nil, err
	}

	// Wait for scan results (first response is received as mcast response
	// and contain scan infos, see parseScan function)
	for true {
		msgs, _, err = c.c.Receive()
		if err != nil {
			return nil, err
		}
		if err := c.checkMessages(msgs, nl80211.CmdNewScanResults); err == nil {
			break
		}
	}
	results, err := parseScan(msgs)

	// Request BSS results and parse them
	msgs, err = c.BSSNoParse(ifi)
	if err != nil {
		return nil, err
	}

	bss, err := parseMultipleBSS(msgs)
	if err != nil {
		return nil, err
	}
	results.BSSInRange = bss
	return results, nil
}

// checkMessages verifies that response messages from generic netlink contain
// the command and family version we expect.
func (c *client) checkMessages(msgs []genetlink.Message, command uint8) error {
	for _, m := range msgs {
		if m.Header.Command != command {
			return errInvalidCommand
		}

		if m.Header.Version != c.familyVersion {
			return errInvalidFamilyVersion
		}
	}

	return nil
}

// parseInterfaces parses zero or more Interfaces from nl80211 interface
// messages.
func parseInterfaces(msgs []genetlink.Message) ([]*Interface, error) {
	ifis := make([]*Interface, 0, len(msgs))
	for _, m := range msgs {
		attrs, err := netlink.UnmarshalAttributes(m.Data)
		if err != nil {
			return nil, err
		}

		var ifi Interface
		if err := (&ifi).parseAttributes(attrs); err != nil {
			return nil, err
		}

		ifis = append(ifis, &ifi)
	}

	return ifis, nil
}

// idAttrs returns the netlink attributes required from an Interface to retrieve
// more data about it.
func (ifi *Interface) idAttrs() []netlink.Attribute {
	return []netlink.Attribute{
		{
			Type: nl80211.AttrIfindex,
			Data: nlenc.Uint32Bytes(uint32(ifi.Index)),
		},
		{
			Type: nl80211.AttrMac,
			Data: ifi.HardwareAddr,
		},
	}
}

// parseAttributes parses netlink attributes into an Interface's fields.
func (ifi *Interface) parseAttributes(attrs []netlink.Attribute) error {
	for _, a := range attrs {
		switch a.Type {
		case nl80211.AttrIfindex:
			ifi.Index = int(nlenc.Uint32(a.Data))
		case nl80211.AttrIfname:
			ifi.Name = nlenc.String(a.Data)
		case nl80211.AttrMac:
			ifi.HardwareAddr = net.HardwareAddr(a.Data)
		case nl80211.AttrWiphy:
			ifi.PHY = int(nlenc.Uint32(a.Data))
		case nl80211.AttrIftype:
			// NOTE: InterfaceType copies the ordering of nl80211's interface type
			// constants.  This may not be the case on other operating systems.
			ifi.Type = InterfaceType(nlenc.Uint32(a.Data))
		case nl80211.AttrWdev:
			ifi.Device = int(nlenc.Uint64(a.Data))
		case nl80211.AttrWiphyFreq:
			ifi.Frequency = int(nlenc.Uint32(a.Data))
		}
	}

	return nil
}

// parseBSS parses a single BSS with a status attribute from nl80211 BSS messages.
func parseBSS(msgs []genetlink.Message) (*BSS, error) {
	for _, m := range msgs {
		bss, err := parseSingleBSS(m, true)
		if err != nil {
			return nil, err
		}
		if bss != nil {
			return bss, nil
		}
	}

	return nil, os.ErrNotExist
}

// parseMultipleBSS parses all BSS found in messages
func parseMultipleBSS(msgs []genetlink.Message) ([]*BSS, error) {
	var ret []*BSS
	for _, m := range msgs {
		bss, err := parseSingleBSS(m, false)
		if err != nil {
			return nil, err
		}
		if bss != nil {
			ret = append(ret, bss)
		}
	}
	return ret, nil
}

// parseSingleBSS actually do the parsing of each message for
// parseBSS and parseMultipleBSS
func parseSingleBSS(msg genetlink.Message, checkstatus bool) (*BSS, error) {
	attrs, err := netlink.UnmarshalAttributes(msg.Data)
	if err != nil {
		return nil, err
	}

	for _, a := range attrs {
		if a.Type != nl80211.AttrBss {
			continue
		}

		nattrs, err := netlink.UnmarshalAttributes(a.Data)
		if err != nil {
			return nil, err
		}

		// The BSS which is associated with an interface will have a status
		// attribute
		if checkstatus && !attrsContain(nattrs, nl80211.BssStatus) {
			return nil, nil
		}

		var bss BSS
		if err := (&bss).parseAttributes(nattrs); err != nil {
			return nil, err
		}

		return &bss, nil
	}

	return nil, os.ErrNotExist
}

// parseAttributes parses netlink attributes into a BSS's fields.
func (b *BSS) parseAttributes(attrs []netlink.Attribute) error {
	for _, a := range attrs {
		switch a.Type {
		case nl80211.BssBssid:
			b.BSSID = net.HardwareAddr(a.Data)
		case nl80211.BssFrequency:
			b.Frequency = int(nlenc.Uint32(a.Data))
		case nl80211.BssBeaconInterval:
			// Raw value is in "Time Units (TU)".  See:
			// https://en.wikipedia.org/wiki/Beacon_frame
			b.BeaconInterval = time.Duration(nlenc.Uint16(a.Data)) * 1024 * time.Microsecond
		case nl80211.BssSeenMsAgo:
			// * @NL80211_BSS_SEEN_MS_AGO: age of this BSS entry in ms
			b.LastSeen = time.Duration(nlenc.Uint32(a.Data)) * time.Millisecond
		case nl80211.BssStatus:
			// NOTE: BSSStatus copies the ordering of nl80211's BSS status
			// constants.  This may not be the case on other operating systems.
			b.Status = BSSStatus(nlenc.Uint32(a.Data))
		case nl80211.BssInformationElements:
			ies, err := parseIEs(a.Data)
			if err != nil {
				return err
			}

			// TODO(mdlayher): return more IEs if they end up being generally useful
			for _, ie := range ies {
				switch ie.ID {
				case ieSSID:
					b.SSID = decodeSSID(ie.Data)
				}
			}
		}
	}

	return nil
}

// parseStationInfo parses StationInfo attributes from a byte slice of
// netlink attributes.
func parseStationInfo(b []byte) (*StationInfo, error) {
	attrs, err := netlink.UnmarshalAttributes(b)
	if err != nil {
		return nil, err
	}

	for _, a := range attrs {
		// The other attributes that are returned here appear to indicate the
		// interface index and MAC address, which is information we already
		// possess.  No need to parse them for now.
		if a.Type != nl80211.AttrStaInfo {
			continue
		}

		nattrs, err := netlink.UnmarshalAttributes(a.Data)
		if err != nil {
			return nil, err
		}

		var info StationInfo
		if err := (&info).parseAttributes(nattrs); err != nil {
			return nil, err
		}

		return &info, nil
	}

	// No station info found
	return nil, os.ErrNotExist
}

// parseAttributes parses netlink attributes into a StationInfo's fields.
func (info *StationInfo) parseAttributes(attrs []netlink.Attribute) error {
	for _, a := range attrs {
		switch a.Type {
		case nl80211.StaInfoConnectedTime:
			// Though nl80211 does not specify, this value appears to be in seconds:
			// * @NL80211_STA_INFO_CONNECTED_TIME: time since the station is last connected
			info.Connected = time.Duration(nlenc.Uint32(a.Data)) * time.Second
		case nl80211.StaInfoInactiveTime:
			// * @NL80211_STA_INFO_INACTIVE_TIME: time since last activity (u32, msecs)
			info.Inactive = time.Duration(nlenc.Uint32(a.Data)) * time.Millisecond
		case nl80211.StaInfoRxBytes64:
			info.ReceivedBytes = int(nlenc.Uint64(a.Data))
		case nl80211.StaInfoTxBytes64:
			info.TransmittedBytes = int(nlenc.Uint64(a.Data))
		case nl80211.StaInfoSignal:
			// Converted into the typical negative strength format
			//  * @NL80211_STA_INFO_SIGNAL: signal strength of last received PPDU (u8, dBm)
			info.Signal = int(a.Data[0]) - math.MaxUint8
		case nl80211.StaInfoRxPackets:
			info.ReceivedPackets = int(nlenc.Uint32(a.Data))
		case nl80211.StaInfoTxPackets:
			info.TransmittedPackets = int(nlenc.Uint32(a.Data))
		case nl80211.StaInfoTxRetries:
			info.TransmitRetries = int(nlenc.Uint32(a.Data))
		case nl80211.StaInfoTxFailed:
			info.TransmitFailed = int(nlenc.Uint32(a.Data))
		case nl80211.StaInfoBeaconLoss:
			info.BeaconLoss = int(nlenc.Uint32(a.Data))
		case nl80211.StaInfoRxBitrate, nl80211.StaInfoTxBitrate:
			rate, err := parseRateInfo(a.Data)
			if err != nil {
				return err
			}

			// TODO(mdlayher): return more statistics if they end up being
			// generally useful
			switch a.Type {
			case nl80211.StaInfoRxBitrate:
				info.ReceiveBitrate = rate.Bitrate
			case nl80211.StaInfoTxBitrate:
				info.TransmitBitrate = rate.Bitrate
			}
		}

		// Only use 32-bit counters if the 64-bit counters are not present.
		// If the 64-bit counters appear later in the slice, they will overwrite
		// these values.
		if info.ReceivedBytes == 0 && a.Type == nl80211.StaInfoRxBytes {
			info.ReceivedBytes = int(nlenc.Uint32(a.Data))
		}
		if info.TransmittedBytes == 0 && a.Type == nl80211.StaInfoTxBytes {
			info.TransmittedBytes = int(nlenc.Uint32(a.Data))
		}
	}

	return nil
}

// rateInfo provides statistics about the receive or transmit rate of
// an interface.
type rateInfo struct {
	// Bitrate in bits per second.
	Bitrate int
}

// parseRateInfo parses a rateInfo from netlink attributes.
func parseRateInfo(b []byte) (*rateInfo, error) {
	attrs, err := netlink.UnmarshalAttributes(b)
	if err != nil {
		return nil, err
	}

	var info rateInfo
	for _, a := range attrs {
		switch a.Type {
		case nl80211.RateInfoBitrate32:
			info.Bitrate = int(nlenc.Uint32(a.Data))
		}

		// Only use 16-bit counters if the 32-bit counters are not present.
		// If the 32-bit counters appear later in the slice, they will overwrite
		// these values.
		if info.Bitrate == 0 && a.Type == nl80211.RateInfoBitrate {
			info.Bitrate = int(nlenc.Uint16(a.Data))
		}
	}

	// Scale bitrate to bits/second as base unit instead of 100kbits/second.
	// * @NL80211_RATE_INFO_BITRATE: total bitrate (u16, 100kbit/s)
	info.Bitrate *= 100 * 1000

	return &info, nil
}

func parseScan(msgs []genetlink.Message) (*ScanResult, error) {
	ret := &ScanResult{}

	for _, m := range msgs {
		attrs, err := netlink.UnmarshalAttributes(m.Data)
		if err != nil {
			return nil, err
		}

		for _, a := range attrs {
			switch a.Type {
			case nl80211.AttrIfindex:
				ret.IfIndex = uint32(nlenc.Uint32(a.Data))
			case nl80211.AttrWiphy:
				ret.Wiphy = uint32(nlenc.Uint32(a.Data))
			case nl80211.AttrScanFrequencies:
				nestattrs, err := netlink.UnmarshalAttributes(a.Data)
				if err != nil {
					return nil, err
				}
				for _, freq := range nestattrs {
					ret.Frequencies = append(ret.Frequencies, uint32(nlenc.Uint32(freq.Data)))
				}
			case nl80211.AttrScanSsids:
				nestattrs, err := netlink.UnmarshalAttributes(a.Data)
				if err != nil {
					return nil, err
				}
				for _, ssid := range nestattrs {
					ret.SSIDs = append(ret.SSIDs, decodeSSID(ssid.Data))
				}
			case nl80211.AttrWdev:
				ret.Wdev = uint64(nlenc.Uint64(a.Data))
			}
		}
	}

	return ret, nil
}

// attrsContain checks if a slice of netlink attributes contains an attribute
// with the specified type.
func attrsContain(attrs []netlink.Attribute, typ uint16) bool {
	for _, a := range attrs {
		if a.Type == typ {
			return true
		}
	}

	return false
}

// decodeSSID safely parses a byte slice into UTF-8 runes, and returns the
// resulting string from the runes.
func decodeSSID(b []byte) string {
	buf := bytes.NewBuffer(nil)
	for len(b) > 0 {
		r, size := utf8.DecodeRune(b)
		b = b[size:]

		buf.WriteRune(r)
	}

	return buf.String()
}

var _ genl = &sysGENL{}

// sysGENL is the system implementation of genl, using generic netlink.
type sysGENL struct {
	*genetlink.Conn
}

// GetFamily is a small adapter to make *genetlink.Conn implement genl.
func (g *sysGENL) GetFamily(name string) (genetlink.Family, error) {
	return g.Conn.Family.Get(name)
}
