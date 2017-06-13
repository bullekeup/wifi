//+build linux

package wifi

import (
	"errors"
	"math"
	"net"
	"os"
	"time"
	"fmt"

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
	errInvalidAttr          = errors.New("invalid attribute or no attribute to parse")
	errInvalidIfType        = errors.New("invalid interface type")
)

var _ osClient = &client{}

// A client is the Linux implementation of osClient, which makes use of
// netlink, generic netlink, and nl80211 to provide access to WiFi device
// actions and statistics.
type client struct {
	c               genl
	familyID        uint16
	familyVersion   uint8
	groups          []genetlink.MulticastGroup
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
	Send(m genetlink.Message, family uint16, flags netlink.HeaderFlags) (netlink.Message, error)
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

func (c *client) JoinGroup(name string, ID uint32) error {
	err := c.c.JoinGroup(ID)
	if err != nil {
		return err
	}
	c.subscribedgrps[name] = ID
	return nil
}

func (c *client) LeaveGroup(name string) error {
	grpid, exists := c.subscribedgrps[name]
	if !exists || grpid == 0 {
		return nil
	}
	err := c.c.LeaveGroup(grpid)
	if err != nil {
		return err
	}
	delete(c.subscribedgrps, name)
	return nil
}

// Close closes the client's generic netlink connection.
func (c *client) Close() error {
	return c.c.Close()
}

func (c *client) forgeCommand(attrs []netlink.Attribute, cmd WiphyCommand) (genetlink.Message, error) {
	ret := genetlink.Message{
		Header : genetlink.Header{
			Command : cmd.Cmd,
			Version : c.familyVersion,
		},
	}
	if attrs != nil {
		b, err := netlink.MarshalAttributes(attrs)
		if err != nil {
			return ret, err
		}
		ret.Data = b
	}
	return ret, nil
}

func (c *client) Execute(attrs []netlink.Attribute, cmd WiphyCommand) ([]genetlink.Message, error) {
	req, err := c.forgeCommand(attrs, cmd)
	if err != nil {
		return nil, err
	}

	if len(cmd.McastGroups) > 0 {
		// Subscribe to groups config and scan to be able to retrieve when scan has ended
		// and results are available
		for _, grp := range cmd.McastGroups {
			if _, subsd := c.subscribedgrps[grp]; !subsd {
				grpid, err := c.ResolveGroupName(grp)
				if err != nil {
					return nil, err
				}
				err = c.JoinGroup(grp, grpid)
				if err != nil {
					return nil, err
				}
			}
		}
	}

	if !cmd.NoResponse {
		var msgs []genetlink.Message
		if len(cmd.McastGroups) > 0 {
			msgs, err = c.c.ExecuteNoSeqCheck(req, c.familyID, cmd.Flags)
			if cmd.Cmd == nl80211.CmdJoinMesh {
				fmt.Printf("Received command after join mesh: %s", cmd.String())
			}
			if err != nil {
				return nil, err
			}
		} else {
			msgs, err = c.c.Execute(req, c.familyID, cmd.Flags)
			if cmd.Cmd == nl80211.CmdJoinMesh {
				fmt.Printf("Received command after join mesh: %s", cmd.String())
			}
			if err != nil {
				return nil, err
			}
		}
		var check uint8
		if cmd.Response != 0 {
			check = cmd.Response
		} else {
			check = cmd.Cmd
		}
		if err := c.checkMessages(msgs, check); err != nil {
			return nil, err
		}
		return msgs, nil
	} else {
		// FIXME ! When NoResponse is set for cmds the kernel doesn't respond to normally but
		// may actually respond if an error is detected.
		// Unfortunately we can't detect it for now as the Receive() function is blocking
		// and changing it requires to much time for now...
		// So be positive and just expect things to go well :/
		_, err := c.c.Send(req, c.familyID, cmd.Flags)
		return nil, err
	}
}

func (c *client) Receive() ([]genetlink.Message, []netlink.Message, error) {
	return c.c.Receive()
}

// Interfaces requests that nl80211 return a list of all WiFi interfaces present
// on this system.
func (c *client) Interfaces() ([]*Interface, error) {
	// Ask nl80211 to dump a list of all WiFi interfaces
	cmd := WiphyCommand{
		Cmd : nl80211.CmdGetInterface,
		Response : nl80211.CmdNewInterface,
		Flags : netlink.HeaderFlagsRequest | netlink.HeaderFlagsDump,
	}

	msgs, err := c.Execute(nil, cmd)
	if err != nil {
		return nil, err
	}

	return parseInterfaces(msgs)
}

func attrInterfaceFlags(flags *InterfaceFlags) (netlink.Attribute, error) {
	var flattrs []netlink.Attribute
	var attr netlink.Attribute
	var flpl []byte
	var i uint16

	if flags == nil {
		return attr, errInvalidAttr
	}

	for i = 0; i < nl80211.MntrFlagMax; i++ {
		if flags.Flags[i] {
			flattrs = append(flattrs, netlink.Attribute{
				Type: i,
			})
		}
	}

	if len(flattrs) == 0 {
		return attr, errInvalidAttr
	}

	flb, err := netlink.MarshalAttributes(flattrs)
	if err != nil {
		return attr, err
	}
	flmsg := netlink.Message{
		Data : flb,
	}
	flpl, err = flmsg.MarshalBinary()
	if err != nil {
		return attr, err
	}

	attr = netlink.Attribute{
		Type : nl80211.AttrMntrFlags,
		Data : flpl,
	}
	return attr, nil
}

func (c *client) InterfaceAdd(iftype InterfaceType, ifname string,
	ifhwaddr net.HardwareAddr, flags *InterfaceFlags, dev WifiDevice) (*Interface, error) {

	phy := dev.Phy()

	attrs := []netlink.Attribute{
		{
			Type : nl80211.AttrWiphy,
			Data : nlenc.Uint32Bytes(uint32(phy)),
		},
		{
			Type : nl80211.AttrIfname,
			Data : nlenc.Bytes(ifname),
		},
		{
			Type : nl80211.AttrIftype,
			Data : nlenc.Uint32Bytes(uint32(iftype)),
		},
	}

	if flags != nil {
		attr, err := attrInterfaceFlags(flags)
		if err != nil {
			return nil, err
		}
		attrs = append(attrs, attr)
	}

	if len(ifhwaddr) == 6 {
		attrs = append(attrs, netlink.Attribute{
			Type : nl80211.AttrMac,
			Data : []byte(ifhwaddr),
		})
	}

	cmd := WiphyCommand{
		Cmd : nl80211.CmdNewInterface,
		Flags : netlink.HeaderFlagsRequest,
	}

	msgs, err := c.Execute(attrs, cmd)
	if err != nil {
		fmt.Printf("Failed to execute request !\n")
		return nil, err
	}

	ifs, err := parseInterfaces(msgs)
	if err != nil {
		return nil, err
	}
	return ifs[0], nil
}

// TODO: Kernel doesn't respond but sends a del info on if mcast
func (c *client) InterfaceDel(ifi *Interface) error {
	cmd := WiphyCommand{
		Cmd : nl80211.CmdDelInterface,
		Flags : netlink.HeaderFlagsRequest,
		McastGroups : []string{"config", "scan"},
	}

	_, err := c.Execute(ifi.idAttrs(), cmd)
	if err != nil {
		return err
	}

	for _, grp := range cmd.McastGroups {
		c.LeaveGroup(grp)
	}

	return nil
}

func (c *client) InterfaceMeshJoin(ifi *Interface, minfos *MeshBasicInfo,
	meshparams map[string]uint32) error {

	if ifi.Type != InterfaceTypeMeshPoint {
		return errInvalidIfType
	}

	cmd := WiphyCommand{
		Cmd : nl80211.CmdJoinMesh,
		Flags : netlink.HeaderFlagsRequest,
		NoResponse : true,
	}

	// First attribute : netdev index
	attrs := []netlink.Attribute{
		{
			Type : nl80211.AttrIfindex,
			Data : nlenc.Uint32Bytes(uint32(ifi.Index)),
		},
	}

	mbasica, err := attrMeshBasic(minfos)
	if err != nil {
		fmt.Printf("Failed to get mesh basic attrs\n")
		return err
	}
	attrs = append(attrs, mbasica...)

	if len(meshparams) > 0 {
		fmt.Printf("Parsing mesh parameters...\n")
		mparamsa, err := attrMeshParams(meshparams)
		if err != nil {
			return err
		}
		attrs = append(attrs, mparamsa)
	}

	msgs, err := c.Execute(attrs, cmd)
	if err != nil {
		return err
	}

	for _, m := range msgs {
		fmt.Printf("Received \n%v\n", m)
	}

	return nil
}

func attrMeshBasic(minfos *MeshBasicInfo) ([]netlink.Attribute, error) {
	attrs := []netlink.Attribute{
		{
			Type : nl80211.AttrMeshId,
			Data : nlenc.Bytes(minfos.MeshID),
		},
	}

	if minfos.Freq != 0 {
		attrs = append(attrs, netlink.Attribute{
			Type : nl80211.AttrWiphyFreq,
			Data : nlenc.Uint32Bytes(minfos.Freq),
		})
	}
	if minfos.Chanmode != "" {
		achan, err := ChanModeAttrs(minfos.Chanmode)
		if err != nil {
			fmt.Printf("Failed to get chan mode attrs !\n")
			return nil, err
		}
		attrs = append(attrs, achan...)
	}
	if len(minfos.Basicrates) > 0 {
		arates, err := BasicRatesAttr(minfos.Basicrates)
		if err != nil {
			fmt.Printf("Failed to get basic rates !\n")
			return nil, err
		}
		attrs = append(attrs, arates)
	}
	if minfos.Mcastrate > 0 {
		attrs = append(attrs, netlink.Attribute{
			Type : nl80211.AttrBeaconInterval,
			Data : nlenc.Uint32Bytes(minfos.Mcastrate),
		})
	}
	if minfos.Dtimperiod > 0 {
		attrs = append(attrs, netlink.Attribute{
			Type : nl80211.AttrDtimPeriod,
			Data : nlenc.Uint32Bytes(minfos.Dtimperiod),
		})
	}

	return attrs, nil
}

func attrMeshParams(mparams map[string]uint32) (netlink.Attribute, error) {
	var attr netlink.Attribute
	// Mesh params are also in a nested attribute
	mparattrs, err := MeshParamsAttrs(mparams)
	if err != nil {
		return attr, err
	}
	bmparattrs, err := netlink.MarshalAttributes(mparattrs)
	if err != nil {
		return attr, err
	}

	attr = netlink.Attribute{
		Type : nl80211.AttrMeshParams,
		Nested : true,
		Data : bmparattrs,
	}
	return attr, nil
}

func (c *client) InterfaceMeshLeave(ifi *Interface) error {

	if ifi.Type != InterfaceTypeMeshPoint {
		return errInvalidIfType
	}

	cmd := WiphyCommand{
		Cmd : nl80211.CmdLeaveMesh,
		Flags : netlink.HeaderFlagsRequest,
	}

	msgs, err := c.Execute(ifi.idAttrs(), cmd)
	if err != nil {
		return err
	}

	for _, m := range msgs {
		fmt.Printf("Received \n%v\n", m)
	}

	return nil
}

// TODO: Parse config used
func (c *client) InterfaceMeshGetConfig(ifi *Interface) error {
	if ifi.Type != InterfaceTypeMeshPoint {
		return errInvalidIfType
	}

	cmd := WiphyCommand{
		Cmd : nl80211.CmdGetMeshConfig,
		Flags : netlink.HeaderFlagsRequest,
	}

	msgs, err := c.Execute(ifi.idAttrs(), cmd)
	if err != nil {
		return err
	}

	for _, m := range msgs {
		fmt.Printf("\n\nNew mesh config response \n")
		fmt.Printf("  * Command : %d\n", m.Header.Command)
		fmt.Printf("  * Attributes :\n")
		attrs, err := netlink.UnmarshalAttributes(m.Data)
		if err != nil {
			continue
		}
		for _, attr := range attrs {
			fmt.Printf("  * *\n")
			fmt.Printf("  * * Type:    %d\n", attr.Type)
			fmt.Printf("  * * Length:  %d\n", attr.Length)
			fmt.Printf("  * * Data:    %v\n", attr.Data)
		}
	}

	return nil
}

func (c *client) InterfaceMeshGetParams(ifi *Interface) error {
	return c.InterfaceMeshGetConfig(ifi)
}

// BSS requests that nl80211 return the BSS for the specified Interface.
func (c *client) BSS(ifi *Interface) (*BSS, error) {
	cmd := WiphyCommand{
		Cmd : nl80211.CmdGetScan,
		Response : nl80211.CmdNewScanResults,
		Flags : netlink.HeaderFlagsRequest | netlink.HeaderFlagsDump,
	}

	msgs, err := c.Execute(ifi.idAttrs(), cmd)
	if err != nil {
		return nil, err
	}

	return parseBSS(msgs)
}

// StationInfo requests that nl80211 return station info for the specified
// Interface.
func (c *client) StationInfo(ifi *Interface) (*StationInfo, error) {
	cmd := WiphyCommand{
		Cmd : nl80211.CmdGetStation,
		Response : nl80211.CmdNewStation,
		Flags : netlink.HeaderFlagsRequest | netlink.HeaderFlagsDump,
	}

	msgs, err := c.Execute(ifi.idAttrs(), cmd)
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

	return parseStationInfo(msgs[0].Data)
}

// Scan request a new scan for available networks to the kernel.
// We must have subscribed to groups sending back scan triggered and results available
func (c *client) Scan(ifi *Interface) (*ScanResult, error) {
	cmd := WiphyCommand{
		Cmd : nl80211.CmdTriggerScan,
		Flags : netlink.HeaderFlagsRequest,
		McastGroups : []string{"config", "scan"},
	}

	// Execute the command
	msgs, err := c.Execute(ifi.idAttrs(), cmd)
	if err != nil {
		return nil, err
	}

	// Wait for scan results (first response is received as mcast response
	// and contain scan infos, see parseScan function)
	//TODO: Move this in a dedicated channel which parses available networks
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
	for _, grp := range cmd.McastGroups {
		c.LeaveGroup(grp)
	}

	// Request BSS results and parse them
	cmd = WiphyCommand{
		Cmd : nl80211.CmdGetScan,
		Response : nl80211.CmdNewScanResults,
		Flags : netlink.HeaderFlagsRequest | netlink.HeaderFlagsDump,
	}

	msgs, err = c.Execute(ifi.idAttrs(), cmd)
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

func (c *client) ProtocolFeatures() (uint32, error) {
	cmd := WiphyCommand{
		Cmd : nl80211.CmdGetProtocolFeatures,
		Flags : netlink.HeaderFlagsRequest,
	}

	msgs, err := c.Execute(nil, cmd)
	if err != nil {
		return 0, err
	}

	return parseProtocolFeatures(msgs)
}

func (c *client) Phys() ([]*Wiphy, error) {
	feat, err := c.ProtocolFeatures()
	if err != nil {
		return nil, err
	}

	if (feat & nl80211.ProtocolFeatureSplitWiphyDump) == 0 {
		return nil, errInvalidAttr
	}

	cmd := WiphyCommand{
		Cmd : nl80211.CmdGetWiphy,
		Response : nl80211.CmdNewWiphy,
		Flags : netlink.HeaderFlagsRequest | netlink.HeaderFlagsDump,
	}

	msgs, err := c.Execute(nil, cmd)
	if err != nil {
		return nil, err
	}

	return parseWiphys(msgs)
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
			ies, err := ParseIEs(a.Data)
			if err != nil {
				return err
			}

			// TODO(mdlayher): return more IEs if they end up being generally useful
			for _, ie := range ies {
				switch ie.ID {
				case ieSSID:
					b.SSID = ParseSSID(ie.Data)
				case ieMeshID:
					b.MBSS = true
					b.MeshID = ParseSSID(ie.Data)
				case ieSupportedRates:
					b.Ies.SupportedRates = ParseSupportedRates(ie.Data)
				case ieHtCapa:
					b.Ies.HtInfos = ParseHtInfos(ie.Data)
				case ieHtOper:
					b.Ies.HtOps = ParseHtOper(ie.Data)
				case ieVhtCapa:
					b.Ies.VhtInfos = ParseVhtInfos(ie.Data)
				case ieVhtOper:
					b.Ies.VhtOps = ParseVhtOps(ie.Data)
				case ieMeshConfig:
					b.Ies.MeshCfg = ParseMeshCfg(ie.Data)
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

func parseProtocolFeatures(msgs []genetlink.Message) (uint32, error) {
	for _, m := range msgs {
		attrs, err := netlink.UnmarshalAttributes(m.Data)
		if err != nil {
			return 0, err
		}

		for _, a := range attrs {
			switch a.Type {
			case nl80211.AttrProtocolFeatures:
				return uint32(nlenc.Uint32(a.Data)), nil
			}
		}
	}

	return 0, errInvalidAttr
}

func parseWiphys(msgs []genetlink.Message) ([]*Wiphy, error) {
	var ret []*Wiphy
	var wiphy *Wiphy = nil
	var band *WiphyBand = nil
	neg := -1
	for _, m := range msgs {
		attrs, err := netlink.UnmarshalAttributes(m.Data)
		if err != nil {
			return nil, err
		}
		for _, a := range attrs {
			switch a.Type {
			case nl80211.AttrWiphy:
				phyid := int(nlenc.Uint32(a.Data))
				if wiphy == nil || phyid != wiphy.ID {
					if wiphy != nil {
						ret = append(ret, wiphy)
					}
					wiphy = &Wiphy{
						ID : phyid,
					}
				}
			case nl80211.AttrWiphyName:
				wiphy.Name = nlenc.String(a.Data)
			case nl80211.AttrMaxNumScanSsids:
				wiphy.MaxNumScanSSIDs = nlenc.Uint8(a.Data)
			case nl80211.AttrMaxScanIeLen:
				wiphy.MaxScanIELen = nlenc.Uint16(a.Data)
			case nl80211.AttrMaxNumSchedScanSsids:
				wiphy.MaxNumSchedScanSSIDs = nlenc.Uint8(a.Data)
			case nl80211.AttrMaxMatchSets:
				wiphy.MaxMatchSets = nlenc.Uint8(a.Data)
			case nl80211.AttrMaxNumSchedScanPlans:
				wiphy.MaxNumSchedScanPlans = nlenc.Uint32(a.Data)
			case nl80211.AttrMaxScanPlanInterval:
				wiphy.MaxScanPlanInterval = nlenc.Uint32(a.Data)
			case nl80211.AttrMaxScanPlanIterations:
				wiphy.MaxScanPlanIterations = nlenc.Uint32(a.Data)
			case nl80211.AttrWiphyFragThreshold:
				frag := nlenc.Uint32(a.Data)
				if frag == uint32(neg) {
					continue
				}
				wiphy.FragThreshold = frag
			case nl80211.AttrWiphyRtsThreshold:
				rts := nlenc.Uint32(a.Data)
				if rts == uint32(neg) {
					continue
				}
				wiphy.RTSThreshold = rts
			case nl80211.AttrWiphyRetryShort:
				wiphy.RetryShort = nlenc.Uint8(a.Data)
			case nl80211.AttrWiphyRetryLong:
				wiphy.RetryLong = nlenc.Uint8(a.Data)
			case nl80211.AttrWiphyCoverageClass:
				wiphy.CoverageClass = nlenc.Uint8(a.Data)
			case nl80211.AttrWiphyAntennaAvailTx:
				wiphy.AntennaAvTX = nlenc.Uint32(a.Data)
			case nl80211.AttrWiphyAntennaAvailRx:
				wiphy.AntennaAvRX = nlenc.Uint32(a.Data)
			case nl80211.AttrWiphyAntennaTx:
				wiphy.AntennaCfTX = nlenc.Uint32(a.Data)
			case nl80211.AttrWiphyAntennaRx:
				wiphy.AntennaCfRX = nlenc.Uint32(a.Data)
			case nl80211.AttrSupportedIftypes:
				attrtypes, err := netlink.UnmarshalAttributes(a.Data)
				if err != nil {
					continue
				}
				for _, attrtype := range attrtypes {
					wiphy.SupportedIfType = append(wiphy.SupportedIfType, InterfaceType(attrtype.Type))
				}
			case nl80211.AttrSoftwareIftypes:
				attrtypes, err := netlink.UnmarshalAttributes(a.Data)
				if err != nil {
					continue
				}
				for _, attrtype := range attrtypes {
					wiphy.SoftwareIfType = append(wiphy.SupportedIfType, InterfaceType(attrtype.Type))
				}
			case nl80211.AttrSupportedCommands:
				attrcmds, err := netlink.UnmarshalAttributes(a.Data)
				if err != nil {
					continue
				}
				for _, attrcmd := range attrcmds {
					wiphy.SupportedCmds = append(wiphy.SupportedCmds, WiphyCommand{Cmd : attrcmd.Data[0],})
				}
			case nl80211.AttrCipherSuites:
				for i := 0; i < len(a.Data); i+=4 {
					wiphy.Ciphers = append(wiphy.Ciphers, CipherSuite(nlenc.Uint32(a.Data[i:i+4])))
				}
			case nl80211.AttrSupportIbssRsn:
				wiphy.IBSSRSN = true
			case nl80211.AttrRoamSupport:
				wiphy.Roaming = true
			case nl80211.AttrSupportApUapsd:
				wiphy.APUAPSD = true
			case nl80211.AttrTdlsSupport:
				wiphy.TDLS = true
			case nl80211.AttrWiphyBands:
				abands, err := netlink.UnmarshalAttributes(a.Data)
				if err != nil {
					continue
				}
				for _, aband := range abands {
					bandid := aband.Type
					if band == nil || bandid != band.ID {
						if band != nil {
							wiphy.Band = append(wiphy.Band, band)
						}
						band = &WiphyBand{
							ID : bandid,
						}
					}
					battrs, err := netlink.UnmarshalAttributes(aband.Data)
					if err != nil {
						continue
					}
					band.HtInfos = parseHtInfosAttrs(battrs)
					band.VhtInfos = parseVhtInfosAttrs(battrs)
				}
				if band != nil {
					wiphy.Band = append(wiphy.Band, band)
				}
			}
		}
	}
	if wiphy != nil {
		ret = append(ret, wiphy)
	}

	return ret, nil
}

func parseVhtInfosAttrs(attrs []netlink.Attribute) WiphyBandVhtInfos {
	VhtInfos := WiphyBandVhtInfos{}
	for _, battr := range attrs {
		switch battr.Type {
		case nl80211.BandAttrVhtCapa:
			VhtInfos.Capa = nlenc.Uint32(battr.Data)
		case nl80211.BandAttrVhtMcsSet:
			VhtInfos.MCSInfo = battr.Data
		}
	}
	return VhtInfos
}

func parseHtInfosAttrs(attrs []netlink.Attribute) WiphyBandHtInfos {
	HtInfos := WiphyBandHtInfos{}
	for _, battr := range attrs {
		switch battr.Type {
		case nl80211.BandAttrHtCapa:
			HtInfos.Capa = nlenc.Uint16(battr.Data)
		case nl80211.BandAttrHtAmpduFactor:
			HtInfos.AMPDUFactor = nlenc.Uint8(battr.Data)
		case nl80211.BandAttrHtAmpduDensity:
			HtInfos.AMPDUDensity = nlenc.Uint8(battr.Data)
		case nl80211.BandAttrHtMcsSet:
			if len(battr.Data) != 16 {
				continue
			}
			HtInfos.MCSInfo.MaxRxSuppDataRate = uint32((battr.Data[10] | ((battr.Data[11] & 0x03) <<8)))
			HtInfos.MCSInfo.TxMcsSetDefined = (battr.Data[12] & (1 << 0)) != 0
			HtInfos.MCSInfo.TxMcsSetEqual = (battr.Data[12] & (1 << 1)) == 0
			HtInfos.MCSInfo.TxMaxNumSpatialStreams = uint32(((battr.Data[12] >> 2) & 3) + 1)
			HtInfos.MCSInfo.TxUnequalModulation = (battr.Data[12] & (1 << 4)) != 0
			HtInfos.MCSInfo.RxMcsBitmask = battr.Data[0:10]
			// We must keep only 76 bits (9.5 bytes)
			HtInfos.MCSInfo.RxMcsBitmask[9] &= 0x0 << 4
		}
	}
	return HtInfos
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
					ret.SSIDs = append(ret.SSIDs, ParseSSID(ssid.Data))
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

var _ genl = &sysGENL{}

// sysGENL is the system implementation of genl, using generic netlink.
type sysGENL struct {
	*genetlink.Conn
}

// GetFamily is a small adapter to make *genetlink.Conn implement genl.
func (g *sysGENL) GetFamily(name string) (genetlink.Family, error) {
	return g.Conn.Family.Get(name)
}

func (fl InterfaceFlags) Set(flag int) error {
	if flag < 0 || flag > nl80211.MntrFlagMax {
		return errInvalidIfFlag
	}
	fl.Flags[flag] = true
	return nil
}

func (fl InterfaceFlags) Clear(flag int) error {
	if flag < 0 || flag > nl80211.MntrFlagMax {
		return errInvalidIfFlag
	}
	fl.Flags[flag] = false
	return nil
}
