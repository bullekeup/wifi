
package wifi

import (
	"bytes"
	"fmt"
	"github.com/mdlayher/netlink"
  "github.com/mdlayher/wifi/internal/nl80211"
)

type CipherSuite uint32

const (
	Cipher_WEP40 = 0x000fac01
	Cipher_TKIP = 0x000fac02
	Cipher_CCMP_128 = 0x000fac04
	Cipher_WEP104 = 0x000fac05
	Cipher_CMAC = 0x000fac06
	Cipher_GCMP_128 = 0x000fac08
	Cipher_GCMP_256 = 0x000fac09
	Cipher_CCMP_256 = 0x000fac10
	Cipher_WPISMS4 = 0x00147201
)

func (c CipherSuite) String() string {
	switch c {
	case Cipher_WEP40:
		return "WEP40      (00-0f-ac:1)"
	case Cipher_TKIP:
		return "TKIP       (00-0f-ac:2)"
	case Cipher_CCMP_128:
		return "CCMP-128   (00-0f-ac:4)"
	case Cipher_WEP104:
		return "WEP104     (00-0f-ac:5)"
	case Cipher_CMAC:
		return "CMAC       (00-0f-ac:6)"
	case Cipher_GCMP_128:
		return "GCMP-128   (00-0f-ac:8)"
	case Cipher_GCMP_256:
		return "GCMP-256   (00-0f-ac:9)"
	case Cipher_CCMP_256:
		return "CCMP-256   (00-0f-ac:10)"
	case Cipher_WPISMS4:
		return "WPI-SMS4   (00-14-72:1)"
	default:
		return fmt.Sprintf("unknown    (%.2x-%.2x-%.2x:%d)", uint32(c >> 24),
		uint32((c >> 16) & 0xff), uint32((c >> 8) & 0xff), uint32(c & 0xff))
	}
}

type AKMSuite uint32

const (
	PMKSA_1X = 0x000fac01
	PSK = 0x000fac02
	FT_1X = 0x000fac03
	FT_PSK = 0x000fac04
	PMKSA_1X_SHA256 = 0x000fac05
	PSK_SHA256 = 0x000fac06
	TDLS_TPK = 0x000fac07
	SAE = 0x000fac08
	FT_SAE_SHA256 = 0x000fac09
)

type WiphyCommand struct {
	Cmd uint8
	Response uint8
	Flags netlink.HeaderFlags
	McastGroups []string
	NoResponse bool
}

// TODO: complete that
func (c WiphyCommand) String() string {
	switch c.Cmd {
	case nl80211.CmdNewInterface:
		return "new_interface"
	case nl80211.CmdSetInterface:
		return "set_interface"
	case nl80211.CmdNewKey:
		return "new_key"
  case nl80211.CmdStartAp:
    return "start_ap"
  case nl80211.CmdNewStation:
    return "new_station"
	default:
		return fmt.Sprintf("unknown cmd (%d)", c.Cmd)
	}
}

//TODO: Use theses structs
type WiphyFreq struct {
	Freq uint32
	MaxTXPow uint32
	NoIr bool
	NoIBSS bool
	PassiveScan bool
	Radar bool
	DfsState uint32
	DfsTime uint32
	DfsCacTime uint32
}

type WiphyBitrate struct {
	Rate float32
	ShortPreamb bool
}

type WiphyBandHtOps struct {
	PrimaryChan uint8
	SecondaryChanOffset uint8
	STAChanWidth uint8
	RIFS uint8
	HTProtection uint8
	NonGFPresent uint8
	OBSSNonGFPresent uint8
	DualBeacon uint8
	DualCTSProtection uint8
	STBCBeacon uint8
	LSIGTXOPProt uint8
	PCOActive uint8
	PCOPhase uint8
}

type WiphyBandHtMcs struct {
  MaxRxSuppDataRate uint32
  TxMcsSetDefined bool
  TxMcsSetEqual bool
  TxMaxNumSpatialStreams uint32
  TxUnequalModulation bool
  RxMcsBitmask []byte
}

type WiphyBandHtInfos struct {
	Capa uint16
	AMPDUFactor uint8		// parsed with print_ampdu_length in iw
	AMPDUDensity uint8  // parsed with print_ampdu_spacing in iw
	MCSInfo WiphyBandHtMcs // parsed with print_ht_mcs in iw
}

type WiphyBandVhtOps struct {
	ChanWidth uint8
	CtrFreqSeg1 uint8
	CtrFreqSeg2 uint8
	BasicMcsSet uint16
}

type WiphyBandVhtInfos struct {
	Capa uint32
	MCSInfo []byte
}

type WiphyBand struct {
  ID uint16
	HtInfos WiphyBandHtInfos
	VhtInfos WiphyBandVhtInfos
}

//TODO: Add WoWlan, combinations, HT - VHT, Feature flags, Ext features, Coalesce rule support
type Wiphy struct {
	ID int
	Name string
	MaxNumScanSSIDs uint8
	MaxScanIELen uint16
	MaxNumSchedScanSSIDs uint8
	MaxMatchSets uint8
	MaxNumSchedScanPlans uint32
	MaxScanPlanInterval uint32
	MaxScanPlanIterations uint32
	FragThreshold uint32
	RTSThreshold uint32
	RetryShort uint8
	RetryLong uint8
	CoverageClass uint8
	Ciphers []CipherSuite
	AntennaAvTX uint32
	AntennaAvRX uint32
	AntennaCfTX uint32
	AntennaCfRX uint32
	SupportedIfType []InterfaceType
	SoftwareIfType []InterfaceType
	SupportedCmds []WiphyCommand
	SupportedTXFrames map[InterfaceType]uint16   // Unparsed
	SupportedRXFrames map[InterfaceType]uint16   // Unparsed
	IBSSRSN bool
	Roaming bool
	APUAPSD bool
	TDLS bool
  Band []*WiphyBand
}

func (phy *Wiphy) String() string {
	var buffer bytes.Buffer

  buffer.WriteString(fmt.Sprintf("Phy #%d (%s)\n", phy.ID, phy.Name))

  return buffer.String()
}

func (phy *Wiphy) Phy() int {
	return phy.ID
}

type WifiDevice interface {
	Phy() int
}
