package wifi

import (
  "errors"
  "github.com/mdlayher/netlink"
  "github.com/mdlayher/netlink/nlenc"
  "github.com/mdlayher/wifi/internal/nl80211"
)

var (
  errInvalidChanMode = errors.New("invalid channel mode")
  errInvalidMeshParamSize = errors.New("invalid mesh param size")
)

type MeshBasicInfo struct {
  MeshID string
  Freq uint32
	Chanmode string
  Basicrates []uint8
  Mcastrate uint32
  Beaconinterval uint32
	Dtimperiod uint32
  Vendorsync bool
}

type MeshParamDescr struct {
  Name string
  Attr uint16
  Size uint8
}

var (
  MeshParams = [26]MeshParamDescr {
    {
      Name: "mesh_retry_timeout",
      Attr: nl80211.MeshconfRetryTimeout,
      Size: 2,
    },
    {
      Name: "mesh_confirm_timeout",
      Attr: nl80211.MeshconfConfirmTimeout,
      Size: 2,
    },
    {
      Name: "mesh_holding_timeout",
      Attr: nl80211.MeshconfHoldingTimeout,
      Size: 2,
    },
    {
      Name: "mesh_max_peer_links",
      Attr: nl80211.MeshconfMaxPeerLinks,
      Size: 2,
    },
    {
      Name: "mesh_max_retries",
      Attr: nl80211.MeshconfMaxRetries,
      Size: 1,
    },
    {
      Name: "mesh_ttl",
      Attr: nl80211.MeshconfTtl,
      Size: 1,
    },
    {
      Name: "mesh_element_ttl",
      Attr: nl80211.MeshconfElementTtl,
      Size: 1,
    },
    {
      Name: "mesh_auto_open_plinks",
      Attr: nl80211.MeshconfAutoOpenPlinks,
      Size: 1,
    },
    {
      Name: "mesh_hwmp_max_preq_retries",
      Attr: nl80211.MeshconfHwmpMaxPreqRetries,
      Size: 1,
    },
    {
      Name: "mesh_path_refresh_time",
      Attr: nl80211.MeshconfPathRefreshTime,
      Size: 4,
    },
    {
      Name: "mesh_min_discovery_timeout",
      Attr: nl80211.MeshconfMinDiscoveryTimeout,
      Size: 2,
    },
    {
      Name: "mesh_hwmp_active_path_timeout",
      Attr: nl80211.MeshconfHwmpActivePathTimeout,
      Size: 4,
    },
    {
      Name: "mesh_hwmp_preq_min_interval",
      Attr: nl80211.MeshconfHwmpPreqMinInterval,
      Size: 2,
    },
    {
      Name: "mesh_hwmp_net_diameter_traversal_time",
      Attr: nl80211.MeshconfHwmpNetDiamTrvsTime,
      Size: 2,
    },
    {
      Name: "mesh_hwmp_rootmode",
      Attr: nl80211.MeshconfHwmpRootmode,
      Size: 1,
    },
    {
      Name: "mesh_hwmp_rann_interval",
      Attr: nl80211.MeshconfHwmpRannInterval,
      Size: 2,
    },
    {
      Name: "mesh_gate_announcements",
      Attr: nl80211.MeshconfGateAnnouncements,
      Size: 1,
    },
    {
      Name: "mesh_fwding",
      Attr: nl80211.MeshconfForwarding,
      Size: 1,
    },
    {
      Name: "mesh_sync_offset_max_neighor",
      Attr: nl80211.MeshconfSyncOffsetMaxNeighbor,
      Size: 4,
    },
    {
      Name: "mesh_rssi_threshold",
      Attr: nl80211.MeshconfRssiThreshold,
      Size: 4,
    },
    {
      Name: "mesh_hwmp_active_path_to_root_timeout",
      Attr: nl80211.MeshconfHwmpPathToRootTimeout,
      Size: 4,
    },
    {
      Name: "mesh_hwmp_root_interval",
      Attr: nl80211.MeshconfHwmpRootInterval,
      Size: 2,
    },
    {
      Name: "mesh_hwmp_confirmation_interval",
      Attr: nl80211.MeshconfHwmpConfirmationInterval,
      Size: 2,
    },
    {
      Name: "mesh_power_mode",
      Attr: nl80211.MeshconfPowerMode,
      Size: 4,
    },
    {
      Name: "mesh_awake_window",
      Attr: nl80211.MeshconfAwakeWindow,
      Size: 2,
    },
    {
      Name: "mesh_plink_timeout",
      Attr: nl80211.MeshconfPlinkTimeout,
      Size: 4,
    },
  }
)

type ChanMode struct {
  Width uint32
  Freq1Diff uint32
  ChanType int
}

var (
  neg = -10
  chanModes = map[string]ChanMode{
    "5MHz" : {
      Width : nl80211.ChanWidth5,
      Freq1Diff : 0,
      ChanType : -1,
    },
    "10MHz" : {
      Width : nl80211.ChanWidth10,
      Freq1Diff : 0,
      ChanType : -1,
    },
    "HT20" : {
      Width : nl80211.ChanWidth20,
      Freq1Diff : 0,
      ChanType : nl80211.ChanHt20,
    },
    "HT40+" : {
      Width : nl80211.ChanWidth40,
      Freq1Diff : 10,
      ChanType : nl80211.ChanHt40plus,
    },
    "HT40-" : {
      Width : nl80211.ChanWidth40,
      Freq1Diff : uint32(neg),
      ChanType : nl80211.ChanHt40minus,
    },
    "NOHT" : {
      Width : nl80211.ChanWidth20Noht,
      Freq1Diff : 0,
      ChanType : nl80211.ChanNoHt,
    },
    "80MHz" : {
      Width : nl80211.ChanWidth80,
      Freq1Diff : 0,
      ChanType : -1,
    },
  }
  chanVHT80 = [6]uint32{5180, 5260, 5500, 5580, 5660, 5745,}
)

func (ch ChanMode) GetCF1(freq uint32) uint32 {
  if ch.Width == nl80211.ChanWidth80 {
    for i := 0; i < len(chanVHT80); i++ {
      if freq <= chanVHT80[i] && freq < (chanVHT80[i] + 80) {
        return chanVHT80[i] + 30
      }
    }
  }
  return freq + ch.Freq1Diff
}

func ChanModeAttrs(name string) ([]netlink.Attribute, error) {
  mode, exists := chanModes[name]
  if !exists {
    return nil, errInvalidChanMode
  }
  attrs := []netlink.Attribute{
    {
      Type : nl80211.AttrChannelWidth,
      Data : nlenc.Uint32Bytes(mode.Width),
    },
    {
      Type : nl80211.AttrCenterFreq1,
      Data : nlenc.Uint32Bytes(mode.GetCF1(mode.Freq1Diff)),
    },
  }
  if mode.ChanType != -1 {
    attrs = append(attrs, netlink.Attribute{
      Type : nl80211.AttrWiphyChannelType,
      Data : nlenc.Uint32Bytes(uint32(mode.ChanType)),
    })
  }
  return attrs, nil
}

func BasicRatesAttr(urates []uint8) (netlink.Attribute, error) {
  var rates []byte
  for _, rate := range urates {
    rates = append(rates, rate * 2)
  }
  if len(rates) > 0 {
    return netlink.Attribute{
      Type : nl80211.AttrBssBasicRates,
      Data : rates,
    }, nil
  }
  return netlink.Attribute{}, errInvalidAttr
}

func MeshParamsAttrs(inparams map[string]uint32) ([]netlink.Attribute, error) {
  var paramsattr []netlink.Attribute
  for _, param := range MeshParams {
    if inparam, exists := inparams[param.Name]; exists {
      var b []byte
      switch param.Size {
      case 1:
        b = []byte{uint8(inparam)}
      case 2:
        b = nlenc.Uint16Bytes(uint16(inparam))
      case 4:
        b = nlenc.Uint32Bytes(uint32(inparam))
      default:
        b = nil
      }
      if len(b) == 0 {
        return nil, errInvalidMeshParamSize
      }
      paramsattr = append(paramsattr, netlink.Attribute{
        Type : param.Attr,
        Data : b,
      })
    }
  }

  return paramsattr, nil
}
