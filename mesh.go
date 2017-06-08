package wifi

import (
  "github.com/mdlayher/wifi/internal/nl80211"
)

type MeshParamDescr struct {
  Name string
  Attr int
  Size uint8
}

const (
  MeshParams = []MeshParamDescr {
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
