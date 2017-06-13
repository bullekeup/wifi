package wifi

import (
  "unicode/utf8"
  "bytes"
)

func ParseMeshCfg(barr []byte) MeshCfg {
	ret := MeshCfg{}
	ret.PathSeleProtoID = barr[0]
	ret.PathSeleProtoMetricID = barr[1]
	ret.CongestCtrlModeID = barr[2]
	ret.SyncMethodID = barr[3]
	ret.AuthProtoID = barr[4]
	ret.MeshFormationInfo = uint16(barr[5]) | (uint16(barr[6]) << 8)
	return ret
}

func ParseVhtOps(barr []byte) WiphyBandVhtOps {
	ret := WiphyBandVhtOps{}
	ret.ChanWidth = barr[0]
	ret.CtrFreqSeg1 = barr[1]
	ret.CtrFreqSeg2 = barr[2]
	ret.BasicMcsSet = uint16(barr[3]) | (uint16(barr[4]) << 8)
	return ret
}

func ParseVhtInfos(barr []byte) WiphyBandVhtInfos {
	ret := WiphyBandVhtInfos{}
	ret.Capa = uint32(barr[0]) | (uint32(barr[1]) << 8) | (uint32(barr[2]) << 16) | (uint32(barr[3]) << 24)
	ret.MCSInfo = barr[4:]
	return ret
}

func ParseHtOper(barr []byte) WiphyBandHtOps {
	ret := WiphyBandHtOps{}
	ret.PrimaryChan = barr[0]
	ret.SecondaryChanOffset = barr[1] & 0x03
	ret.STAChanWidth = (barr[1] & 0x04) >> 2
	ret.RIFS = (barr[1] & 0x08) >> 3
	ret.HTProtection = barr[2] & 0x03
	ret.NonGFPresent = (barr[2] & 0x04) >> 2
	ret.OBSSNonGFPresent = (barr[2] & 0x10) >> 4
	ret.DualBeacon = (barr[4] & 0x40) >> 6
	ret.DualCTSProtection = (barr[4] & 0x80) >> 7
	ret.STBCBeacon = barr[5] & 0x01
	ret.LSIGTXOPProt = (barr[5] & 0x02) >> 1
	ret.PCOActive = (barr[5] & 0x04) >> 2
	ret.PCOPhase = (barr[5] & 0x08) >> 3
	return ret
}

func ParseSupportedRates(barr []byte) []byte {
	var ret []byte
	for _, b := range barr {
		ret = append(ret, b & 0x7f)
	}
	return ret
}

// ParseIEs parses zero or more ies from a byte slice.
// Reference:
//   https://www.safaribooksonline.com/library/view/80211-wireless-networks/0596100523/ch04.html#wireless802dot112-CHP-4-FIG-31
func ParseIEs(b []byte) ([]ie, error) {
	var ies []ie
	var i int
	for {
		if len(b[i:]) == 0 {
			break
		}
		if len(b[i:]) < 2 {
			return nil, errInvalidIE
		}

		id := b[i]
		i++
		l := int(b[i])
		i++

		if len(b[i:]) < l {
			return nil, errInvalidIE
		}

		ies = append(ies, ie{
			ID:   id,
			Data: b[i : i+l],
		})

		i += l
	}

	return ies, nil
}

// ParseSSID safely parses a byte slice into UTF-8 runes, and returns the
// resulting string from the runes.
func ParseSSID(b []byte) string {
	buf := bytes.NewBuffer(nil)
	for len(b) > 0 {
		r, size := utf8.DecodeRune(b)
		b = b[size:]

		buf.WriteRune(r)
	}

	return buf.String()
}

func ParseHtInfos(data []byte) WiphyBandHtInfos {
	HtInfos := WiphyBandHtInfos{
		Capa : uint16(data[0]) | (uint16(data[1]) << 8),
		AMPDUFactor : data[2] & 0x03,
		AMPDUDensity : ((data[2] >> 2) & 0x07),
	}
	rawMCS := data[3:]
	HtInfos.MCSInfo.MaxRxSuppDataRate = uint32((rawMCS[10] | ((rawMCS[11] & 0x03) <<8)))
	HtInfos.MCSInfo.TxMcsSetDefined = (rawMCS[12] & (1 << 0)) != 0
	HtInfos.MCSInfo.TxMcsSetEqual = (rawMCS[12] & (1 << 1)) == 0
	HtInfos.MCSInfo.TxMaxNumSpatialStreams = uint32(((rawMCS[12] >> 2) & 3) + 1)
	HtInfos.MCSInfo.TxUnequalModulation = (rawMCS[12] & (1 << 4)) != 0
	HtInfos.MCSInfo.RxMcsBitmask = rawMCS[0:10]
	// We must keep only 76 bits (9.5 bytes)
	HtInfos.MCSInfo.RxMcsBitmask[9] &= 0x0F
	return HtInfos
}
