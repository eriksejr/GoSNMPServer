package ifMib

import (
	"encoding/hex"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/eriksejr/GoSNMPServer"
	"github.com/gosnmp/gosnmp"
	"github.com/pkg/errors"
	"github.com/shirou/gopsutil/net"
)

// NetworkOIDs Returns a list of network data.
//
//	see http://www.net-snmp.org/docs/mibs/interfaces.html
func NetworkOIDs() []*GoSNMPServer.PDUValueControlItem {
	toRet := []*GoSNMPServer.PDUValueControlItem{}
	valInterfaces, err := net.Interfaces()
	if err != nil {
		g_Logger.Printf("network ifs read failed. err=%v\n", err)
		return toRet
	}
	netifs := make(map[string]net.InterfaceStat)
	for _, val := range valInterfaces {
		netifs[val.Name] = val
	}
	vcounters, err := net.IOCounters(true)
	if err != nil {
		g_Logger.Printf("network IOCounters read failed. err=%v\n", err)
		return toRet
	}
	for ifIndex, val := range vcounters {
		targetIf := netifs[val.Name]
		ifName := val.Name
		ifHWAddr := targetIf.HardwareAddr
		currentIf := []*GoSNMPServer.PDUValueControlItem{
			// ifIndex
			{
				OID:   fmt.Sprintf("1.3.6.1.2.1.2.2.1.1.%d", ifIndex),
				Type:  gosnmp.Integer,
				OnGet: func() (value interface{}, err error) { return GoSNMPServer.Asn1IntegerWrap(ifIndex), nil },
			},
			// ifDescr
			{
				OID:   fmt.Sprintf("1.3.6.1.2.1.2.2.1.2.%d", ifIndex),
				Type:  gosnmp.OctetString,
				OnGet: func() (value interface{}, err error) { return GoSNMPServer.Asn1OctetStringWrap(ifName), nil },
			},
			// ifType
			{
				OID:  fmt.Sprintf("1.3.6.1.2.1.2.2.1.3.%d", ifIndex),
				Type: gosnmp.Integer,
				OnGet: func() (value interface{}, err error) {
					var gigabitEthernet = 117 // see  http://www.net-snmp.org/docs/mibs/interfaces.html#IANAifType
					//XXX: Let's assume all item is gigabitEthernet. /sys/class/net/eth0/type
					return GoSNMPServer.Asn1IntegerWrap(gigabitEthernet), nil
				},
			},
			// ifPhysAddress
			{
				OID:  fmt.Sprintf("1.3.6.1.2.1.2.2.1.6.%d", ifIndex),
				Type: gosnmp.OctetString,
				OnGet: func() (value interface{}, err error) {
					targetStr := strings.Replace(ifHWAddr, ":", "", -1)
					decoded, err := hex.DecodeString(targetStr)
					if err != nil {
						return nil, err
					}
					return GoSNMPServer.Asn1OctetStringWrap(string(decoded)), nil
				},
			},
			// ifInOctets
			{
				OID:  fmt.Sprintf("1.3.6.1.2.1.2.2.1.10.%d", ifIndex),
				Type: gosnmp.Counter32,
				OnGet: func() (value interface{}, err error) {
					vid, err := getNetworkStatsByName(ifName, ifIndex)
					if err != nil {
						return nil, err
					}
					return GoSNMPServer.Asn1Counter32Wrap(uint(vid.BytesRecv)), nil
				},
			},
			// ifInUcastPkts
			{
				OID:  fmt.Sprintf("1.3.6.1.2.1.2.2.1.11.%d", ifIndex),
				Type: gosnmp.Counter32,
				OnGet: func() (value interface{}, err error) {
					vid, err := getNetworkStatsByName(ifName, ifIndex)
					if err != nil {
						return nil, err
					}
					return GoSNMPServer.Asn1Counter32Wrap(uint(vid.PacketsRecv)), nil
				},
			},
			// ifInDiscards
			{
				OID:  fmt.Sprintf("1.3.6.1.2.1.2.2.1.13.%d", ifIndex),
				Type: gosnmp.Counter32,
				OnGet: func() (value interface{}, err error) {
					vid, err := getNetworkStatsByName(ifName, ifIndex)
					if err != nil {
						return nil, err
					}
					return GoSNMPServer.Asn1Counter32Wrap(uint(vid.Dropin)), nil
				},
			},
			// ifInerrors
			{
				OID:  fmt.Sprintf("1.3.6.1.2.1.2.2.1.14.%d", ifIndex),
				Type: gosnmp.Counter32,
				OnGet: func() (value interface{}, err error) {
					vid, err := getNetworkStatsByName(ifName, ifIndex)
					if err != nil {
						return nil, err
					}
					return GoSNMPServer.Asn1Counter32Wrap(uint(vid.Errin)), nil
				},
			},
			// ifOutOctets
			{
				OID:  fmt.Sprintf("1.3.6.1.2.1.2.2.1.16.%d", ifIndex),
				Type: gosnmp.Counter32,
				OnGet: func() (value interface{}, err error) {
					vid, err := getNetworkStatsByName(ifName, ifIndex)
					if err != nil {
						return nil, err
					}
					return GoSNMPServer.Asn1Counter32Wrap(uint(vid.BytesSent)), nil
				},
			},
			// ifOutUcastPkts
			{
				OID:  fmt.Sprintf("1.3.6.1.2.1.2.2.1.17.%d", ifIndex),
				Type: gosnmp.Counter32,
				OnGet: func() (value interface{}, err error) {
					vid, err := getNetworkStatsByName(ifName, ifIndex)
					if err != nil {
						return nil, err
					}
					return GoSNMPServer.Asn1Counter32Wrap(uint(vid.PacketsSent)), nil
				},
			},
			// ifOutDiscards
			{
				OID:  fmt.Sprintf("1.3.6.1.2.1.2.2.1.19.%d", ifIndex),
				Type: gosnmp.Counter32,
				OnGet: func() (value interface{}, err error) {
					vid, err := getNetworkStatsByName(ifName, ifIndex)
					if err != nil {
						return nil, err
					}
					return GoSNMPServer.Asn1Counter32Wrap(uint(vid.Dropout)), nil
				},
			},
			// ifOutErrors
			{
				OID:  fmt.Sprintf("1.3.6.1.2.1.2.2.1.20.%d", ifIndex),
				Type: gosnmp.Counter32,
				OnGet: func() (value interface{}, err error) {
					vid, err := getNetworkStatsByName(ifName, ifIndex)
					if err != nil {
						return nil, err
					}
					return GoSNMPServer.Asn1Counter32Wrap(uint(vid.Errout)), nil
				},
			},
		}
		appendLinuxPlatformNetworks(&currentIf, ifName, ifIndex)
		toRet = append(toRet, currentIf...)
	}
	return toRet
}

func getNetworkStatsByName(name string, hintid int) (net.IOCountersStat, error) {
	vcounters, err := net.IOCounters(true)
	if err != nil {
		return net.IOCountersStat{}, err
	}
	if hintid < len(vcounters) && vcounters[hintid].Name == name {
		return vcounters[hintid], nil
	}
	for _, each := range vcounters {
		if each.Name == name {
			return each, nil
		}
	}
	return net.IOCountersStat{}, errors.Errorf("Not Find eth %v", name)
}

func appendLinuxPlatformNetworks(io *[]*GoSNMPServer.PDUValueControlItem, ifName string, ifIndex int) {
	if runtime.GOOS != "linux" {
		return
	}
	toAppend := []*GoSNMPServer.PDUValueControlItem{
		// ifAdminStatus
		{
			OID:  fmt.Sprintf("1.3.6.1.2.1.2.2.1.7.%d", ifIndex),
			Type: gosnmp.Integer,
			OnGet: func() (value interface{}, err error) {
				adminstatus_up := 1
				adminstatus_down := 2
				_, err = os.ReadFile(fmt.Sprintf("/sys/class/net/%s/carrier", ifName))
				if err != nil {
					return GoSNMPServer.Asn1IntegerWrap(int(adminstatus_down)), nil
				}
				return GoSNMPServer.Asn1IntegerWrap(adminstatus_up), nil
			},
		},
		// ifOperStatus
		{
			OID:  fmt.Sprintf("1.3.6.1.2.1.2.2.1.8.%d", ifIndex),
			Type: gosnmp.Integer,
			OnGet: func() (value interface{}, err error) {
				str_num := map[string]int{
					"up":             1,
					"down":           2,
					"testing":        3,
					"unknown":        4,
					"dormant":        5,
					"notPresent":     6,
					"lowerLayerDown": 7,
				}
				bTs, err := os.ReadFile(fmt.Sprintf("/sys/class/net/%s/operstate", ifName))
				if err != nil {
					return nil, err
				}
				bTString := string(bTs)
				if val, ok := str_num[bTString]; ok {
					return GoSNMPServer.Asn1IntegerWrap(int(val)), nil
				} else {
					g_Logger.Printf("get ifOperStatus: unknown operstate %v\n", bTString)
					return GoSNMPServer.Asn1IntegerWrap(int(0)), nil
				}
			},
		},
	}
	*io = append(*io, toAppend...)
}
