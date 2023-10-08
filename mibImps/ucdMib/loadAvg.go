package ucdMib

import (
	"fmt"

	"github.com/eriksejr/GoSNMPServer"
	"github.com/gosnmp/gosnmp"
	"github.com/shirou/gopsutil/load"
)

// SystemLoadOIDs Returns a list of system Load.
//
//	see http://www.net-snmp.org/docs/mibs/ucdavis.html#DisplayString
func SystemLoadOIDs() []*GoSNMPServer.PDUValueControlItem {
	return []*GoSNMPServer.PDUValueControlItem{
		// laIndex
		{
			OID:   "1.3.6.1.4.1.2021.10.1.1.1",
			Type:  gosnmp.Integer,
			OnGet: func() (value interface{}, err error) { return GoSNMPServer.Asn1IntegerWrap(1), nil },
		},
		// laNames
		{
			OID:   "1.3.6.1.4.1.2021.10.1.2.1",
			Type:  gosnmp.OctetString,
			OnGet: func() (value interface{}, err error) { return GoSNMPServer.Asn1OctetStringWrap("Load-1"), nil },
		},
		// laLoad(float->OctetString)
		{
			OID:  "1.3.6.1.4.1.2021.10.1.3.1",
			Type: gosnmp.OctetString,
			OnGet: func() (value interface{}, err error) {
				if val, err := load.Avg(); err != nil {
					return nil, err
				} else {
					return GoSNMPServer.Asn1OctetStringWrap(fmt.Sprintf("%v", val.Load1)), nil
				}
			},
		},
		// laLoadInt
		{
			OID:  "1.3.6.1.4.1.2021.10.1.5.1",
			Type: gosnmp.Integer,
			OnGet: func() (value interface{}, err error) {
				if val, err := load.Avg(); err != nil {
					return nil, err
				} else {
					return GoSNMPServer.Asn1IntegerWrap(int(val.Load1)), nil
				}
			},
		},
		/////  5Min
		// laIndex
		{
			OID:   "1.3.6.1.4.1.2021.10.1.1.2",
			Type:  gosnmp.Integer,
			OnGet: func() (value interface{}, err error) { return GoSNMPServer.Asn1IntegerWrap(2), nil },
		},
		// laNames
		{
			OID:   "1.3.6.1.4.1.2021.10.1.2.2",
			Type:  gosnmp.OctetString,
			OnGet: func() (value interface{}, err error) { return GoSNMPServer.Asn1OctetStringWrap("Load-5"), nil },
		},
		// laLoad(float->OctetString)
		{
			OID:  "1.3.6.1.4.1.2021.10.1.3.2",
			Type: gosnmp.OctetString,
			OnGet: func() (value interface{}, err error) {
				if val, err := load.Avg(); err != nil {
					return nil, err
				} else {
					return GoSNMPServer.Asn1OctetStringWrap(fmt.Sprintf("%v", val.Load5)), nil
				}
			},
		},
		// laLoadInt
		{
			OID:  "1.3.6.1.4.1.2021.10.1.5.2",
			Type: gosnmp.Integer,
			OnGet: func() (value interface{}, err error) {
				if val, err := load.Avg(); err != nil {
					return nil, err
				} else {
					return GoSNMPServer.Asn1IntegerWrap(int(val.Load5)), nil
				}
			},
		},
		/////  15 min
		// laIndex
		{
			OID:   "1.3.6.1.4.1.2021.10.1.1.3",
			Type:  gosnmp.Integer,
			OnGet: func() (value interface{}, err error) { return GoSNMPServer.Asn1IntegerWrap(3), nil },
		},
		// laNames
		{
			OID:   "1.3.6.1.4.1.2021.10.1.2.3",
			Type:  gosnmp.OctetString,
			OnGet: func() (value interface{}, err error) { return GoSNMPServer.Asn1OctetStringWrap("Load-15"), nil },
		},
		// laLoad(float->OctetString)
		{
			OID:  "1.3.6.1.4.1.2021.10.1.3.3",
			Type: gosnmp.OctetString,
			OnGet: func() (value interface{}, err error) {
				if val, err := load.Avg(); err != nil {
					return nil, err
				} else {
					return GoSNMPServer.Asn1OctetStringWrap(fmt.Sprintf("%v", val.Load15)), nil
				}
			},
		},
		// laLoadInt
		{
			OID:  "1.3.6.1.4.1.2021.10.1.5.3",
			Type: gosnmp.Integer,
			OnGet: func() (value interface{}, err error) {
				if val, err := load.Avg(); err != nil {
					return nil, err
				} else {
					return GoSNMPServer.Asn1IntegerWrap(int(val.Load15)), nil
				}
			},
		},
	}
}
