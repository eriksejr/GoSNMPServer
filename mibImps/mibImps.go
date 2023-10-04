package mibImps

import (
	"log"
	"os"

	"github.com/eriksejr/GoSNMPServer"
	"github.com/eriksejr/GoSNMPServer/mibImps/dismanEventMib"
	"github.com/eriksejr/GoSNMPServer/mibImps/ifMib"
	"github.com/eriksejr/GoSNMPServer/mibImps/ucdMib"
)

func init() {
	g_Logger = log.New(os.Stdout, "mibImps", 0)
}

var g_Logger *log.Logger

// SetupLogger Setups Logger for All sub mibs.
func SetupLogger(i *log.Logger) {
	g_Logger = i
	dismanEventMib.SetupLogger(i)
	ifMib.SetupLogger(i)
	ucdMib.SetupLogger(i)
}

// All function provides a list of common used OID
//
//	includes part of ucdMib, ifMib, and dismanEventMib
func All() []*GoSNMPServer.PDUValueControlItem {
	toRet := []*GoSNMPServer.PDUValueControlItem{}
	toRet = append(toRet, dismanEventMib.All()...)
	toRet = append(toRet, ifMib.All()...)
	toRet = append(toRet, ucdMib.All()...)
	return toRet
}
