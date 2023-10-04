package ucdMib

import (
	"log"
	"os"

	"github.com/eriksejr/GoSNMPServer"
)

func init() {
	g_Logger = log.New(os.Stdout, "ucdMib", 0)
}

var g_Logger *log.Logger

// SetupLogger Setups Logger for this mib
func SetupLogger(i *log.Logger) {
	g_Logger = i
}

// All function provides a list of common used OID in UCD-MIB
func All() []*GoSNMPServer.PDUValueControlItem {
	var result []*GoSNMPServer.PDUValueControlItem
	result = append(result, MemoryOIDs()...)
	result = append(result, SystemStatsOIDs()...)
	result = append(result, SystemLoadOIDs()...)
	result = append(result, DiskUsageOIDs()...)
	return result

}
