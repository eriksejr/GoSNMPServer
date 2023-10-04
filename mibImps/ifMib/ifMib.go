package ifMib

import (
	"log"
	"os"

	"github.com/eriksejr/GoSNMPServer"
)

func init() {
	g_Logger = log.New(os.Stdout, "ifMib", 0)
}

var g_Logger *log.Logger

// SetupLogger Setups Logger for this mib
func SetupLogger(i *log.Logger) {
	g_Logger = i
}

// All function provides a list of common used OID in IF-MIB
func All() []*GoSNMPServer.PDUValueControlItem {
	return NetworkOIDs()
}
