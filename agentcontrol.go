package GoSNMPServer

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"io"
	"log"
	"reflect"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/pkg/errors"
)

type EnabledVersion uint8

const (
	SNMPV1 EnabledVersion = 1 << iota
	SNMPV2c
	SNMPV3
)

type FuncGetAuthoritativeEngineTime func() uint32

// MasterAgent identifies software which runs on managed devices
//
//	One server (port) could ONLY have one MasterAgent
type MasterAgent struct {
	SecurityConfig SecurityConfig

	SubAgents []*SubAgent

	Logger *log.Logger

	AllowedVersion EnabledVersion

	CreateTime time.Time

	priv struct {
		communityToSubAgent map[string]*SubAgent
		defaultSubAgent     *SubAgent
	}
}

type SecurityConfig struct {
	NoSecurity bool

	// AuthoritativeEngineID is SNMPV3 AuthoritativeEngineID
	AuthoritativeEngineID SNMPEngineID
	// AuthoritativeEngineBoots is SNMPV3 AuthoritativeEngineBoots
	AuthoritativeEngineBoots uint32
	// OnGetAuthoritativeEngineTime will be called to get SNMPV3 AuthoritativeEngineTime
	//      if sets to nil, the sys boottime will be used
	OnGetAuthoritativeEngineTime FuncGetAuthoritativeEngineTime

	Users []gosnmp.UsmSecurityParameters
}

func (v *SecurityConfig) FindForUser(name string) *gosnmp.UsmSecurityParameters {
	if v.Users == nil {
		return nil
	}
	for item := range v.Users {
		if v.Users[item].UserName == name {
			return &v.Users[item]
		}
	}
	return nil
}

type SNMPEngineID struct {
	// See https://tools.ietf.org/html/rfc3411#section-5
	// 			SnmpEngineID ::= TEXTUAL-CONVENTION
	//      SYNTAX       OCTET STRING (SIZE(5..32))
	PEN uint32

	EngineIDData string
}

func (t *SNMPEngineID) Marshal() []byte {
	// msgAuthoritativeEngineID: 80004fb8054445534b544f502d4a3732533245343ab63bc8
	// 1... .... = Engine ID Conformance: RFC3411 (SNMPv3)
	// Engine Enterprise ID: pysnmp (20408) - used if no PEN specified
	// Engine ID Format: Octets, administratively assigned (5)
	// Engine ID Data: 4445534b544f502d4a3732533245343ab63bc8

	engineIdPrefix := make([]byte, 4)
	// Use the PEN for the first 4 octets as per RFC3411
	pen := t.PEN
	// Set the first bit to 1 to indicate RFC3411 method
	pen |= 1 << 31
	// Convert this uint32 to []byte via the binary package
	binary.BigEndian.PutUint32(engineIdPrefix, pen)
	// Append the engine ID format info to the slice, in this
	// case we will use Octets, administratively assigned (5) per
	// RFC 3411
	engineIdPrefix = append(engineIdPrefix, 0x05)
	tm := make([]byte, hex.EncodedLen(len(engineIdPrefix)))
	hex.Encode(tm, engineIdPrefix)
	// Append the remaining engine ID data
	toAppend := []byte(t.EngineIDData)
	maxDefineallowed := 32 - 5
	if len(toAppend) > maxDefineallowed { //Max 32 bytes
		toAppend = toAppend[:maxDefineallowed]
	}
	tm = append(tm, toAppend...)
	return tm
}

func (t *MasterAgent) syncAndCheck() error {
	if len(t.SubAgents) == 0 {
		return errors.WithStack(errors.Errorf("MasterAgent shell have at least one SubAgents"))
	}
	if t.SecurityConfig.NoSecurity && len(t.SubAgents) != 1 {
		return errors.WithStack(errors.Errorf("NoSecurity MasterAgent shell have one one SubAgent"))
	}

	if t.Logger == nil {
		//Set New NIL Logger
		t.Logger = log.New(io.Discard, "", 0)
	}
	if t.CreateTime.IsZero() {
		t.CreateTime = time.Now()
	}
	if t.SecurityConfig.OnGetAuthoritativeEngineTime == nil {
		t.SecurityConfig.OnGetAuthoritativeEngineTime = func() uint32 {
			return uint32(time.Since(t.CreateTime).Seconds())
		}
	}
	if t.SecurityConfig.AuthoritativeEngineID.EngineIDData == "" {
		t.SecurityConfig.AuthoritativeEngineID = DefaultAuthoritativeEngineID()
	}
	return nil
}

func (t *MasterAgent) ReadyForWork() error {
	if err := t.syncAndCheck(); err != nil {
		return err
	}
	return t.SyncConfig()
}

func (t *MasterAgent) getUserNameFromRequest(request *gosnmp.SnmpPacket) string {
	var username string
	if val, ok := request.SecurityParameters.(*gosnmp.UsmSecurityParameters); !ok {
		panic(errors.WithMessagef(ErrUnsupportedPacketData, "GoSNMP .Unknown Type:%v", reflect.TypeOf(request.SecurityParameters)))
	} else {
		username = val.UserName
	}
	return username
}

func (t *MasterAgent) ResponseForBuffer(i []byte) ([]byte, error) {
	// Decode
	vhandle := gosnmp.GoSNMP{}
	vhandle.Logger = gosnmp.NewLogger(t.Logger)
	mb, _ := t.getUsmSecurityParametersFromUser("")
	vhandle.SecurityParameters = mb
	request, decodeError := vhandle.SnmpDecodePacket(i)

	if (request.Version == gosnmp.Version1) && (t.AllowedVersion&SNMPV1 != 0) {
		return t.marshalPkt(t.ResponseForPkt(request))
	} else if (request.Version == gosnmp.Version2c) && (t.AllowedVersion&SNMPV2c != 0) {
		return t.marshalPkt(t.ResponseForPkt(request))
	} else if (request.Version == gosnmp.Version3) && (t.AllowedVersion&SNMPV3 != 0) {
		// check for initial - discover response / non Privacy Items
		if decodeError == nil && len(request.Variables) == 0 {
			val, err := t.ResponseForPkt(request)

			if val == nil {
				return t.marshalPkt(request, err)
			} else {
				return t.marshalPkt(val, err)
			}
		}
		//v3 might want for Privacy
		if request.SecurityParameters == nil {
			return nil, errors.WithMessagef(ErrUnsupportedPacketData, "GoSNMP Returns %v", decodeError)
		}
		username := t.getUserNameFromRequest(request)
		usm, err := t.getUsmSecurityParametersFromUser(username)
		if err != nil {
			return nil, err
		}
		if decodeError != nil {
			t.Logger.Printf("v3 decode [will fail with non password] meet %v\n", err)
			vhandle.SecurityParameters = &gosnmp.UsmSecurityParameters{
				UserName:                 usm.UserName,
				AuthenticationProtocol:   usm.AuthenticationProtocol,
				PrivacyProtocol:          usm.PrivacyProtocol,
				AuthenticationPassphrase: usm.AuthenticationPassphrase,
				PrivacyPassphrase:        usm.PrivacyPassphrase,
				Logger:                   vhandle.Logger,
			}
			request, err = vhandle.SnmpDecodePacket(i)
			if err != nil {
				return nil, errors.WithMessagef(ErrUnsupportedPacketData, "GoSNMP Returns %v", err)
			}
		}

		val, err := t.ResponseForPkt(request)
		if val == nil {
			request.SecurityParameters = vhandle.SecurityParameters
			return t.marshalPkt(request, err)
		} else {
			securityParamters := usm
			GenKeys(securityParamters)
			GenSalt(securityParamters)
			val.SecurityParameters = securityParamters

			return t.marshalPkt(val, err)
		}
	} else {
		return nil, errors.WithStack(ErrUnsupportedProtoVersion)
	}
}

func (t *MasterAgent) marshalPkt(pkt *gosnmp.SnmpPacket, err error) ([]byte, error) {
	// when err. marshal error pkt
	if pkt == nil {
		pkt = &gosnmp.SnmpPacket{}
	}
	if err != nil {
		t.Logger.Printf("Will marshal: %v\n", err)

		errFill := t.fillErrorPkt(err, pkt)
		if errFill != nil {
			return nil, err
		}

		return pkt.MarshalMsg()
	}

	out, err := pkt.MarshalMsg()
	return out, err
}

func (t *MasterAgent) getUsmSecurityParametersFromUser(username string) (*gosnmp.UsmSecurityParameters, error) {
	if username == "" {
		return &gosnmp.UsmSecurityParameters{
			Logger:                   gosnmp.NewLogger(t.Logger),
			AuthoritativeEngineID:    string(t.SecurityConfig.AuthoritativeEngineID.Marshal()),
			AuthoritativeEngineBoots: t.SecurityConfig.AuthoritativeEngineBoots,
			AuthoritativeEngineTime:  t.SecurityConfig.OnGetAuthoritativeEngineTime(),
		}, nil

	}
	if val := t.SecurityConfig.FindForUser(username); val != nil {
		fval := val.Copy().(*gosnmp.UsmSecurityParameters)
		fval.Logger = gosnmp.NewLogger(t.Logger)
		fval.AuthoritativeEngineID = string(t.SecurityConfig.AuthoritativeEngineID.Marshal())
		fval.AuthoritativeEngineBoots = t.SecurityConfig.AuthoritativeEngineBoots
		fval.AuthoritativeEngineTime = t.SecurityConfig.OnGetAuthoritativeEngineTime()
		return fval, nil
	} else {
		return nil, errors.WithStack(ErrNoPermission)
	}

}

func (t *MasterAgent) fillErrorPkt(err error, io *gosnmp.SnmpPacket) error {
	io.PDUType = gosnmp.GetResponse
	if errors.Is(err, ErrNoSNMPInstance) {
		io.Error = gosnmp.NoAccess
	} else if errors.Is(err, ErrUnsupportedOperation) {
		io.Error = gosnmp.ResourceUnavailable
	} else if errors.Is(err, ErrNoPermission) {
		io.Error = gosnmp.AuthorizationError
	} else if errors.Is(err, ErrUnsupportedPacketData) {
		io.Error = gosnmp.BadValue
	} else {
		io.Error = gosnmp.GenErr
	}
	io.ErrorIndex = 0
	return nil
}

func (t *MasterAgent) ResponseForPkt(i *gosnmp.SnmpPacket) (*gosnmp.SnmpPacket, error) {
	// Find for which SubAgent
	community := getPktContextOrCommunity(i)
	subAgent := t.findForSubAgent(community)
	if subAgent == nil {
		return i, errors.WithStack(ErrNoSNMPInstance)
	}
	return subAgent.Serve(i)
}

func (t *MasterAgent) SyncConfig() error {
	t.priv.defaultSubAgent = nil
	t.priv.communityToSubAgent = make(map[string]*SubAgent)

	for id, current := range t.SubAgents {
		t.SubAgents[id].Logger = t.Logger
		t.SubAgents[id].master = t
		if err := t.SubAgents[id].SyncConfig(); err != nil {
			return err
		}

		if len(current.CommunityIDs) == 0 || t.SecurityConfig.NoSecurity {
			if t.priv.defaultSubAgent != nil {
				return errors.Errorf("SyncConfig: Config Error: duplicate default agent")
			}
			t.priv.defaultSubAgent = current
			continue
		}
		for _, val := range current.CommunityIDs {
			if _, exists := t.priv.communityToSubAgent[val]; exists {
				return errors.Errorf("SyncConfig: Config Error: duplicate value:%s", val)
			}
			t.Logger.Printf("communityToSubAgent: val=%v, current=%p\n", val, current)
			t.priv.communityToSubAgent[val] = current
		}

	}
	return nil
}

func (t *MasterAgent) findForSubAgent(community string) *SubAgent {
	if val, ok := t.priv.communityToSubAgent[community]; ok {
		return val
	} else {
		return t.priv.defaultSubAgent
	}
}

// NOTE: Using random data here really is *NOT* the proper way to do this
// as per RFC3411 the same SNMP Engine should always return the same SNMP
// engine ID
func RandomEngineIdData(length int) string {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		// This really shouldn't error
		panic(err)
	}
	return hex.EncodeToString(bytes)
}

func DefaultAuthoritativeEngineID() SNMPEngineID {
	return SNMPEngineID{
		PEN:          20408,
		EngineIDData: RandomEngineIdData(16),
	}
}
