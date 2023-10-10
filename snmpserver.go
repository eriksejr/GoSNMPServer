package GoSNMPServer

import (
	"log"
	"net"
	"reflect"

	"github.com/pkg/errors"
)

type SNMPServer struct {
	wconnStream ISnmpServerListener
	master      MasterAgent
	logger      *log.Logger
}

func NewSNMPServer(master MasterAgent) *SNMPServer {
	ret := new(SNMPServer)
	if err := master.ReadyForWork(); err != nil {
		panic(err)
	}
	ret.master = master
	ret.logger = master.Logger
	return ret
}

func (server *SNMPServer) ListenUDP(l3proto, address string) error {
	if server.wconnStream != nil {
		return errors.New("Listened")
	}
	i, err := NewUDPListener(l3proto, address)
	if err != nil {
		return err
	}
	server.logger.Printf("ListenUDP: l3proto=%s, address=%s\n", l3proto, address)
	i.SetupLogger(server.logger)
	server.wconnStream = i
	return nil
}

func (server *SNMPServer) Address() net.Addr {
	return server.wconnStream.Address()
}

func (server *SNMPServer) Shutdown() {
	server.logger.Println("Shutdown server")
	if server.wconnStream != nil {
		server.wconnStream.Shutdown()
	}
}

func (server *SNMPServer) ServeForever() error {
	if server.wconnStream == nil {
		return errors.New("Not Listen")
	}

	for {
		err := server.ServeNextRequest()
		if err != nil {
			var opError *net.OpError
			if errors.As(err, &opError) {
				server.logger.Printf("ServeForever: break because of serveNextRequest error %v\n", opError)
				return nil
			}

			server.logger.Printf("ServeForever: ServeNextRequest error %v [type %v]\n", err, reflect.TypeOf(err))
			return errors.Wrap(err, "ServeNextRequest")
		}
	}
}

func (server *SNMPServer) ServeNextRequest() (err error) {
	defer func() {
		if err := recover(); err != nil {
			switch err.(type) {
			case error:
				err = errors.Wrap(err.(error), "ServeNextRequest fails with panic")
			default:
				err = errors.Errorf("ServeNextRequest fails with panic. err(type %v)=%v", reflect.TypeOf(err), err)
			}
			server.logger.Printf("ServeNextRequest error: %+v\n", err)
			return
		}
	}()
	bytePDU, replyer, err := server.wconnStream.NextSnmp()
	if err != nil {
		return err
	}
	result, err := server.master.ResponseForBuffer(bytePDU)
	if err != nil {
		v := "with"
		if len(result) == 0 {
			v = "without"
		}
		server.logger.Printf("ResponseForBuffer Error: %v. %s result\n", err, v)
	}
	if len(result) != 0 {
		if errreply := replyer.ReplyPDU(result); errreply != nil {
			server.logger.Printf("Reply PDU meet err: %s\n", errreply)
			replyer.Shutdown()
			return nil
		}
	}
	if err != nil {
		replyer.Shutdown()
	}
	return nil
}
