package alicebob

import (
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/sanjit-bhat/pav/ktcore"
)

type blameInterp struct {
	code   ktcore.Blame
	interp string
}

// alertUser goes to end-user in real system.
func alertUser(t *testing.T, err ktcore.Blame, evid *ktcore.Evid) {
	t.Log(interpBlame(err))
	if evid != nil {
		t.Log("cryptographic evidence of mis-behavior. whisteblow by posting this publicly:", evid)
	}
}

func interpBlame(err ktcore.Blame) string {
	if err&ktcore.BlameUnknown != 0 {
		return "[ERROR]: unknown source"
	}
	parties := blameToString(err)
	return fmt.Sprintf("[ERROR]: %s suspect; if good, would not observe error", parties)
}

func blameToString(err ktcore.Blame) string {
	allInterps := []blameInterp{
		{ktcore.BlameServSig, "ServSig"},
		{ktcore.BlameServFull, "ServFull"},
		{ktcore.BlameAdtrSig, "AdtrSig"},
		{ktcore.BlameAdtrFull, "AdtrFull"},
		{ktcore.BlameClients, "Clients"},
	}

	var interps []string
	for _, x := range allInterps {
		if err&x.code != 0 {
			interps = append(interps, x.interp)
		}
	}
	return strings.Join(interps, " and ")
}

func TestAliceBob(t *testing.T) {
	if err, evid := testAliceBob(makeUniqueAddr(), makeUniqueAddr()); err != ktcore.BlameNone {
		t.Error()
		alertUser(t, err, evid)
	}
}

func getFreePort() (port uint64, err error) {
	var a *net.TCPAddr
	if a, err = net.ResolveTCPAddr("tcp", "localhost:0"); err == nil {
		var l *net.TCPListener
		if l, err = net.ListenTCP("tcp", a); err == nil {
			defer l.Close()
			return uint64(l.Addr().(*net.TCPAddr).Port), nil
		}
	}
	return
}

func makeUniqueAddr() uint64 {
	port, err := getFreePort()
	if err != nil {
		panic("bad port")
	}
	// left shift to make IP 0.0.0.0.
	return port << 32
}
