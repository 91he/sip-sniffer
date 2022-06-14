package main

/*
#include "nids.h"
int do_cap();

union Addr {
  char ip[4];
  int addr;
};
*/
import "C"

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"unsafe"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/pion/rtp/v2"
	"github.com/pion/sdp/v3"
)

type Invite struct {
	Addr uint32
	Port uint16
}

type Dialog struct {
	CallerData chan []byte
	CalleeData chan []byte
	fromID     string
	toID       string
	saddr      uint32
	daddr      uint32
	sport      uint16
	dport      uint16
	codec      string
	inDialog   bool
	ctx        context.Context
	cancel     context.CancelFunc
}

type DialogInfo struct {
	DialogID string
	First    bool
	FromID   string
	ToID     string
}

type AudioMediaInfo struct {
	Codec string
	Addr  uint32
	Port  uint16
}

var (
	saddr        uint32
	userFinder   = regexp.MustCompile("sip:(.+)@.*;tag=([^$;]+)")
	Invites      = map[string]*Invite{}
	Dialogs      = map[string]*Dialog{}
	Callers      = map[Invite]*Dialog{}
	Callees      = map[Invite]*Dialog{}
	nativeEndian binary.ByteOrder
)

func (d Dialog) MatchTuple(tuple *C.struct_tuple4) bool {
	return false
}

func (d *Dialog) Cancel() {
	d.cancel()
}

func (d Dialog) String() string {
	return fmt.Sprintf("{src=%v@%v:%v dst=%v@%v:%v codec=%v inDialog=%v}",
		d.fromID, ipFromAddr(d.saddr), d.sport,
		d.toID, ipFromAddr(d.daddr), d.dport,
		d.codec, d.inDialog)
}

func addrFromIP(ip string) (uint32, error) {
	var serverIP C.union_Addr
	tmp := ((*[31]byte)(unsafe.Pointer(&serverIP)))[:4:4]

	arr := strings.Split(ip, ".")
	for i, v := range arr {
		if x, err := strconv.Atoi(v); err != nil {
			return 0, err
		} else {
			tmp[i] = byte(x)
		}
	}

	return *(*uint32)(unsafe.Pointer(&serverIP)), nil
}

func ipFromAddr(addr uint32) string {
	var tmp [4]byte
	nativeEndian.PutUint32(tmp[:4:4], addr)
	//return fmt.Sprintf("%v.%v.%v.%v", (addr&0xff000000)>>24, (addr&0x00ff0000)>>16, (addr&0x0000ff00)>>8, addr&0x000000ff)
	return fmt.Sprintf("%v.%v.%v.%v", tmp[0], tmp[1], tmp[2], tmp[3])
}

func init() {
	buf := [2]byte{}
	*(*uint16)(unsafe.Pointer(&buf[0])) = uint16(0xABCD)

	switch buf {
	case [2]byte{0xCD, 0xAB}:
		nativeEndian = binary.LittleEndian
	case [2]byte{0xAB, 0xCD}:
		nativeEndian = binary.BigEndian
	default:
		panic("Could not determine native endianness.")
	}

	var err error
	saddr, err = addrFromIP("100.89.34.49")
	if err != nil {
		panic("Invalid ip")
	}
}

func DialogInfoFromSIP(sip *layers.SIP) (*DialogInfo, error) {
	var fromTag, toTag, fromID, toID string

	matchs := userFinder.FindStringSubmatch(sip.GetFrom())
	if len(matchs) == 3 {
		fromID = matchs[1]
		fromTag = matchs[2]
	} else {
		return nil, errors.New("No from tag")
	}

	matchs = userFinder.FindStringSubmatch(sip.GetTo())
	if len(matchs) == 2 {
		toID = matchs[1]
	} else if len(matchs) == 3 {
		toID = matchs[1]
		toTag = matchs[2]
	}

	dialogID := fmt.Sprintf("%s#%s#%s", sip.GetCallID(), fromTag, toTag)

	return &DialogInfo{
		DialogID: dialogID,
		First:    toTag == "",
		FromID:   fromID,
		ToID:     toID,
	}, nil
}

func CodecFromAttributes(attrs []sdp.Attribute) (string, error) {
	for _, attr := range attrs {
		if attr.Key == "rtpmap" {
			codec := strings.Split(attr.Value, " ")[1]
			if strings.HasPrefix(codec, "telephone-event") {
				continue
			}
			return codec, nil
		}
	}

	return "", errors.New("No valid codec.")
}

func AudioMediaFromSDP(sdp *sdp.SessionDescription) (am *AudioMediaInfo, err error) {
	var (
		codec string
		addr  uint32
		port  uint16
	)

	if sdp.ConnectionInformation.Address != nil {
		addr, err = addrFromIP(sdp.ConnectionInformation.Address.Address)
		if err != nil {
			return
		}
	}

	for _, m := range sdp.MediaDescriptions {
		if m.MediaName.Media == "audio" {
			if m.ConnectionInformation != nil && m.ConnectionInformation.Address != nil {
				addr, err = addrFromIP(sdp.ConnectionInformation.Address.Address)
			}
			port = uint16(m.MediaName.Port.Value)
			codec, _ = CodecFromAttributes(m.Attributes)
			break
		}
	}

	am = &AudioMediaInfo{
		Codec: codec,
		Addr:  addr,
		Port:  port,
	}

	return
}

//export go_write
func go_write(tuple *C.struct_tuple4, buf *C.char, length C.int) {
	if (uint32(tuple.saddr) == saddr && (tuple.source-5060 < 10)) || (uint32(tuple.daddr) == saddr && (tuple.dest-5060) < 10) {
		sip := layers.NewSIP()
		if err := sip.DecodeFromBytes(C.GoBytes(unsafe.Pointer(buf), length), gopacket.NilDecodeFeedback); err != nil {
			return
		}
		if sip.Method == layers.SIPMethodBye {
			dialogInfo, err := DialogInfoFromSIP(sip)
			if err != nil {
				return
			}
			dialog, ok := Dialogs[dialogInfo.DialogID]
			if ok {
				dialog.Cancel()
				fmt.Printf("BYE: %s, %v\n", dialogInfo.DialogID, dialog)
				delete(Dialogs, dialogInfo.DialogID)
			}
			return
		}
		if sip.IsResponse {
			if sip.Method == layers.SIPMethodInvite && (sip.ResponseCode == 200 || sip.ResponseCode == 183) {
				dialogInfo, err := DialogInfoFromSIP(sip)
				if err != nil {
					return
				}
				dialogID := dialogInfo.DialogID
				//fmt.Printf("RESPONSE %v, DialogID: %s\n", sip.ResponseCode, dialogID)

				var dialog *Dialog
				if len(sip.Headers["content-type"]) > 0 && sip.Headers["content-type"][0] == "application/sdp" {
					sdpParser, err := sdp.NewJSEPSessionDescription(true)
					if err != nil {
						return
					}
					sdpParser.Unmarshal(sip.Payload())
					am, _ := AudioMediaFromSDP(sdpParser)
					//fmt.Println(am)

					var ok bool
					dialog, ok = Dialogs[dialogID]
					if ok {
						if dialog.codec != am.Codec {
							fmt.Println("WARN: codec changed while connecting")
						}
						dialog.codec = am.Codec
						dialog.daddr = am.Addr
						dialog.dport = am.Port

						oldInvite, newInvite := Invite{dialog.saddr, dialog.sport}, Invite{am.Addr, am.Port}
						if oldInvite != newInvite {
							delete(Callees, oldInvite)
							Callees[newInvite] = dialog
						}
					} else {
						inviteID := dialogID[:strings.LastIndex(dialogID, "#")+1]
						invite, ok := Invites[inviteID]
						if !ok {
							fmt.Println("WARN: can't find invite request")
							return
						}
						ctx, cancel := context.WithCancel(context.Background())
						dialog = &Dialog{
							CallerData: make(chan []byte, 8),
							CalleeData: make(chan []byte, 8),
							fromID:     dialogInfo.FromID,
							toID:       dialogInfo.ToID,
							codec:      am.Codec,
							saddr:      invite.Addr,
							daddr:      am.Addr,
							sport:      invite.Port,
							dport:      am.Port,
							ctx:        ctx,
							cancel:     cancel,
						}
						Dialogs[dialogID] = dialog
						Callers[Invite{dialog.saddr, dialog.sport}] = dialog
						Callees[Invite{dialog.daddr, dialog.dport}] = dialog
					}
				} else {
					dialog, _ = Dialogs[dialogID]
				}
				//fmt.Println(sip.ResponseCode, dialogID, inDialog, dialog)

				if sip.ResponseCode == 200 {
					if dialog != nil {
						if !dialog.inDialog {
							dialog.inDialog = true
							fmt.Printf("WOW, we did it. id: %s, dialog=%v\n", dialogID, dialog)
							go func() {
								// TODO: create ws connections and rtp map
								offer, err := os.Create(fmt.Sprintf("Caller-%s.pcm", dialog.fromID))
								if err != nil {
									return
								}
								defer offer.Close()
								answer, err := os.Create(fmt.Sprintf("Callee-%s.pcm", dialog.toID))
								if err != nil {
									return
								}
								defer answer.Close()
								for {
									select {
									case data := <-dialog.CallerData:
										offer.Write(data)
									case data := <-dialog.CalleeData:
										answer.Write(data)
									case <-dialog.ctx.Done():
										break
									}
								}
							}()
						} else {
							fmt.Printf("WOW, we update it. id: %s, dialog=%v\n", dialogID, dialog)
						}
					}
				}
			}
		} else {
			if sip.Method == layers.SIPMethodInvite {
				if sip.Headers["content-type"][0] == "application/sdp" {
					sdpParser, err := sdp.NewJSEPSessionDescription(true)
					if err != nil {
						fmt.Println("new sdp parser error")
						return
					}
					if err := sdpParser.Unmarshal(sip.Payload()); err != nil {
						fmt.Println("parse sdp error")
						return
					}

					am, _ := AudioMediaFromSDP(sdpParser)
					//fmt.Println(am)

					dialogInfo, err := DialogInfoFromSIP(sip)
					inviteID, first := dialogInfo.DialogID, dialogInfo.First
					if err != nil {
						return
					}
					//fmt.Printf("REQUEST DialogID: %s, %v\n", dialogID, first)

					if first {
						Invites[inviteID] = &Invite{Addr: am.Addr, Port: am.Port}
					} else {
						dialog, ok := Dialogs[inviteID]
						if ok {
							dialog.saddr = am.Addr
							dialog.sport = am.Port

							oldInvite, newInvite := Invite{dialog.saddr, dialog.sport}, Invite{am.Addr, am.Port}
							if oldInvite != newInvite {
								delete(Callers, oldInvite)
								Callers[newInvite] = dialog
							}
						} else {
							fmt.Println("WARN: dialog not exist")
						}
					}
					// for _, m := range sdpParser.MediaDescriptions {
					// 	fmt.Println("REQUEST", sdpParser.ConnectionInformation.Address.Address, m.MediaName.Port.Value)
					// }
				}
			}
		}
	} else {
		sInvite, dInvite := Invite{uint32(tuple.saddr), uint16(tuple.source)}, Invite{uint32(tuple.daddr), uint16(tuple.dest)}
		if dialog, ok := Callers[sInvite]; ok {
			packet := &rtp.Packet{}
			err := packet.Unmarshal(C.GoBytes(unsafe.Pointer(buf), length))
			if err == nil {
				dialog.CallerData <- packet.Payload
				fmt.Printf("主->: caller data from %s\n", dialog.fromID)
			}
			return
		}
		if dialog, ok := Callees[dInvite]; ok {
			packet := &rtp.Packet{}
			err := packet.Unmarshal(C.GoBytes(unsafe.Pointer(buf), length))
			if err == nil {
				dialog.CallerData <- packet.Payload
				fmt.Printf("被<-: caller data from %s\n", dialog.fromID)
			}
			return
		}
		if dialog, ok := Callers[dInvite]; ok {
			packet := &rtp.Packet{}
			err := packet.Unmarshal(C.GoBytes(unsafe.Pointer(buf), length))
			if err == nil {
				dialog.CalleeData <- packet.Payload
				fmt.Printf("被<-: callee data from %s\n", dialog.toID)
			}
			return
		}
		if dialog, ok := Callees[sInvite]; ok {
			packet := &rtp.Packet{}
			err := packet.Unmarshal(C.GoBytes(unsafe.Pointer(buf), length))
			if err == nil {
				dialog.CalleeData <- packet.Payload
				fmt.Printf("主->: callee data from %s\n", dialog.toID)
			}
			return
		}
	}
}

func main() {
	C.do_cap()
}
