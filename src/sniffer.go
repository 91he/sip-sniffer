package src

/*
#include "nids.h"
int do_cap(const char *dev, char *filter);

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
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"unsafe"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/pion/rtp/v2"
	"github.com/pion/sdp/v3"
	"github.com/rs/zerolog/log"

	"gopkg.in/yaml.v3"
)

type SipDirection int

const (
	SIP_OUT SipDirection = iota
	SIP_IN
)

type SipConfig struct {
	CIDR string  `yaml:"cidr"`
	Port *uint16 `yaml:"port"`
}

type PcapConfig struct {
	Device string `yaml:"device"`
	filter string `yaml:"filter"`
}

type StaffPattern struct {
	Pattern string `yaml:"pattern"`
}

type DittoConfig struct {
	Bid      string `yaml:"bid"`
	Category string `yaml:"category"`
	Profile  string `yaml:"profile"`
	Endpoint string `yaml:"endpoint"`
}

type AssistantConfig struct {
	StaffPatterns []StaffPattern `yaml:"staff_patterns"`
	Ditto         DittoConfig    `yaml:"ditto"`
}

type SnifferConfig struct {
	Sip       SipConfig       `yaml:"sip"`
	Pcap      PcapConfig      `yaml:"pcap"`
	Assistant AssistantConfig `yaml:"assistant"`
}

type Sniffer struct {
	Config        string `clop:"short;long" usage:"server config path" valid:"required"`
	Level         string `clop:"short;long" usage:"log level" default:"INFO"`
	config        SnifferConfig
	CIDR          *net.IPNet
	StaffMatchers []*regexp.Regexp
}

var SS = Sniffer{}

func (s *Sniffer) init() {
	dat, err := os.ReadFile(s.Config)
	if err != nil {
		//log.Error().Msgf("fail reading ss config: %v", err)
		panic(errors.New("fail reading ss config"))
	}

	if err = yaml.Unmarshal(dat, &s.config); err != nil {
		panic(errors.New("fail parsing ss config"))
	}

	var cidr *net.IPNet
	if _, cidr, err = net.ParseCIDR(s.config.Sip.CIDR); err != nil {
		panic(errors.New("fail parsing cidr"))
	}

	s.CIDR = cidr

	var matchers []*regexp.Regexp
	for _, sp := range s.config.Assistant.StaffPatterns {
		if exp, err := regexp.Compile(sp.Pattern); err != nil {
			panic(fmt.Errorf("fail compiling regexp: %s", sp.Pattern))
		} else {
			matchers = append(matchers, exp)
		}
	}

	s.StaffMatchers = matchers
}

func (s *Sniffer) MatchStaff(dialog *DialogInfo) (bool, SipDirection) {
	for _, matcher := range s.StaffMatchers {
		if matcher.MatchString(dialog.FromID) {
			return true, SIP_OUT
		} else if matcher.MatchString(dialog.ToID) {
			return true, SIP_IN
		}
	}

	return false, SIP_IN
}

func (s *Sniffer) MatchSip(tuple *C.struct_tuple4, buf *C.char, length C.int) (match bool) {
	if s.config.Sip.Port != nil {
		if (s.CIDR.Contains(IPFromAddr(uint32(tuple.saddr))) && uint16(tuple.source) == *s.config.Sip.Port) ||
			(s.CIDR.Contains(IPFromAddr(uint32(tuple.daddr))) && uint16(tuple.dest) == *s.config.Sip.Port) {
			match = true
		}
	} else {
		if s.CIDR.Contains(IPFromAddr(uint32(tuple.saddr))) || s.CIDR.Contains(IPFromAddr(uint32(tuple.daddr))) {
			match = true
		}
	}

	if match {
		sip := layers.NewSIP()
		if err := sip.DecodeFromBytes(C.GoBytes(unsafe.Pointer(buf), length), gopacket.NilDecodeFeedback); err != nil {
			if s.config.Sip.Port == nil {
				match = false
			}
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
				log.Info().Msgf("BYE: %s, %v\n", dialogInfo.DialogID, dialog)
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

				ok, direction := s.MatchStaff(dialogInfo)
				if !ok {
					log.Info().Msgf("staff do not match, drop sip request. Info: %v\n", dialogInfo)
					return
				}

				dialogID := dialogInfo.DialogID
				log.Debug().Msgf("RESPONSE %v, DialogID: %s\n", sip.ResponseCode, dialogID)

				var dialog *Dialog
				if len(sip.Headers["content-type"]) > 0 && sip.Headers["content-type"][0] == "application/sdp" {
					sdpParser, err := sdp.NewJSEPSessionDescription(true)
					if err != nil {
						return
					}
					sdpParser.Unmarshal(sip.Payload())
					am, _ := AudioMediaFromSDP(sdpParser)

					var ok bool
					dialog, ok = Dialogs[dialogID]
					if ok {
						if dialog.codec != am.Codec {
							log.Warn().Msg("codec changed while connecting")
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
							log.Warn().Msg("can't find invite request")
							return
						}
						ctx, cancel := context.WithCancel(context.Background())
						dialog = &Dialog{
							CallerData: make(chan []byte, 8),
							CalleeData: make(chan []byte, 8),
							direction:  direction,
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
				log.Debug().Msgf("%v, %v, %v", sip.ResponseCode, dialogID, dialog)

				if sip.ResponseCode == 200 {
					if dialog != nil {
						if !dialog.inDialog {
							dialog.inDialog = true
							log.Info().Msgf("WOW, we did it. id: %s, dialog=%v\n", dialogID, dialog)
							go func() {
								callerOnce, calleeOnce := sync.Once{}, sync.Once{}
								var (
									offer  *os.File
									answer *os.File
								)

								if true {
									offer, err = os.Create(fmt.Sprintf("Caller-%s.pcm", dialog.fromID))
									if err != nil {
										return
									}
									defer offer.Close()
									answer, err = os.Create(fmt.Sprintf("Callee-%s.pcm", dialog.toID))
									if err != nil {
										return
									}
									defer answer.Close()
								}

								for {
									select {
									case data := <-dialog.CallerData:
										callerOnce.Do(func() {
											role := "staff"
											if dialog.direction == SIP_IN {
												role = "customer"
											}
											log.Info().Msg(role)
											//Send start request
										})
										if true {
											offer.Write(data)
										}
									case data := <-dialog.CalleeData:
										calleeOnce.Do(func() {
											role := "staff"
											if dialog.direction == SIP_OUT {
												role = "customer"
											}
											log.Info().Msg(role)
											//Send start request
										})
										if true {
											answer.Write(data)
										}
									case <-dialog.ctx.Done():
										break
									}
								}
							}()
						} else {
							log.Info().Msgf("WOW, we update it. id: %s, dialog=%v\n", dialogID, dialog)
						}
					}
				}
			}
		} else {
			if sip.Method == layers.SIPMethodInvite {
				if sip.Headers["content-type"][0] == "application/sdp" {
					sdpParser, err := sdp.NewJSEPSessionDescription(true)
					if err != nil {
						log.Error().Msg("new sdp parser error")
						return
					}
					if err := sdpParser.Unmarshal(sip.Payload()); err != nil {
						log.Error().Msg("parse sdp error")
						return
					}

					am, _ := AudioMediaFromSDP(sdpParser)

					dialogInfo, err := DialogInfoFromSIP(sip)
					if err != nil {
						return
					}
					//fmt.Printf("REQUEST DialogID: %s, %v\n", dialogID, first)
					ok, _ := s.MatchStaff(dialogInfo)
					if !ok {
						log.Info().Msgf("staff do not match, drop sip request. Info: %v\n", dialogInfo)
						return
					}

					inviteID, first := dialogInfo.DialogID, dialogInfo.First
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
							log.Warn().Msg("WARN: dialog not exist")
						}
					}
					// for _, m := range sdpParser.MediaDescriptions {
					// 	fmt.Println("REQUEST", sdpParser.ConnectionInformation.Address.Address, m.MediaName.Port.Value)
					// }
				}
			}
		}
	}

	return
}

type Invite struct {
	Addr uint32
	Port uint16
}

type Dialog struct {
	CallerData chan []byte
	CalleeData chan []byte
	direction  SipDirection
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

func IPFromAddr(addr uint32) net.IP {
	var tmp [4]byte
	nativeEndian.PutUint32(tmp[:4:4], addr)
	return tmp[:]
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
	if !SS.MatchSip(tuple, buf, length) {
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

func (s *Sniffer) DoSniff() {
	var (
		device *C.char
		filter *C.char
	)

	s.init()

	if s.config.Pcap.Device != "" {
		device = C.CString(SS.config.Pcap.Device)
	}

	if s.config.Pcap.filter != "" {
		filter = C.CString(SS.config.Pcap.filter)
	}

	C.do_cap(device, filter)
}
