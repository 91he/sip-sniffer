package asr

import (
	"context"
	"fmt"

	"github.com/gorilla/websocket"
	"github.com/pion/rtp/v2"
	"github.com/rs/zerolog/log"
	"gopkg.in/mgo.v2/bson"
)

var Sn = fmt.Sprintf(`%x`, string(bson.NewObjectId()))

var PayloadTypes = map[uint8]PayloadType{
	0:  {"PCMU/8000", "mulaw", 8000},
	3:  {"GSM/8000", "gsm", 8000},
	4:  {"G723/8000", "g723_1", 8000},
	8:  {"PCMA/8000", "alaw", 8000},
	9:  {"G722/8000", "g722", 8000},
	11: {"L16/44100", "s16be", 44100},
	18: {"G729/8000", "g729", 8000},
}

type PayloadType struct {
	Name       string
	Format     string
	SampleRate int
}

type DittoConfig struct {
	Bid      string `yaml:"bid"`
	Category string `yaml:"category"`
	Profile  string `yaml:"profile"`
	Endpoint string `yaml:"endpoint"`
}

type StartRequest struct {
	Sn                string   `json:"sn" yaml:"-"`
	Action            string   `json:"action" yaml:"-"`
	Profile           string   `json:"profile" yaml:"profile"`
	Format            string   `json:"format" yaml:"format"`
	SampleRate        int      `json:"sample_rate" yaml:"sample_rate"`
	Category          *string  `json:"category" yaml:"category"`
	Id                string   `json:"id" yaml:"-"`
	Call              Call     `json:"call" yaml:"call"`
	Token             string   `json:"token" yaml:"-"`
	Bid               *string  `json:"bid,omitempty" yaml:"bid,omitempty"`
	Sid               string   `json:"sid,omitempty"`
	VadAggressiveness *int     `yaml:"vad_aggressiveness,omitempty" json:"vad_aggressiveness,omitempty"`
	VadPadding        *float64 `yaml:"vad_padding,omitempty" json:"vad_padding,omitempty"`
	VadRatio          *float64 `yaml:"vad_ratio,omitempty" json:"vad_ratio,omitempty"`
}

type RtaType struct {
	WithSt *bool `json:"with_st,omitempty"`
	WithCn *bool `json:"with_cn,omitempty"`
}

type Call struct {
	RtaType
	Caller string `json:"caller" yaml:"caller"`
	Callee string `json:"callee" yaml:"callee"`
	Role   string `json:"role" yaml:"role"`
}

type AsrResponse struct {
	TaskId  string     `json:"task_id"`
	Action  string     `json:"action"`
	Payload AsrPayload `json:"payload"`
}

type AsrPayload struct {
	StatusCode    int     `json:"status_code"`
	Text          string  `json:"text"`
	Message       string  `json:"message"`
	SentenceIndex int     `json:"sentence_index"`
	BeginTime     int     `json:"begin_time"`
	EndTime       int     `json:"end_time"`
	Confidence    float64 `json:"confidence"`
}

type DittoClient struct {
	CallId string
	Caller string
	Callee string
	Role   string
	Format string
	Config DittoConfig
	Data   chan *rtp.Packet
}

func (dc *DittoClient) createStartRequest(format string, sampleRate int) StartRequest {
	call := Call{
		Role:   dc.Role,
		Callee: dc.Callee,
		Caller: dc.Caller,
	}

	var (
		bid      *string
		category *string
	)

	if dc.Config.Bid != "" {
		bid = &dc.Config.Bid
	}

	if dc.Config.Category != "" {
		bid = &dc.Config.Category
	}

	return StartRequest{
		Sn:                Sn,
		Action:            "Start",
		Profile:           dc.Config.Profile,
		Format:            format,
		SampleRate:        sampleRate,
		Bid:               bid,
		Category:          category,
		Id:                dc.CallId,
		Call:              call,
		VadAggressiveness: nil, //TODO
		VadRatio:          nil,
		VadPadding:        nil,
	}
}

func (dc *DittoClient) Start(ctx context.Context) {
	role, uid := dc.Role, dc.Caller
	if role != "staff" {
		uid = dc.Callee
	}

	go func() {
		for {
			var (
				pt         uint8
				format     string
				sampleRate int
				data       []byte
			)
		INNER:
			for {
				select {
				case <-ctx.Done():
					return
				case pkg := <-dc.Data:
					if plt, ok := PayloadTypes[pkg.PayloadType]; ok {
						format = plt.Format
						sampleRate = plt.SampleRate
						pt = pkg.PayloadType
						data = pkg.Payload
						break INNER
					} else {
						log.Info().Msgf("unsupport audio payload type: %v", pkg.PayloadType)
					}
				}
			}

			conn, _, err := websocket.DefaultDialer.Dial(dc.Config.Endpoint, nil)
			if err != nil {
				log.Error().Msgf("%s(%s) connect asr server failed", role, uid)
				return
			}
			log.Info().Msgf("%s(%s) connect asr server successful", role, uid)

			startRequest := dc.createStartRequest(format, sampleRate)

			if err := conn.WriteJSON(startRequest); err != nil {
				log.Error().Msgf("%s(%s) send start request failed", role, uid)
				return
			} else {
				conn.WriteMessage(websocket.BinaryMessage, data)
			}

			innerCtx, cancel := context.WithCancel(ctx)

			go func() {
				for {
					select {
					case <-innerCtx.Done():
						return
					case pkg := <-dc.Data:
						if err := conn.WriteMessage(websocket.BinaryMessage, pkg.Payload); err != nil {
							cancel()
							return
						}

						if pkg.PayloadType != pt {
							log.Warn().Msgf("%s(%s) incompatible format.", role, uid)
							//TODO: break and restart websocket
						}
					}
				}
			}()

			go func() {
				for {
					select {
					case <-innerCtx.Done():
						return
					default:
						resp := AsrResponse{}
						if err = conn.ReadJSON(&resp); err != nil {
							log.Warn().Msg("Fail reading websocket response")
							cancel()
							return
						}

						if resp.Action == "EndOfSentence" || resp.Action == "ResultUpdated" {
							if !(resp.Payload.Text == "。" || resp.Payload.Text == "" || resp.Payload.Text == " ") {
								log.Debug().Msgf("Id:[%v]|StaffId:[%v]|Role:[%v]Action:[%v] --- Recv:[%v]\n",
									dc.CallId, dc.Caller, role, resp.Action, resp.Payload.Text)
							}
						} else if resp.Action == "TranscribeCompleted" {
							cancel()
							return
						}
					}
				}
			}()

			select {
			case <-ctx.Done():
				log.Info().Msgf("%s(%s) asr stopped", role, uid)
				return
			case <-innerCtx.Done():
				if ctx.Err() != nil {
					return
				}
			}
			log.Info().Msgf("%s(%s) disconnected with asr server and will retry soon", role, uid)
		}
	}()
}
