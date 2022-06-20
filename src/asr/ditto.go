package asr

import (
	"context"
	"fmt"

	"sip-sniffer/src"

	"github.com/gorilla/websocket"
	"github.com/rs/zerolog/log"
	"gopkg.in/mgo.v2/bson"
)

var Sn = fmt.Sprintf(`%x`, string(bson.NewObjectId()))

type StartRequest struct {
	Sn                string   `json:"sn" yaml:"-"`
	Action            string   `json:"action" yaml:"-"`
	Profile           string   `json:"profile" yaml:"profile"`
	SampleRate        int      `json:"sample_rate" yaml:"sample_rate"`
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
	CallId     string
	Caller     string
	Callee     string
	Role       string
	SampleRate int
	Config     src.DittoConfig
	Data       chan []byte
}

func (dc *DittoClient) createStartRequest() StartRequest {
	call := Call{
		Role:   dc.Role,
		Callee: dc.Callee,
		Caller: dc.Caller,
	}

	return StartRequest{
		Sn:                Sn,
		Action:            "Start",
		Profile:           dc.Config.Profile,
		SampleRate:        dc.SampleRate,
		Bid:               &dc.Config.Bid,
		Id:                dc.CallId,
		Call:              call,
		VadAggressiveness: nil, //TODO
		VadRatio:          nil,
		VadPadding:        nil,
	}
}

func (dc *DittoClient) Start(ctx context.Context) {
	go func() {
		for {
			conn, _, err := websocket.DefaultDialer.Dial(dc.Config.Endpoint, nil)
			if err != nil {
				log.Error().Msgf("%s connect asr server failed", dc.Role)
				return
			}
			log.Info().Msgf("%s connect asr server successful", dc.Role)

			startRequest := dc.createStartRequest()

			if err := conn.WriteJSON(startRequest); err != nil {
				log.Error().Msgf("%s send start request failed", dc.Role)
				return
			}

			innerCtx, cancel := context.WithCancel(ctx)

			go func() {
				for {
					select {
					case <-innerCtx.Done():
						return
					case buf := <-dc.Data:
						if err := conn.WriteMessage(websocket.BinaryMessage, buf); err != nil {
							cancel()
							return
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
									dc.CallId, dc.Caller, dc.Role, resp.Action, resp.Payload.Text)
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
				log.Info().Msgf("%s asr stopped", dc.Role)
				return
			case <-innerCtx.Done():
				if ctx.Err() != nil {
					return
				}
			}
			log.Info().Msgf("%s disconnected with asr server and will retry soon", dc.Role)
		}
	}()
}
