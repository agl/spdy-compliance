// Copyright 2011 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// spdy_compliance.go runs tests on a SPDY server to evaluate its compliance
// with the SPDY specification.  It reads configuration from a JSON file
// specified as the first command line argument.  For example:
//
// % cat config.json
// {
//   "Endpoint": "www.google.com:443",
//   "PostURL":   "http://www.google.com",
//   "GetURL":   "http://www.google.com",
//   "DisabledTests": [
//     "GOAWAY after empty SYN_REPLY"
//   ]
// }
//
// To install the go tools, follow the instructions here:
//   http://golang.org/doc/install.html
//
// Compile and run with:
// % go run spdy_compliance.go <config.json>

package main

import (
	"bytes"
	"compress/zlib"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"code.google.com/p/go.net/spdy"
)

// TerminalColorEscapes contains strings that, when printed to a terminal, will
// cause subsequent text to be displayed in the given manner.
type TerminalColorEscapes struct {
	Red, Green, Yellow, Bold, Normal string
}

var ansiTerminal = TerminalColorEscapes{
	Red: "[0;31m",
	Green: "[0;32m",
	Yellow: "[0;33m",
	Bold: "[1m",
	Normal: "[0m",
}

// noTerminal contains empty strings for all the escapes and is suitable for
// writing to a file or other, non-terminal device
var noTerminal TerminalColorEscapes

// ----------------------------------------------------------------------

// A TestConfig defines the parameters for configuring a SPDY compliance
// test.
type TestConfig struct {
	Endpoint      string
	GetURL        *url.URL
	PostURL       *url.URL
	PushURL       *url.URL // URL that will result in resources being pushed
	DisabledTests []string
	MaxStreams    int
}

// NewTestConfig creates a TestConfig by parsing JSON from the given file.
func NewTestConfig(configFileName string) (*TestConfig, error) {
	configBytes, err := ioutil.ReadFile(configFileName)
	if err != nil {
		return nil, err
	}

	var testConfigJSON struct {
		Endpoint                 string
		GetURL, PostURL, PushURL string
		DisabledTests            []string
		MaxStreams               int
	}

	if err := json.Unmarshal(configBytes, &testConfigJSON); err != nil {
		return nil, err
	}

	t := &TestConfig{
		Endpoint:      testConfigJSON.Endpoint,
		MaxStreams:    testConfigJSON.MaxStreams,
		DisabledTests: testConfigJSON.DisabledTests,
	}

	if t.GetURL, err = ParseURL(testConfigJSON.GetURL); err != nil {
		return nil, errors.New("failed to parse GetURL from config: " + err.Error())
	}
	if t.PostURL, err = ParseURL(testConfigJSON.PostURL); err != nil {
		return nil, errors.New("failed to parse PostURL from config: " + err.Error())
	}
	if t.PushURL, err = ParseURL(testConfigJSON.PushURL); err != nil {
		return nil, errors.New("failed to parse PushURL from config: " + err.Error())
	}

	return t, nil
}

// ParseURL returns nil if s is empty and url.Parse otherwise.
func ParseURL(s string) (*url.URL, error) {
	if len(s) == 0 {
		return nil, nil
	}
	return url.Parse(s)
}

// ----------------------------------------------------------------------

// A TestRunner runs a number of tests, and records the results.
// If a test panics, the TestRunner will recover, and mark the test
// as failed.
type TestRunner struct {
	config           *TestConfig // test configuration
	numTests         int         // total number of tests run
	numDisabledTests int         // total number of disabled tests
	failedTests      []string    // list of test descriptions that failed
	color            *TerminalColorEscapes
	args             []string      // list of command line arguments used to restrict the actual set of tests to be run
	elapsedTime      time.Duration // Total time spent executing tests
	readTimeout      time.Duration // Read timeout for a single test
}

func NewTestRunner(useColor bool, configFileName string, args []string) (*TestRunner, error) {
	config, err := NewTestConfig(configFileName)
	if err != nil {
		return nil, err
	}

	t := &TestRunner{
		args:   args,
		color:  &noTerminal,
		config: config,
	}
	if useColor {
		t.color = &ansiTerminal
	}
	return t, nil
}

// Log prints formatted descriptive message with the status text displayed in
// the specified color, followed by the description.
func (t *TestRunner) Log(color, status, description string) {
	fmt.Printf("%s[%s]%s %s\n", color, status, t.color.Normal, description)
}

// FetchSettings connects to the server and reads a SETTINGS frame, if needed.
func (t *TestRunner) FetchSettings() error {
	if t.config.MaxStreams != 0 {
		return nil
	}

	tester := NewSPDYTester(t.config)
	defer tester.Close()

	frame, err := tester.framer.ReadFrame()
	if err != nil {
		return err
	}
	settings, ok := frame.(*spdy.SettingsFrame)
	if !ok {
		return fmt.Errorf("expected SETTINGS, got %#v", frame)
	}

	for _, setting := range settings.FlagIdValues {
		if setting.Id == spdy.SettingsMaxConcurrentStreams {
			maxStreams := int(setting.Value)
			switch {
			case maxStreams < 0:
				panic("SettingsMaxConcurrentStreams so large that it overflowed")
			case maxStreams == 0:
				panic("SettingsMaxConcurrentStreams is zero")
			}
			t.config.MaxStreams = maxStreams
		}
	}

	if t.config.MaxStreams == 0 {
		return fmt.Errorf("no SettingsMaxConcurrentStreams in SETTINGS")
	}

	return nil
}

// RunTest runs the specified test, and records the results. The test will be
// marked as failed if it panics.
func (t *TestRunner) RunTest(test func(*SPDYTester), description string) {
	// If any arguments were given, then this test must have been listed.
	if len(t.args) > 0 {
		match := false
		for _, arg := range t.args {
			if description == arg {
				match = true
				break
			}
		}
		if !match {
			return
		}
	}
	for _, disabled := range t.config.DisabledTests {
		if disabled == description {
			t.RecordDisabledTest(description)
			return
		}
	}

	t.Log(t.color.Green, " RUN      ", description)
	start := time.Now()
	defer t.Finished(description, start)
	tester := NewSPDYTester(t.config)
	defer tester.Close()
	test(tester)
}

// RecordDisabledTest marks a test as disabled.
func (t *TestRunner) RecordDisabledTest(description string) {
	t.numDisabledTests++
	t.Log(t.color.Yellow, " DISABLED ", description)
}

// Finished handles the completion of a test by calling recover and looking for
// a panic.
func (t *TestRunner) Finished(description string, start time.Time) {
	end := time.Now()
	duration := end.Sub(start)
	t.elapsedTime += duration
	t.numTests++

	text := fmt.Sprintf("%s (%d ms)", description, int(1000*duration.Seconds()))
	if err := recover(); err != nil {
		fmt.Printf("%sERROR%s: %s\n", t.color.Bold, t.color.Normal, err)
		t.Log(t.color.Red, "  FAILED  ", text)
		t.failedTests = append(t.failedTests, description)
	} else {
		t.Log(t.color.Green, "       OK ", text)
	}
}

// Summarize prints a textual summary of all the test run.
func (t *TestRunner) Summarize() bool {
	t.Log(t.color.Green, "==========", fmt.Sprintf("%d tests ran. (%d ms total)", t.numTests, int(1000*t.elapsedTime.Seconds())))

	t.Log(t.color.Green, "  PASSED  ", fmt.Sprintf("%d tests.", t.numTests-len(t.failedTests)))

	t.Log(t.color.Yellow, " DISABLED ", fmt.Sprintf("%d tests", t.numDisabledTests))

	if len(t.failedTests) != 0 {
		t.Log(t.color.Red, "  FAILED  ", fmt.Sprintf("%d tests, listed below:", len(t.failedTests)))

		for _, test := range t.failedTests {
			t.Log(t.color.Red, "  FAILED  ", test)
		}
		return false
	}
	return true
}

// ----------------------------------------------------------------------

// Utility function for creating a sequence of bytes that represents
// a (probably invalid) SPDY control frame.
func CreateControlFrameBytes(version uint8, frameType uint16, flags uint8, length uint8) []byte {
	bytes := make([]byte, 8+length)
	bytes[0] = 1 << 7
	bytes[1] = version
	bytes[2] = uint8(frameType >> 8)
	bytes[3] = uint8(frameType & 0x00FF)
	bytes[4] = flags
	bytes[5] = 0
	bytes[6] = 0
	bytes[7] = length
	return bytes
}

// ----------------------------------------------------------------------

type spdyVersion int

const (
	SPDY2 spdyVersion = 2
	SPDY3 spdyVersion = 3
)

type SPDYTester struct {
	conn    *tls.Conn
	framer  *spdy.Framer
	config  *TestConfig
	version spdyVersion
}

func NewSPDYTester(config *TestConfig) *SPDYTester {
	tester := &SPDYTester{
		config:  config,
		version: SPDY2,
	}
	tester.Dial([]string{"spdy/2"})
	return tester
}

// Dial creates a TLS connection to the configured end-point and negotiates
// with the given Next Protocol Negotiation strings.
func (t *SPDYTester) Dial(nextProtos []string) {
	conn, err := tls.Dial("tcp", t.config.Endpoint, &tls.Config{
		NextProtos:         nextProtos,
		InsecureSkipVerify: true,
	})
	if err != nil {
		panic(fmt.Sprintf("failed to make TLS connection to %s: %s", t.config.Endpoint, err))
	}
	// Timeout reads after 1 second.  This causes an ERR_IO_PENDING error
	// to be returned when attempting to read a frame, and allows us
	// to detect when the server has failed to reply (quickly enough)
	// to one of our requests
	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	t.conn = conn
	if t.framer, err = spdy.NewFramer(conn, conn); err != nil {
		panic(err)
	}
}

func (t *SPDYTester) SetReadTimeout(timeout time.Duration) {
	t.conn.SetReadDeadline(time.Now().Add(timeout))
}

func (t *SPDYTester) Close() {
	t.conn.Close()
}

// Returns the protocol negotiated during the handshake, or the empty string
// if no protocol was agreed upon.
func (t *SPDYTester) NegotiatedProtocol() string {
	if !t.conn.ConnectionState().NegotiatedProtocolIsMutual {
		return ""
	}
	return t.conn.ConnectionState().NegotiatedProtocol
}

func (t *SPDYTester) CreateSynStreamFrameBytes(streamId int) []byte {
	frame := &spdy.SynStreamFrame{
		StreamId: uint32(streamId),
		Headers: http.Header{
			"method":  []string{"GET"},
			"version": []string{"HTTP/1.1"},
			"url":     []string{t.config.GetURL.String()},
			"host":    []string{t.config.GetURL.Host},
			"scheme":  []string{t.config.GetURL.Scheme},
		},
	}
	frame.CFHeader.Flags = spdy.ControlFlagFin

	var buf bytes.Buffer
	framer, err := spdy.NewFramer(&buf, &buf)
	if err != nil {
		panic(err)
	}
	framer.WriteFrame(frame)

	return buf.Bytes()
}

// ReadNextNonSettingsFrame returns the next frame read from the framer that is
// not a SETTINGS frame.
func (t *SPDYTester) ReadNextNonSettingsFrame() (spdy.Frame, error) {
	for true {
		frame, err := t.framer.ReadFrame()
		if err != nil {
			return nil, err
		}
		if _, ok := frame.(*spdy.SettingsFrame); !ok {
			return frame, nil
		}
	}
	panic("unreachable")
}

// ExpectGoAway reads a GOAWAY frame (with the given lastGoodStreamId) after
// zero or more SETTINGS frames, or panics.
func (t *SPDYTester) ExpectGoAway(lastGoodStreamId int) {
	frame, err := t.ReadNextNonSettingsFrame()
	if err != nil {
		panic(err)
	}
	goAwayFrame, ok := frame.(*spdy.GoAwayFrame)
	if !ok {
		panic(fmt.Sprintf("Expected GOAWAY, got: %#v", frame))
	}
	if goAwayFrame.LastGoodStreamId != uint32(lastGoodStreamId) {
		panic(fmt.Sprintf("Incorrect LastGoodStreamId: expected 0, got %d", goAwayFrame.LastGoodStreamId))
	}

	t.ExpectEOF()
}

// ExpectEOF panics unless the next read from the session returns EOF.
func (t *SPDYTester) ExpectEOF() {
	frame, err := t.ReadNextNonSettingsFrame()
	if frame != nil {
		panic(fmt.Sprintf("Expected EOF, got: %#v", frame))
	}
	if err != io.EOF {
		panic(fmt.Sprintf("Expected EOF, got: %s", err))
	}
}

// ExpectPing panics if the next non-settings frame is not a PING frame.
func (t *SPDYTester) ExpectPing(id uint32) {
	frame, err := t.ReadNextNonSettingsFrame()
	if err != nil {
		panic(fmt.Sprintf("Unexpected error: %s", err))
	}

	pingFrame, ok := frame.(*spdy.PingFrame)
	if !ok {
		panic(fmt.Sprintf("Expected PING, got: %#v", frame))
	}
	if pingFrame.Id != id {
		panic(fmt.Sprintf("Incorrect PING id: expected %d, got %d", id, pingFrame.Id))
	}
}

// ExpectRstStream panics if the next non-settings frame is not a RST_STREAM
// frame with StreamID set to id.
func (t *SPDYTester) ExpectRstStream(id uint32, status spdy.StatusCode) {
	frame, err := t.ReadNextNonSettingsFrame()
	if err != nil {
		panic(fmt.Sprintf("Unexpected error: %s", err))
	}

	rst, ok := frame.(*spdy.RstStreamFrame)
	if !ok {
		panic(fmt.Sprintf("Expected a RST_STREAM frame, got: %#v", frame))
	}
	if rst.StreamId != id {
		panic(fmt.Sprintf("Incorrect RST_STREAM id: expected %d, got %d", id, rst.StreamId))
	}
	if rst.Status != status {
		panic(fmt.Sprintf("Incorrect RST_STREAM status: expected %s, got %s", status, rst.Status))
	}
}

// ExpectReply checks that a SYN_REPLY frame is received as the first
// non-settings frame followed by optional data frames until receipt of a frame
// with FIN set.
func (t *SPDYTester) ExpectReply(id uint32) *spdy.SynReplyFrame {
	frame, err := t.ReadNextNonSettingsFrame()
	if err != nil {
		panic(fmt.Sprintf("Unexpected error: %s", err))
	}

	reply, ok := frame.(*spdy.SynReplyFrame)
	if !ok {
		panic(fmt.Sprintf("Expected a SYN_REPLY frame, got: %#v", frame))
	}
	if reply.StreamId != id {
		panic(fmt.Sprintf("Incorrect SYN_REPLY id: expected %d, got %d", id, reply.StreamId))
	}
	if reply.CFHeader.Flags != spdy.ControlFlagFin {
		for {
			frame, err := t.ReadNextNonSettingsFrame()
			if err != nil {
				panic(fmt.Sprintf("Unexpected error: %s", err))
			}
			data, ok := frame.(*spdy.DataFrame)
			if !ok {
				panic(fmt.Sprintf("Expected a DATA frame, got: %s", frame))
			}
			if data.StreamId != id {
				panic(fmt.Sprintf("Incorrect DATA id: expected %d, got %d", id, data.StreamId))
			}
			if data.Flags == spdy.DataFlagFin {
				break
			}
		}
	}

	return reply
}

func (t *SPDYTester) ExpectPushReply(streamId int) {
	var dataReceived bool
	var numPushed int
	pushedIds := make(map[uint32]bool)

	for {
		frame, err := t.ReadNextNonSettingsFrame()
		if err != nil {
			panic(err)
		}
		switch frame := frame.(type) {
		case *spdy.SynReplyFrame:
			if frame.StreamId != uint32(streamId) {
				panic(fmt.Sprintf("Expected repl for stream %d, got %d", streamId, frame.StreamId))
			}
		case *spdy.SynStreamFrame:
			if dataReceived {
				panic("Stream pushed after data recevied")
			}
			if frame.StreamId%2 != 0 {
				panic(fmt.Sprintf("Server push stream with odd stream id: %d", frame.StreamId))
			}
			if frame.CFHeader.Flags != 2 {
				panic(fmt.Sprintf("Server push stream was not unidirectional"))
			}
			for k, _ := range pushedIds {
				if frame.StreamId < k {
					panic(fmt.Sprintf("Decreasing stream id: %d", frame.StreamId))
				}
				if frame.StreamId == k {
					panic(fmt.Sprintf("Duplicate stream id: %d", frame.StreamId))
				}
			}
			// TODO(rch): Check for decreasing
			// TODO(rch): Check for even and > 0
			pushedIds[frame.StreamId] = true
			numPushed++
		case *spdy.DataFrame:
			if frame.StreamId == 1 {
				dataReceived = true
			} else {
				if frame.Flags == spdy.DataFlagFin {
					delete(pushedIds, frame.StreamId)
				}
			}
			if len(pushedIds) == 0 {
				break
			}
		}
	}
	if numPushed == 0 {
		panic("No streams pushed")
	}
}

// ----------------------------------------------------------------------

// SendDataAndExpectGoAway check that a GOAWAY frame is received as the first
// non-settings frame after sending |data|.
func (t *SPDYTester) SendDataAndExpectGoAway(data []uint8, lastGoodStreamId int) {
	t.conn.Write(data)
	t.ExpectGoAway(lastGoodStreamId)
}

// SendDataAndExpectRstStream checks that a RST_STREAM frame is received as the
// first non-settings frame after sending |data|.
func (t *SPDYTester) SendDataAndExpectRstStream(data []uint8, streamId int, status spdy.StatusCode) {
	t.conn.Write(data)
	t.ExpectRstStream(uint32(streamId), status)
}

// SendDataAndExpectValidReply checks that a SYN_REPLY frame is received as the
// first non-settings frame after sending |data|.
func (t *SPDYTester) SendDataAndExpectValidReply(data []uint8) {
	t.conn.Write(data)
	t.ExpectReply(1)
}

// SendDataAndExpectPing checks that a PING frame is received as the first
// non-settings frame after sending |data|.
func (t *SPDYTester) SendDataAndExpectPing(data []uint8) {
	t.conn.Write(data)
	t.ExpectPing(uint32(data[11]))
}

// Tests that the server support NPN negotiation for
// all the various protocols and versions.
func CheckNextProtocolNegotiationSupport(t *TestRunner) {
	protos := [...]string{"http/1.1", "spdy/2", "spdy/3"}
	for _, proto := range protos {
		t.RunTest(
			func(t *SPDYTester) {
				t.Close()
				t.Dial([]string{proto})
				if t.NegotiatedProtocol() != proto {
					panic("Unable to NPN negotiate: " + proto)
				}
			},
			"NPN negotiate "+proto)
	}
}

// Send a variety of invalid control frames and verify that
// the server sends a GOAWAY.
func CheckInvalidControlFrameDetection(t *TestRunner) {
	t.RunTest(
		func(t *SPDYTester) {
			t.SendDataAndExpectGoAway([]uint8{
				0xff, 0xff, 0xff, 0xff,
				0xff, 0xff, 0xff, 0xff,
				0xff, 0xff, 0xff, 0xff,
				0xff, 0xff, 0xff, 0xff,
				0xff, 0xff, 0xff, 0xff}, 0)
		},
		"GOAWAY after garbage")

	// Invalid version
	// TODO(rch): what is correct behavior.  Draft 2 says:
	// SPDY does lazy version checking on receipt of any control frame, and
	// does version enforcement only on SYN_STREAM frames.  If an endpoint
	// receives a SYN_STREAM frame with an unsupported version, the endpoint
	// must return a RST_STREAM frame with the status code UNSUPPORTED_VERSION.
	// For any other type of control frame, the frame must be ignored.
	//
	// Draft 3 is silent on the subject.
	t.RunTest(func(t *SPDYTester) {
		bytes := CreateControlFrameBytes(3, uint16(spdy.TypeNoop), 0, 0)
		t.SendDataAndExpectGoAway(bytes, 0)
	},
		"GOAWAY after invalid version in control frame")

	// Invalid control frame type
	// TODO(rch): actually, according to the spec:
	// If an endpoint receives a control frame for a type it does not recognize,
	// it MUST ignore the frame.
	t.RunTest(func(t *SPDYTester) {
		bytes := CreateControlFrameBytes(
			2, uint16(spdy.TypeWindowUpdate)+6, 0, 0)
		t.SendDataAndExpectGoAway(bytes, 0)
		// after sending this packet, send a ping and expect a ping?
	},
		"GOAWAY after invalid control frame type")
}

func CheckSynStreamSupport(t *TestRunner) {
	t.RunTest(func(t *SPDYTester) {
		// Bogus flags
		bytes := t.CreateSynStreamFrameBytes(1)
		bytes[4] = 0xFF
		//	bytes[11] = 1  // stream id
		//	DumpBytes(bytes)
		t.SendDataAndExpectGoAway(bytes, 0)
	},
		"GOAWAY after invalid SYN_STREAM flags")

	t.RunTest(func(t *SPDYTester) {
		bytes := t.CreateSynStreamFrameBytes(1)
		bytes[7] = 0x0 // no length
		t.SendDataAndExpectGoAway(bytes, 0)
	},
		"GOAWAY after invalid SYN_STREAM length")

	t.RunTest(func(t *SPDYTester) {
		bytes := t.CreateSynStreamFrameBytes(2)
		//	DumpBytes(bytes)
		t.SendDataAndExpectGoAway(bytes, 0)
	},
		"GOAWAY after invalid SYN_STREAM StreamID (2)")

	t.RunTest(func(t *SPDYTester) {
		bytes := t.CreateSynStreamFrameBytes(0)
		//	DumpBytes(bytes)
		t.SendDataAndExpectGoAway(bytes, 0)
	},
		"GOAWAY after invalid SYN_STREAM StreamID (0)")

	t.RunTest(func(t *SPDYTester) {
		bytes := t.CreateSynStreamFrameBytes(1)
		//	DumpBytes(bytes)
		t.SendDataAndExpectValidReply(bytes)
	},
		"Valid response to SYN_STREAM")

	t.RunTest(func(t *SPDYTester) {
		// try sending same syn stream again
		bytes := t.CreateSynStreamFrameBytes(1)
		bytes = append(bytes, bytes...)
		t.SendDataAndExpectGoAway(bytes, 1)
	},
		"GOAWAY after duplicate SYN_STREAM StreamID")

	t.RunTest(func(t *SPDYTester) {
		// try sending decreasing stream id
		bytes := t.CreateSynStreamFrameBytes(3)
		bytes2 := t.CreateSynStreamFrameBytes(2)
		bytes = append(bytes, bytes2...)
		t.SendDataAndExpectGoAway(bytes, 3)
	},
		"GOAWAY after decreasing SYN_STREAM StreamID")

	t.RunTest(func(t *SPDYTester) { CheckConcurrentStreamSupport(t) },
		"Concurrent streams")

	// Send a complete request with connection: close,
	// and read complete reply, then verify that the connection stays open
	// and we can send an additional request
	t.RunTest(func(t *SPDYTester) {
		frame := new(spdy.SynStreamFrame)
		frame.CFHeader.Flags = spdy.ControlFlagFin
		frame.Headers = http.Header{
			"method":     []string{"GET"},
			"version":    []string{"HTTP/1.1"},
			"url":        []string{t.config.GetURL.String()},
			"host":       []string{t.config.GetURL.Host},
			"scheme":     []string{t.config.GetURL.Scheme},
			"connection": []string{"close"}}

		frame.StreamId = 1
		t.framer.WriteFrame(frame)
		t.ExpectReply(1)

		frame.StreamId = 3
		t.framer.WriteFrame(frame)
		t.ExpectReply(3)
	},
		"Connection header ignored")

	t.RunTest(func(t *SPDYTester) {
		syn := new(spdy.SynStreamFrame)
		syn.StreamId = 1
		syn.Headers = http.Header{
			"method":  []string{"POST"},
			"version": []string{"HTTP/1.1"},
			"url":     []string{t.config.PostURL.String()},
			"host":    []string{t.config.PostURL.Host},
			"scheme":  []string{t.config.PostURL.Scheme}}
		//syn.CFHeader.Flags = spdy.ControlFlagFin
		t.framer.WriteFrame(syn)

		rst := new(spdy.RstStreamFrame)
		rst.StreamId = 1
		rst.Status = spdy.Cancel
		t.framer.WriteFrame(rst)

		data := new(spdy.DataFrame)
		data.StreamId = 1
		data.Data = []byte{1, 2, 3}
		t.framer.WriteFrame(data)

		t.ExpectGoAway(1)
	},
		"DATA after RST")

	// Send a complete POST request with an invalid content-length
	t.RunTest(func(t *SPDYTester) {
		syn := new(spdy.SynStreamFrame)
		syn.StreamId = 1
		syn.Headers = http.Header{
			"method":         []string{"POST"},
			"version":        []string{"HTTP/1.1"},
			"url":            []string{t.config.PostURL.String()},
			"host":           []string{t.config.PostURL.Host},
			"scheme":         []string{t.config.PostURL.Scheme},
			"content-length": []string{"10"}}
		t.framer.WriteFrame(syn)

		data := new(spdy.DataFrame)
		data.StreamId = 1
		data.Flags = spdy.DataFlagFin
		data.Data = []byte{1, 2, 3}
		t.framer.WriteFrame(data)

		// 3.2.1 If a server receives a request where the sum of the data frame
		// payload lengths does not equal the size of the Content-Length header,
		// the server MUST return a 400 (Bad Request) error.
		reply := t.ExpectReply(1)
		if status := reply.Headers.Get("status"); !strings.HasPrefix(status, "400") {
			panic("expected 400 status but got: " + status)
		}
	},
		"Incorrect content-length")

	t.RunTest(func(t *SPDYTester) {
		if t.config.PushURL == nil {
			panic("No PushURL specified in config")
		}
		syn := new(spdy.SynStreamFrame)
		syn.StreamId = 1
		syn.CFHeader.Flags = spdy.ControlFlagFin
		syn.Headers = http.Header{
			"method":  []string{"GET"},
			"version": []string{"HTTP/1.1"},
			"url":     []string{t.config.PushURL.String()},
			"host":    []string{t.config.PushURL.Host},
			"scheme":  []string{t.config.PushURL.Scheme}}

		t.framer.WriteFrame(syn)
		t.ExpectPushReply(1)
	}, "Server push")
}

// buildNameValueBlock returns an encoded (but not compressed) Name/Value block
// consisting of the given strings. The number of values is given explicitly so
// that it can be incorrect.
func buildNameValueBlock(spdyVersion spdyVersion, numValues int, values ...string) []byte {
	sizeSize := 2
	if spdyVersion == SPDY3 {
		sizeSize = 4
	}

	length := sizeSize /* num values */
	for _, v := range values {
		length += sizeSize + len(v)
	}

	ret := make([]byte, length)
	x := ret

	if spdyVersion == SPDY3 {
		x[0] = byte(numValues >> 24)
		x[1] = byte(numValues >> 16)
		x = x[2:]
	}
	x[0] = byte(numValues >> 8)
	x[1] = byte(numValues)
	x = x[2:]

	for _, v := range values {
		if spdyVersion == SPDY3 {
			x[0] = byte(len(v) >> 24)
			x[1] = byte(len(v) >> 16)
			x = x[2:]
		}
		x[0] = byte(len(v) >> 8)
		x[1] = byte(len(v))
		x = x[2:]

		copy(x, []byte(v))
		x = x[len(v):]
	}

	if len(x) > 0 {
		panic("internal error")
	}

	return ret
}

// synStreamHeader is a SPDY SYN_STREAM with a zero length a no compressed
// name/value block.
var synStreamHeader = []byte{
	0x80, 0x02, // version = 2
	0x00, 0x01,
	0x01,             // flags
	0x00, 0x00, 0x00, // length (pending)
	0x00, 0x00, 0x00, 0x01, // stream ID
	0x00, 0x00, 0x00, 0x00, // assoc stream ID
	0x00, // priority
	0x00, // unused
}

// buildSynStreamWithNameValueData compresses the given name/value data and
// returns a SYN_STREAM frame using it.
func buildSynStreamWithNameValueData(nameValueData []byte) []byte {
	compressBuf := new(bytes.Buffer)
	compressor, _ := zlib.NewWriterLevelDict(compressBuf, zlib.BestCompression, []byte(spdy.HeaderDictionary))
	compressor.Write(nameValueData)
	compressor.Flush()

	var bytes []byte
	bytes = append(bytes, synStreamHeader...)
	bytes = append(bytes, compressBuf.Bytes()...)
	length := len(bytes) - 8
	bytes[5] = byte(length >> 16)
	bytes[6] = byte(length >> 8)
	bytes[7] = byte(length)

	return bytes
}

func CheckNameValueBlocks(t *TestRunner) {
	t.RunTest(func(t *SPDYTester) {
		var bytes []byte
		bytes = append(bytes, synStreamHeader...)
		// append invalid zlib data
		bytes = append(bytes, []byte{0x42, 0x42, 0x42}...)
		bytes[7] = byte(len(bytes) - 8)
		// Shouldn't the last good stream ID here be zero?
		t.SendDataAndExpectGoAway(bytes, 1)
	}, "Send SYN_STREAM with bad zlib data")

	t.RunTest(func(t *SPDYTester) {
		bytes := buildSynStreamWithNameValueData(buildNameValueBlock(t.version, 5,
			"method", "GET",
			"version", "HTTP/1.1",
			"url", t.config.GetURL.String(),
			"host", t.config.GetURL.Host,
			"scheme", t.config.GetURL.Scheme,
		))
		t.SendDataAndExpectValidReply(bytes)
	}, "Send SYN_STREAM with valid NV block")

	t.RunTest(func(t *SPDYTester) {
		bytes := buildSynStreamWithNameValueData(buildNameValueBlock(t.version, 5,
			"Method", "GET",
			"version", "HTTP/1.1",
			"url", t.config.GetURL.String(),
			"host", t.config.GetURL.Host,
			"scheme", t.config.GetURL.Scheme,
		))
		t.SendDataAndExpectGoAway(bytes, 0)
	}, "Send SYN_STREAM with uppercase header")

	t.RunTest(func(t *SPDYTester) {
		bytes := buildSynStreamWithNameValueData(buildNameValueBlock(t.version, 6,
			"method", "GET",
			"version", "HTTP/1.1",
			"url", t.config.GetURL.String(),
			"host", t.config.GetURL.Host,
			"scheme", t.config.GetURL.Scheme,
			"", "bar",
		))
		t.SendDataAndExpectGoAway(bytes, 0)
	}, "Send SYN_STREAM with empty name")

	t.RunTest(func(t *SPDYTester) {
		bytes := buildSynStreamWithNameValueData(buildNameValueBlock(t.version, 6,
			"method", "GET",
			"version", "HTTP/1.1",
			"url", t.config.GetURL.String(),
			"host", t.config.GetURL.Host,
			"scheme", t.config.GetURL.Scheme,
			"foo", "",
		))
		t.SendDataAndExpectValidReply(bytes)
	}, "Send SYN_STREAM with empty value")

	t.RunTest(func(t *SPDYTester) {
		nvBlock := buildNameValueBlock(t.version, 5,
			"method", "GET",
			"version", "HTTP/1.1",
			"url", t.config.GetURL.String(),
			"host", t.config.GetURL.Host,
			"scheme", t.config.GetURL.Scheme,
		)
		nvBlock = append(nvBlock, 0)
		bytes := buildSynStreamWithNameValueData(nvBlock)
		t.SendDataAndExpectGoAway(bytes, 0)
	}, "Send SYN_STREAM with garbage after NV block")

	t.RunTest(func(t *SPDYTester) {
		bytes := buildSynStreamWithNameValueData(buildNameValueBlock(t.version, 6,
			"method", "GET",
			"method", "GET",
			"version", "HTTP/1.1",
			"url", t.config.GetURL.String(),
			"host", t.config.GetURL.Host,
			"scheme", t.config.GetURL.Scheme,
		))
		t.SendDataAndExpectGoAway(bytes, 0)
	}, "Send SYN_STREAM with duplicate header")

	t.RunTest(func(t *SPDYTester) {
		bytes := buildSynStreamWithNameValueData(buildNameValueBlock(t.version, 6,
			"method", "GET",
			"version", "HTTP/1.1",
			"url", t.config.GetURL.String(),
			"host", t.config.GetURL.Host,
			"scheme", t.config.GetURL.Scheme,
		))
		t.SendDataAndExpectGoAway(bytes, 0)
	}, "Send SYN_STREAM with too large NV count")

	t.RunTest(func(t *SPDYTester) {
		bytes := buildSynStreamWithNameValueData(buildNameValueBlock(t.version, 4,
			"method", "GET",
			"version", "HTTP/1.1",
			"url", t.config.GetURL.String(),
			"host", t.config.GetURL.Host,
			"scheme", t.config.GetURL.Scheme,
		))
		t.SendDataAndExpectGoAway(bytes, 0)
	}, "Send SYN_STREAM with too small NV count")

	t.RunTest(func(t *SPDYTester) {
		block := buildNameValueBlock(t.version, 0,
			"method", "GET",
			"version", "HTTP/1.1",
			"url", t.config.GetURL.String(),
			"host", t.config.GetURL.Host,
			"scheme", t.config.GetURL.Scheme,
		)
		// Alter the number of headers to be huge
		block[0] = 0x7f
		bytes := buildSynStreamWithNameValueData(block)
		t.SendDataAndExpectGoAway(bytes, 0)
	}, "Send SYN_STREAM with huge NV count")

	t.RunTest(func(t *SPDYTester) {
		block := buildNameValueBlock(t.version, 0,
			"method", "GET",
			"version", "HTTP/1.1",
			"url", t.config.GetURL.String(),
			"host", t.config.GetURL.Host,
			"scheme", t.config.GetURL.Scheme,
		)
		// Alter the number of headers to be possibly negative. This
		// might get by a sanity check in a buggy server.
		block[0] = 0x81
		bytes := buildSynStreamWithNameValueData(block)
		t.SendDataAndExpectGoAway(bytes, 0)
	}, "Send SYN_STREAM with possibly negative NV count")

	t.RunTest(func(t *SPDYTester) {
		block := buildNameValueBlock(t.version, 5,
			"method", "GET",
			"version", "HTTP/1.1",
			"url", t.config.GetURL.String(),
			"host", t.config.GetURL.Host,
			"scheme", t.config.GetURL.Scheme,
		)
		// Alter the first key length to be huge
		block[4] = 0x7f
		bytes := buildSynStreamWithNameValueData(block)
		t.SendDataAndExpectGoAway(bytes, 0)
	}, "Send SYN_STREAM with huge NV key length")

	t.RunTest(func(t *SPDYTester) {
		block := buildNameValueBlock(t.version, 5,
			"method", "GET",
			"version", "HTTP/1.1",
			"url", t.config.GetURL.String(),
			"host", t.config.GetURL.Host,
			"scheme", t.config.GetURL.Scheme,
		)
		// Alter the first key length to be possibly negative
		block[4] = 0x81
		bytes := buildSynStreamWithNameValueData(block)
		t.SendDataAndExpectGoAway(bytes, 0)
	}, "Send SYN_STREAM with possibly negative NV key length")

	t.RunTest(func(t *SPDYTester) {
		compressBuf := new(bytes.Buffer)
		compressor, _ := zlib.NewWriterLevelDict(compressBuf, zlib.BestCompression, []byte(spdy.HeaderDictionary))
		// 1 MB of NULs
		nuls := make([]byte, 1024)
		for i := 0; i < 1024; i++ {
			compressor.Write(nuls)
		}
		compressor.Flush()

		var bytes []byte
		bytes = append(bytes, synStreamHeader...)
		bytes = append(bytes, compressBuf.Bytes()...)
		length := len(bytes) - 8
		bytes[5] = byte(length >> 16)
		bytes[6] = byte(length >> 8)
		bytes[7] = byte(length)
		t.SendDataAndExpectGoAway(bytes, 1)
	}, "Send SYN_STREAM with huge NV block")
}

func CheckConcurrentStreamSupport(t *SPDYTester) {
	// Open up lots of streams and see what happens! :>
	// This test takes maxStreams+1 RTTs to the server so we increase the
	// read timeout.
	t.SetReadTimeout(10 * time.Second)

	var buf bytes.Buffer
	framer, err := spdy.NewFramer(&buf, &buf)
	if err != nil {
		panic(err)
	}

	maxStreams := t.config.MaxStreams
	var allBytes []byte
	for i := 0; i < maxStreams+1; i++ {
		headers :=
			http.Header{
				"method":  []string{"POST"},
				"version": []string{"HTTP/1.1"},
				"url":     []string{t.config.GetURL.String()},
				"host":    []string{t.config.GetURL.Host},
				"scheme":  []string{t.config.GetURL.Scheme}}

		frame := new(spdy.SynStreamFrame)
		frame.StreamId = uint32(2*i + 1)
		frame.Headers = headers
		framer.WriteFrame(frame)
		frameBytes := buf.Bytes()
		buf.Reset()

		frameBytes[4] = 0x00 // clear FLAG_FIN
		allBytes = append(allBytes, frameBytes...)
	}

	t.conn.Write(allBytes)

	// We've now sent 1 too many streams
	// Verify that we get a rst stream for the most recent stream
	t.ExpectRstStream(uint32(2*(maxStreams)+1), spdy.RefusedStream)

	// Now finish each of the frames and read the reply
	for i := maxStreams - 1; i >= 0; i-- {
		frame := new(spdy.DataFrame)
		frame.Flags = spdy.DataFlagFin
		frame.StreamId = uint32(2*i + 1)
		framer.WriteFrame(frame)
		t.conn.Write(buf.Bytes())
		buf.Reset()
		t.ExpectReply(frame.StreamId)
	}
}

func CheckSynReplySupport(t *TestRunner) {
	t.RunTest(func(t *SPDYTester) {
		bytes := CreateControlFrameBytes(2, uint16(spdy.TypeSynReply), 0, 0)
		t.SendDataAndExpectGoAway(bytes, 0)
	},
		"GOAWAY after empty SYN_REPLY")
	// In general client should not be sending SYN_REPLY.
	// How to test server push?
}

func CheckRstStreamSupport(t *TestRunner) {
	validLength := 8
	// Try various invalid sizes
	for i := 0; i < validLength*2; i++ {
		if i == validLength {
			continue
		}
		t.RunTest(func(t *SPDYTester) {
			bytes := CreateControlFrameBytes(
				2, uint16(spdy.TypeRstStream), 0, uint8(i))
			t.SendDataAndExpectGoAway(bytes, 0)
		},
			fmt.Sprintf("GOAWAY after invalid RST_STREAM length (%d)", i))
	}

	for i := 0; i < 16; i++ {
		t.RunTest(func(t *SPDYTester) {
			bytes := CreateControlFrameBytes(
				2, uint16(spdy.TypeRstStream), 0, 8)
			bytes[15] = uint8(i)
			t.SendDataAndExpectGoAway(bytes, 0)
		},
			fmt.Sprintf("GOAWAY after invalid RST_STREAM flags (%d)", i))
	}

	t.RunTest(func(t *SPDYTester) {
		bytes := CreateControlFrameBytes(
			2, uint16(spdy.TypeRstStream), 0, 8)
		bytes[11] = 3 // stream id that has not been opened
		t.SendDataAndExpectGoAway(bytes, 0)
	},
		"GOAWAY after invalid Stream ID in RST_STREAM")
}

func CheckPingSupport(t *TestRunner) {
	validLength := 4
	// Try various invalid sizes
	for i := 0; i < validLength*2; i++ {
		if i == validLength {
			continue
		}
		t.RunTest(func(t *SPDYTester) {
			bytes := CreateControlFrameBytes(
				2, uint16(spdy.TypePing), 0, uint8(i))
			t.SendDataAndExpectGoAway(bytes, 0)
		},
			fmt.Sprintf("GOAWAY after invalid PING size: %d", i))
	}

	// Try various invalid (even) ids
	for i := uint8(0); i < 8; i += 2 {
		t.RunTest(func(t *SPDYTester) {
			bytes := CreateControlFrameBytes(
				2, uint16(spdy.TypePing), 0, 4)
			bytes[11] = i
			t.SendDataAndExpectGoAway(bytes, 0)
		},
			fmt.Sprintf("GOAWAY after invalid PING id (%d)", i))
	}

	t.RunTest(func(t *SPDYTester) {
		bytes := CreateControlFrameBytes(
			2, uint16(spdy.TypePing), 0, 4)
		bytes[11] = 0xFF
		t.SendDataAndExpectPing(bytes)
	},
		"PING response")
}

func CheckGoAwaySupport(t *TestRunner) {
	validLength := 8
	// Try various invalid sizes
	for i := 0; i < validLength*2; i++ {
		if i == validLength {
			continue
		}
		t.RunTest(func(t *SPDYTester) {
			bytes := CreateControlFrameBytes(
				2, uint16(spdy.TypeGoAway), 0, uint8(validLength))
			t.SendDataAndExpectGoAway(bytes, 0)
		},
			fmt.Sprintf("GOAWAY after invalid GOAWAY size: %d", i))
	}
}

func CheckHeadersSupport(t *TestRunner) {
	t.RunTest(func(t *SPDYTester) {
		bytes := CreateControlFrameBytes(
			2, uint16(spdy.TypeHeaders), 0, 0)
		t.SendDataAndExpectGoAway(bytes, 0)
	},
		"GOAWAY after empty HEADERS")

	t.RunTest(func(t *SPDYTester) {
		bytes := CreateControlFrameBytes(
			2, uint16(spdy.TypeHeaders), 0, 4)
		bytes[11] = 1 // stream id
		t.SendDataAndExpectGoAway(bytes, 0)
	},
		"GOAWAY after HEADERS for non open stream")

	t.RunTest(func(t *SPDYTester) {
		syn := new(spdy.SynStreamFrame)
		syn.StreamId = 1
		syn.Headers = http.Header{}

		headers := new(spdy.HeadersFrame)
		headers.StreamId = 1
		headers.Headers = http.Header{
			"method":  []string{"GET"},
			"version": []string{"HTTP/1.1"},
			"url":     []string{t.config.GetURL.String()},
			"host":    []string{t.config.GetURL.Host},
			"scheme":  []string{t.config.GetURL.Scheme}}

		t.framer.WriteFrame(syn)
		t.framer.WriteFrame(headers)
		t.ExpectReply(1)
	},
		"Valid reply after SYN_STREAM + HEADERS")

	// For valid stream need to check for.
	// number of pairs >0 when length = 4
	// lenght of name that extends past end of frame
	// length of value that extends past end of frame
}

func CheckWindowUpdateSupport(t *TestRunner) {
	validLength := 8
	// Try various invalid sizes
	for i := 0; i < validLength*2; i++ {
		if i == validLength {
			continue
		}
		t.RunTest(func(t *SPDYTester) {
			bytes := CreateControlFrameBytes(
				2, uint16(spdy.TypeWindowUpdate), 0, uint8(validLength))
			t.SendDataAndExpectGoAway(bytes, 0)
		},
			fmt.Sprintf("GOAWAY after invalid WINDOW_UPDATE size: %d", i))
	}
}

func CheckSettingsSupport(t *TestRunner) {
	t.RunTest(func(t *SPDYTester) {
		bytes := CreateControlFrameBytes(
			2, uint16(spdy.TypeSettings), 0, 0)
		t.SendDataAndExpectGoAway(bytes, 0)
	},
		"GOAWAY after empty SETTINGS")

	t.RunTest(func(t *SPDYTester) {
		bytes := CreateControlFrameBytes(
			2, uint16(spdy.TypeSettings), 0, 4)
		bytes[11] = 0
		t.SendDataAndExpectGoAway(bytes, 0)
	},
		"GOAWAY after SETTINGS with no id/values")

	t.RunTest(func(t *SPDYTester) {
		bytes := CreateControlFrameBytes(
			2, uint16(spdy.TypeSettings), 0, 8)
		bytes[11] = 1
		bytes[12] = 1 // SETTINGS_UPLOAD_BANDWIDTH
		bytes[14] = 4
		// TODO: test accepted in some way
		t.SendDataAndExpectGoAway(bytes, 0)
	},
		"GOAWAY after SETTINGS with valid id / value")

	t.RunTest(func(t *SPDYTester) {
		bytes := CreateControlFrameBytes(
			2, uint16(spdy.TypeSettings), 0, 8)
		bytes[11] = 1 // a single setting
		bytes[12] = 0xFF
		bytes[15] = 0xff
		t.SendDataAndExpectGoAway(bytes, 0)
	},
		"GOAWAY after SETTINGS with invalid setting flag")
}

func CheckCredentialSupport(t *TestRunner) {
	t.RunTest(func(t *SPDYTester) {
		bytes := CreateControlFrameBytes(
			2, uint16(spdy.TypeWindowUpdate)+1, 0, 0)
		t.SendDataAndExpectGoAway(bytes, 0)
	},
		"GOAWAY after empty CREDENTIAL")
	/*
		bytes = CreateControlFrameBytes(
			2, uint16(spdy.TypeSettings), 0, 8)
		bytes[11] = 1 // a single setting
		bytes[12] = 0xFF
		bytes[15] = 0xff
		t.RunTest(func(t *SPDYTester) { t.SendDataAndExpectGoAway(bytes) },
			"GOAWAY after SETTINGS with invalid setting flag")
	*/
}

func CheckDataSupport(t *TestRunner) {
	// 2.2.2: If an endpoint receives a data frame for a stream-id which is not
	// open and the endpoint has not sent a GOAWAY (Section 2.6.6) frame, it
	// MUST send issue a stream error (Section 2.4.2) with the error code
	// INVALID_STREAM for the stream-id.
	t.RunTest(func(t *SPDYTester) {
		data := new(spdy.DataFrame)
		data.StreamId = 1
		t.framer.WriteFrame(data)
		t.ExpectRstStream(0, spdy.InvalidStream)
	},
		"RST_STREAM after DATA frame for invalid stream")

	// 2.2.2: If the endpoint which created the stream receives a data frame
	// before receiving a SYN_REPLY on that stream, it is a protocol error,
	// and the recipient MUST issue a stream error (Section 2.4.2) with
	// the status code PROTOCOL_ERROR for the stream-id.

	// 2.2.2: All SPDY endpoints MUST accept compressed data frames.
	// Compression of data frames is always done using zlib compression. Each
	// stream initializes and uses its own compression context dedicated to use
	// within that stream. Endpoints are encouraged to use application
	// level compression rather than SPDY stream level compression.

	// 2.2.2 Each SPDY stream sending compressed frames creates its own zlib
	// context for that stream. (Thus, if both endpoints of a stream are
	// compressing data on the stream, there will be two zlib contexts, one
	// for sending and one for receiving).
}

// ----------------------------------------------------------------------
func main() {

	if len(os.Args) == 1 {
		fmt.Printf("usage: spdy_compliance <config> [<test> ...]\n")
		os.Exit(1)
	}
	// TODO(rch): figure out how to detect a tty, and conditionally enable color
	useColor := true
	t, err := NewTestRunner(useColor, os.Args[1], os.Args[2:])
	if err != nil {
		panic("Error: " + err.Error())
	}
	if err := t.FetchSettings(); err != nil {
		panic("Failed to fetch SETTINGS frame: " + err.Error())
	}

	CheckNextProtocolNegotiationSupport(t)
	CheckInvalidControlFrameDetection(t)
	CheckSynStreamSupport(t)
	CheckNameValueBlocks(t)
	CheckSynReplySupport(t)
	CheckRstStreamSupport(t)
	CheckSettingsSupport(t)
	CheckPingSupport(t)
	CheckGoAwaySupport(t)
	CheckHeadersSupport(t)
	// TODO(rch): conditionally test spdy/3 functionality
	//CheckWindowUpdateSupport(t)
	//CheckCredentialSupport(t)
	CheckDataSupport(t)

	// HTTP layering
	// If a client sends a HEADERS without all of the method, host, path, scheme, and version headers, the server MUST reply with a HTTP 400 Bad Request reply.
	// If a server receives a request where the sum of the data frame payload lengths does not equal the size of the Content-Length header, the server MUST return a 400 (Bad Request) error.
	// check that response headers are all lowercase

	if !t.Summarize() {
		os.Exit(1)
	}
}
