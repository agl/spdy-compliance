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
//   "PostUrl":   "http://www.google.com",
//   "GetUrl":   "http://www.google.com",
//   "MaxStreams": 101
//   "DisabledTests": [
//     "GOAWAY after empty SYN_REPLY"
//   ]
// }
//
// Compile and run with:
// % 6g spdy_compliance.go && 6l spdy_compliance.6 && ./6.out <config.json>

package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"http"
	"http/spdy"
	"io/ioutil"
	"json"
	"os"
	"time"
	"url"
)

// Various ANSI escape sequences 
const (
	RED    = "[0;31m"
	GREEN  = "[0;32m"
	YELLOW = "[0;33m"
	BOLD   = "[1m"
	NORMAL = "[0m"
)

// ----------------------------------------------------------------------

// A TestConfig defines the parameters for configuring a SPDY compliance
// test.
type TestConfig struct {
	Endpoint      string
	GetUrl        *url.URL
	PostUrl       *url.URL  
	PushUrl       *url.URL  // URL that will result in resources being pushed
	DisabledTests []string
	MaxStreams    int
}

// Loads the configuration data from a file.
func (t *TestConfig) Load(filename string) {
	var i interface{}
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		panic(err)
	}
	err = json.Unmarshal(data, &i)
	if err != nil {
		panic(err)
	}
	m := i.(map[string]interface{})
	t.Endpoint = m["Endpoint"].(string)
	t.MaxStreams = int(m["MaxStreams"].(float64))
	t.GetUrl = t.ParseAsUrl(m["GetUrl"])
	t.PostUrl = t.ParseAsUrl(m["PostUrl"])
	t.PushUrl = t.ParseAsUrl(m["PushUrl"])
	disabled := m["DisabledTests"].([]interface{})
	for _, s := range disabled {
		t.DisabledTests = append(t.DisabledTests, s.(string))
	}
}

func (t *TestConfig) ParseAsUrl(u interface{}) *url.URL {
	if u == nil {
		return nil
	}
		url, err := url.Parse(u.(string))
		if err != nil {
			panic(err)
	}
	return url
}

// ----------------------------------------------------------------------

// A TestRunner runs a number of tests, and records the results.
// If a test panics, the TestRunner will recover, and mark the test
// as failed.
type TestRunner struct {
	config           TestConfig // test configuration
	numTests         int        // total number of tests run
	numDisabledTests int        // total number of disabled tests
	failedTests      []string   // list of test descriptions that failed
	useColor         bool       // if true, then ansi color will be used in the output
	args             []string   // list of command line arguments used to restrict
	// the actual set of tests to be run
	elapsedTime      int64      // Total number of nanoseconds spent executing tests
}

func NewTestRunner(useColor bool, config string, args []string) *TestRunner {
	t := new(TestRunner)
	t.useColor = useColor
	t.args = args
	t.config.Load(config)
	//fmt.Printf("%s\n", t.config)
	return t
}

// Logs a formatted descriptive message with the status text displayed
// in the specified color, followed by the description.
func (t *TestRunner) Log(color, status, description string) {
	if t.useColor {
		fmt.Printf("%s[%s]%s %s\n", color, status, NORMAL, description)
	} else {
		fmt.Printf("[%s] %s\n", status, description)
	}
}

// Runs the specified test, and records the results.  The test will be
// marked as failed if it panics.
func (t *TestRunner) RunTest(test func(*SpdyTester), description string) {
	if len(t.args) > 0 {
		match := false
		for _, arg := range t.args {
			// fmt.Printf("checking: %s\n", arg)
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
		//fmt.Printf("%s ?= %s\n", disabled, description)
		if disabled == description {
			//fmt.Printf("disabled == description\n")
			t.DisabledTest(test, description)
			return
		}
	}

	t.Log(GREEN, " RUN      ", description)
  start := time.Nanoseconds()
	defer t.Finished(description, start)
	tester := NewSpdyTester(&t.config)
	defer tester.Close()
	test(tester)
}

// Marks the test as disabled, and does not run it.
func (t *TestRunner) DisabledTest(f func(t *SpdyTester), description string) {
	t.numDisabledTests++
	t.Log(YELLOW, " DISABLED ", description)
}

// Handles the completion of a test by calling recover and looking for
// a panic.
func (t *TestRunner) Finished(description string, start int64) {
	end := time.Nanoseconds()
	delta := end - start
	t.elapsedTime += delta
	t.numTests++
	err := recover()
	
	text := fmt.Sprintf("%s (%d ms)", description, delta / 1000000)
	if err != nil {
		if t.useColor {
			fmt.Printf("%sERROR%s: %s\n", BOLD, NORMAL, err)
		} else {
			fmt.Printf("ERROR: %s\n", err)
		}
		t.Log(RED, "  FAILED  ", text)
		t.failedTests = append(t.failedTests, description)
	} else {
		t.Log(GREEN, "       OK ", text)
	}
}

// Prints a textual summary of all the test run.
func (t *TestRunner) Summarize() bool {
	t.Log(GREEN, "==========",
		fmt.Sprintf("%d tests ran. (%d ms total)", t.numTests, t.elapsedTime / 1000000))

	t.Log(GREEN, "  PASSED  ",
		fmt.Sprintf("%d tests.", t.numTests-len(t.failedTests)))

	t.Log(YELLOW, " DISABLED ", fmt.Sprintf("%d tests", t.numDisabledTests))

	if len(t.failedTests) != 0 {
		t.Log(RED, "  FAILED  ",
			fmt.Sprintf("%d tests, listed below:", len(t.failedTests)))

		for _, test := range t.failedTests {
			t.Log(RED, "  FAILED  ", test)
		}
		return false
	}
	return true
}

// ----------------------------------------------------------------------

// Utility function for creating a sequence of bytes that represents 
// a (probably invalid) SPDY control frame.
func CreateControlFrameBytes(
	version uint8, frameType uint16,
	flags uint8, length uint8) []byte {
	bytes := make([]byte, 8+length, 8+length)
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

type SpdyTester struct {
	conn   *tls.Conn
	framer *spdy.Framer
	config *TestConfig
}

func NewSpdyTester(config *TestConfig) *SpdyTester {
	var sessionTester = new(SpdyTester)
	sessionTester.config = config
	sessionTester.init([]string{"spdy/2"})
	return sessionTester
}

func (t *SpdyTester) init(nextProtos []string) {
	var tlsConfig = new(tls.Config)
	tlsConfig.NextProtos = nextProtos
	conn, err := tls.Dial("tcp", t.config.Endpoint, tlsConfig)
	if err != nil {
		panic(err)
	}
	// Timeout reads after 1 second.  This causes an ERR_IO_PENDING error
	// to be returned when attempting to read a frame, and allows us
	// to detect when the server has failed to reply (quickly enough)
	// to one of our requests
	conn.SetReadTimeout(1000000000)
	t.conn = conn
	t.framer, err = spdy.NewFramer(conn, conn)
	if err != nil {
		panic(err)
	}
}

func (t *SpdyTester) Close() {
	t.conn.Close()
}

// Returns the protocol negotiated during the handshake, or the empty string
// if no protocol was agreed upon.
func (t *SpdyTester) NegotiatedProtocol() string {
	if !t.conn.ConnectionState().NegotiatedProtocolIsMutual {
		return ""
	}
	return t.conn.ConnectionState().NegotiatedProtocol
}

func (t *SpdyTester) CreateSynStreamFrameBytes(streamId int) []byte {
	frame := new(spdy.SynStreamFrame)
	frame.StreamId = uint32(streamId)
	frame.CFHeader.Flags = spdy.ControlFlagFin
	frame.Headers = http.Header{
		"method":  []string{"GET"},
		"version": []string{"HTTP/1.1"},
		"url":     []string{t.config.GetUrl.Raw},
		"host":    []string{t.config.GetUrl.Host},
		"scheme":  []string{t.config.GetUrl.Scheme}}

	buf := new(bytes.Buffer)
	framer, err := spdy.NewFramer(buf, buf)
	if err != nil {
		fmt.Printf("ERROR: %s", err)
	}
	framer.WriteFrame(frame)

	bytes := buf.Bytes()
	return bytes
}

// Returns the next frame read from the framer that is not a SETTINGS frame.
func (t *SpdyTester) ReadNextNonSettingsFrame() (spdy.Frame, os.Error) {
	for true {
		//		fmt.Printf("Reading frame...\n")
		frame, err := t.framer.ReadFrame()
		//		fmt.Printf("Done.\n")
		if err != nil {
			return nil, err
		}
		//fmt.Printf("ReadFrame! %s\n", frame)
		_, ok := frame.(*spdy.SettingsFrame)
		if !ok {
			return frame, nil
		}
		//fmt.Printf("SETTINGS: %s\n", frame)
	}
	panic("unreachable")
}

// Panics unless the non-settings frame is not a GOAWAY frame
func (t *SpdyTester) ExpectGoAway(lastGoodStreamId int) {
	frame, err := t.ReadNextNonSettingsFrame()
	if err != nil {
		panic(err)
	}
	goAwayFrame, ok := frame.(*spdy.GoAwayFrame)
	if !ok {
		panic(fmt.Sprintf("Expected GOAWAY, received: %s", frame))
	}
	if goAwayFrame.LastGoodStreamId != uint32(lastGoodStreamId) {
		panic(fmt.Sprintf("Incorrect LastGoodStreamId: expected 0 got %d",
			goAwayFrame.LastGoodStreamId))
	}

	t.ExpectEOF()
}

// Panics unless the next read from the session returns EOF.
func (t *SpdyTester) ExpectEOF() {
	frame, err := t.ReadNextNonSettingsFrame()
	if frame != nil {
		panic(fmt.Sprintf("Unexpected frame after %s", frame))
	}
	if err != os.EOF {
		panic(fmt.Sprintf("Unexpected error: %s", err))
	}
}

// Panics if the next non-settings frame is not a PING frame.
func (t *SpdyTester) ExpectPing(id uint32) {
	frame, err := t.ReadNextNonSettingsFrame()
	if err != nil {
		panic(fmt.Sprintf("Unexpected error: %s", err))
	}

	pingFrame, ok := frame.(*spdy.PingFrame)
	if !ok {
		panic(fmt.Sprintf("Not a ping frame.  Parsed incorrect frame type: %s",
			frame))
	}
	if pingFrame.Id != id {
		panic(fmt.Sprintf("Incorrect id: expected %d got %d",
			id, pingFrame.Id))
	}
}

// Panics if the next non-settings frame is not a RST_STREAM frame
// with StreamID set to id.
func (t *SpdyTester) ExpectRstStream(id uint32, status spdy.StatusCode) {
	frame, err := t.ReadNextNonSettingsFrame()
	if err != nil {
		panic(fmt.Sprintf("Unexpected error: %s", err))
	}

	rst, ok := frame.(*spdy.RstStreamFrame)
	if !ok {
		panic(fmt.Sprintf("Expected an RST_STREAM frame, received: %s", frame))
	}
	if rst.StreamId != id {
		panic(fmt.Sprintf("Incorrect id: expected %d got %d", id, rst.StreamId))
	}
	if rst.Status != status {
		panic(fmt.Sprintf("Incorrect status: expected %s got %s",
			status, rst.Status))
	}
}

// Check that a SYN_REPLY frame is received as the first non-settings frame
// followed by optional data frames until receipt of a frame with FIN set.
func (t *SpdyTester) ExpectReply(id uint32) {
	frame, err := t.ReadNextNonSettingsFrame()
	if err != nil {
		panic(fmt.Sprintf("Unexpected error: %s", err))
	}

	reply, ok := frame.(*spdy.SynReplyFrame)
	if !ok {
		panic(fmt.Sprintf("Expected an SYN_REPLY frame, received: %s", frame))
	}
	if reply.StreamId != id {
		panic(fmt.Sprintf("Incorrect id: expected %d got %d", id, reply.StreamId))
	}
	if reply.CFHeader.Flags != spdy.ControlFlagFin {
		for true {
			frame, err := t.ReadNextNonSettingsFrame()
			if err != nil {
				panic(fmt.Sprintf("Unexpected error: %s", err))
			}
			data, ok := frame.(*spdy.DataFrame)
			if !ok {
				panic(fmt.Sprintf("Expected a DATA frame, received: %s", frame))
			}
			if data.StreamId != id {
				panic(fmt.Sprintf("Incorrect id: expected %d got %d", id, data.StreamId))
			}
			fmt.Printf("FLAGS: %d\n", data.Flags)
			if data.Flags == spdy.DataFlagFin {
				break
			}
		}
	}
}

func (t *SpdyTester) ExpectPushReply(streamId int) {
	dataReceived := false
	pushedIds := make(map[uint32]bool)
	numPushed := 0
	for true {
		frame, err := t.ReadNextNonSettingsFrame()
		if err != nil {
			panic(err)
		}
		reply, ok := frame.(*spdy.SynReplyFrame)
		if ok {
			//fmt.Printf("SYN_REPLY[%d]: %s\n", reply.StreamId, frame)
			if reply.StreamId != uint32(streamId) {
				panic(fmt.Sprintf("Expected repl for stream %d, received %d",
					streamId, reply.StreamId))
			}
			continue
		}
		syn, ok_syn := frame.(*spdy.SynStreamFrame)
		if ok_syn {
			//fmt.Printf("SYN_STREAM[%d]: %s\n", syn.StreamId, frame)
			if dataReceived {
				panic("Stream pushed after data recevied")
			}
			if syn.StreamId % 2 != 0 {
					panic(fmt.Sprintf("Server push stream with odd stream id: %d", 
						syn.StreamId))
			}
			if syn.CFHeader.Flags != 2 {
					panic(fmt.Sprintf("Server push stream was not unidirectional"))
			}
			for k,_ := range pushedIds {
				if syn.StreamId < k {
						panic(fmt.Sprintf("Decreasing stream id: %d", syn.StreamId))
				}
				if syn.StreamId == k {
					panic(fmt.Sprintf("Duplicate stream id: %d", syn.StreamId))
				}
			}
			// TODO(rch): Check for decreasing
			// TODO(rch): Check for even and > 0
			pushedIds[syn.StreamId] = true
			numPushed++
			continue
		}
		data, ok_syn := frame.(*spdy.DataFrame)
		if ok_syn {
			//fmt.Printf("FLAGS: %d\n", data.Flags)
			//fmt.Printf("DATA[%d]: %d\n", data.StreamId, len(data.Data))
			if data.StreamId == 1 {
				dataReceived = true
			} else {
				if data.Flags == spdy.DataFlagFin {
					pushedIds[data.StreamId] = false, false //remove from map
				}
			}
			//fmt.Printf("map: %s %d\n", pushedIds, len(pushedIds))
			if len(pushedIds) == 0 {
				break
			}
		}			
	}
	fmt.Printf("%d\n", numPushed)
	if numPushed == 0 {
		panic("No streams pushed")
	}
}

// ----------------------------------------------------------------------

// Check that a GOAWAY frame is received as the first non-settings frame
// after sending |data|.
func (t *SpdyTester) SendDataAndExpectGoAway(data []uint8, lastGoodStreamId int) {
	t.conn.Write(data)
	t.ExpectGoAway(lastGoodStreamId)
}

// Check that a RST_STREAM frame is received as the first non-settings frame
// after sending |data|.
func (t *SpdyTester) SendDataAndExpectRstStream(data []uint8, streamId int, status spdy.StatusCode) {
	t.conn.Write(data)
	t.ExpectRstStream(uint32(streamId), status)
}

// Check that a SYN_REPLY frame is received as the first non-settings frame
// after sending |data|.
func (t *SpdyTester) SendDataAndExpectValidReply(data []uint8) {
	t.conn.Write(data)
	t.ExpectReply(1)
}

// Check that a PING frame is received as the first non-settings frame
// after sending |data|.
func (t *SpdyTester) SendDataAndExpectPing(data []uint8) {
	t.conn.Write(data)
	t.ExpectPing(uint32(data[11]))
}

// Tests that the server support NPN negotiation for
// all the various protocols and versions.
func CheckNextProtocolNegotiationSupport(t *TestRunner) {
	protos := [...]string{"http/1.1", "spdy/2", "spdy/2.1", "spdy/3"}
	for _, proto := range protos {
		t.RunTest(
			func(t *SpdyTester) {
				t.Close()
				t.init([]string{proto})
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
		func(t *SpdyTester) {
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
	t.RunTest(func(t *SpdyTester) {
		bytes := CreateControlFrameBytes(3, uint16(spdy.TypeNoop), 0, 0)
		t.SendDataAndExpectGoAway(bytes, 0)
	},
		"GOAWAY after invalid version in control frame")

	// Invalid control frame type
	// TODO(rch): actually, according to the spec:
	// If an endpoint receives a control frame for a type it does not recognize,
	// it MUST ignore the frame.
	t.RunTest(func(t *SpdyTester) {
		bytes := CreateControlFrameBytes(
			2, uint16(spdy.TypeWindowUpdate)+6, 0, 0)
		t.SendDataAndExpectGoAway(bytes, 0)
		// after sending this packet, send a ping and expect a ping?
	},
		"GOAWAY after invalid control frame type")
}

func CheckSynStreamSupport(t *TestRunner) {
	t.RunTest(func(t *SpdyTester) {
		// Bogus flags
		bytes := t.CreateSynStreamFrameBytes(1)
		bytes[4] = 0xFF
		//	bytes[11] = 1  // stream id
		//	DumpBytes(bytes)
		t.SendDataAndExpectGoAway(bytes, 0)
	},
		"GOAWAY after invalid SYN_STREAM flags")

	t.RunTest(func(t *SpdyTester) {
		bytes := t.CreateSynStreamFrameBytes(1)
		bytes[7] = 0x0 // no length
		t.SendDataAndExpectGoAway(bytes, 0)
	},
		"GOAWAY after invalid SYN_STREAM length")

	t.RunTest(func(t *SpdyTester) {
		bytes := t.CreateSynStreamFrameBytes(2)
		//	DumpBytes(bytes)
		t.SendDataAndExpectGoAway(bytes, 0)
	},
		"GOAWAY after invalid SYN_STREAM StreamID (2)")

	t.RunTest(func(t *SpdyTester) {
		bytes := t.CreateSynStreamFrameBytes(0)
		//	DumpBytes(bytes)
		t.SendDataAndExpectGoAway(bytes, 0)
	},
		"GOAWAY after invalid SYN_STREAM StreamID (0)")

	t.RunTest(func(t *SpdyTester) {
		bytes := t.CreateSynStreamFrameBytes(1)
		//	DumpBytes(bytes)
		t.SendDataAndExpectValidReply(bytes)
	},
		"Valid response to SYN_STREAM")

	t.RunTest(func(t *SpdyTester) {
		// try sending same syn stream again
		bytes := t.CreateSynStreamFrameBytes(1)
		bytes = append(bytes, bytes...)
		t.SendDataAndExpectGoAway(bytes, 1)
	},
		"GOAWAY after duplicate SYN_STREAM StreamID")

	t.RunTest(func(t *SpdyTester) {
		// try sending decreasing stream id
		bytes := t.CreateSynStreamFrameBytes(3)
		bytes2 := t.CreateSynStreamFrameBytes(2)
		bytes = append(bytes, bytes2...)
		t.SendDataAndExpectGoAway(bytes, 3)
	},
		"GOAWAY after decreasing SYN_STREAM StreamID")

	t.RunTest(func(t *SpdyTester) { CheckConcurrentStreamSupport(t) },
		"Concurrent streams")

	// Send a complete request with connection: close,
	// and read complete reply, then verify that the connection stays open
	// and we can send an additional request
	t.RunTest(func(t *SpdyTester) {
		frame := new(spdy.SynStreamFrame)
		frame.CFHeader.Flags = spdy.ControlFlagFin
		frame.Headers = http.Header{
			"method":     []string{"GET"},
			"version":    []string{"HTTP/1.1"},
			"url":        []string{t.config.GetUrl.Raw},
			"host":       []string{t.config.GetUrl.Host},
			"scheme":     []string{t.config.GetUrl.Scheme},
			"connection": []string{"close"}}

		frame.StreamId = 1
		t.framer.WriteFrame(frame)
		t.ExpectReply(1)

		frame.StreamId = 3
		t.framer.WriteFrame(frame)
		t.ExpectReply(3)
	},
		"Connection header ignored")

	// Send a complete request with connection: close,
	// and read complete reply, then verify that the connection stays open
	// and we can send an additional request
	t.RunTest(func(t *SpdyTester) {
		syn := new(spdy.SynStreamFrame)
		syn.StreamId = 1
		syn.Headers = http.Header{
			"method":  []string{"POST"},
			"version": []string{"HTTP/1.1"},
			"url":     []string{t.config.PostUrl.Raw},
			"host":    []string{t.config.PostUrl.Host},
			"scheme":  []string{t.config.PostUrl.Scheme}}
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

		t.ExpectGoAway(0)
	},
		"DATA after RST")

	// Send a complete POST request with an invalid content-length
	t.RunTest(func(t *SpdyTester) {
		syn := new(spdy.SynStreamFrame)
		syn.StreamId = 1
		syn.Headers = http.Header{
			"method":         []string{"POST"},
			"version":        []string{"HTTP/1.1"},
			"url":            []string{t.config.PostUrl.Raw},
			"host":           []string{t.config.PostUrl.Host},
			"scheme":         []string{t.config.PostUrl.Scheme},
			"content-length": []string{"10"}}
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

		// 3.2.1 If a server receives a request where the sum of the data frame
		// payload lengths does not equal the size of the Content-Length header,
		// the server MUST return a 400 (Bad Request) error.
		t.ExpectGoAway(0)
	},
		"Incorrect content-length")

	t.RunTest(func(t *SpdyTester) {
		if t.config.PushUrl == nil {
			panic("No PushUrl specified in config")
		}
		syn := new(spdy.SynStreamFrame)
		syn.StreamId = 1
		syn.CFHeader.Flags = spdy.ControlFlagFin
		syn.Headers = http.Header{
			"method":  []string{"GET"},
			"version": []string{"HTTP/1.1"},
			"url":     []string{t.config.PushUrl.Raw},
			"host":    []string{t.config.PushUrl.Host},
			"scheme":  []string{t.config.PushUrl.Scheme}}

		t.framer.WriteFrame(syn)
		t.ExpectPushReply(1)
	}, "Server push")
}

func CheckConcurrentStreamSupport(t *SpdyTester) {
	// Open up lots of streams and see what happens! :>
	buf := new(bytes.Buffer)
	framer, err := spdy.NewFramer(buf, buf)
	if err != nil {
		fmt.Printf("ERROR: %s", err)
	}

	var allBytes []byte
	maxStreams := t.config.MaxStreams
	for i := 0; i < maxStreams+1; i++ {
		headers :=
			http.Header{
				"method":  []string{"POST"},
				"version": []string{"HTTP/1.1"},
				"url":     []string{t.config.GetUrl.Raw},
				"host":    []string{t.config.GetUrl.Host},
				"scheme":  []string{t.config.GetUrl.Scheme}}

		frame := new(spdy.SynStreamFrame)
		frame.StreamId = uint32(2*i + 1)
		frame.Headers = headers
		framer.WriteFrame(frame)
		//fmt.Printf("id: %d\n", frame.StreamId)
		frameBytes := buf.Bytes()
		buf.Reset()
		//fmt.Printf("buf.Len(): %d\n", buf.Len())

		frameBytes[4] = 0x00 // fin
		allBytes = append(allBytes, frameBytes...)
		//fmt.Printf("len(bytes): %d\n", len(allBytes))
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
	t.RunTest(func(t *SpdyTester) {
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
		t.RunTest(func(t *SpdyTester) {
			bytes := CreateControlFrameBytes(
				2, uint16(spdy.TypeRstStream), 0, uint8(i))
			t.SendDataAndExpectGoAway(bytes, 0)
		},
			fmt.Sprintf("GOAWAY after invalid RST_STREAM length (%d)", i))
	}

	for i := 0; i < 16; i++ {
		t.RunTest(func(t *SpdyTester) {
			bytes := CreateControlFrameBytes(
				2, uint16(spdy.TypeRstStream), 0, 8)
			bytes[15] = uint8(i)
			t.SendDataAndExpectGoAway(bytes, 0)
		},
			fmt.Sprintf("GOAWAY after invalid RST_STREAM flags (%d)", i))
	}

	t.RunTest(func(t *SpdyTester) {
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
		t.RunTest(func(t *SpdyTester) {
			bytes := CreateControlFrameBytes(
				2, uint16(spdy.TypePing), 0, uint8(i))
			t.SendDataAndExpectGoAway(bytes, 0)
		},
			fmt.Sprintf("GOAWAY after invalid PING size: %d", i))
	}

	// Try various invalid (even) ids
	for i := uint8(0); i < 8; i += 2 {
		t.RunTest(func(t *SpdyTester) {
			bytes := CreateControlFrameBytes(
				2, uint16(spdy.TypePing), 0, 4)
			bytes[11] = i
			t.SendDataAndExpectGoAway(bytes, 0)
		},
			fmt.Sprintf("GOAWAY after invalid PING id (%d)", i))
	}

	t.RunTest(func(t *SpdyTester) {
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
		t.RunTest(func(t *SpdyTester) {
			bytes := CreateControlFrameBytes(
				2, uint16(spdy.TypeGoAway), 0, uint8(validLength))
			t.SendDataAndExpectGoAway(bytes, 0)
		},
			fmt.Sprintf("GOAWAY after invalid GOAWAY size: %d", i))
	}
}

func CheckHeadersSupport(t *TestRunner) {
	t.RunTest(func(t *SpdyTester) {
		bytes := CreateControlFrameBytes(
			2, uint16(spdy.TypeHeaders), 0, 0)
		t.SendDataAndExpectGoAway(bytes, 0)
	},
		"GOAWAY after empty HEADERS")

	t.RunTest(func(t *SpdyTester) {
		bytes := CreateControlFrameBytes(
			2, uint16(spdy.TypeHeaders), 0, 4)
		bytes[11] = 1 // stream id
		t.SendDataAndExpectGoAway(bytes, 0)
	},
		"GOAWAY after HEADERS for non open stream")

	t.RunTest(func(t *SpdyTester) {
		syn := new(spdy.SynStreamFrame)
		syn.StreamId = 1
		syn.Headers = http.Header{}

		headers := new(spdy.HeadersFrame)
		headers.StreamId = 1
		headers.Headers = http.Header{
			"method":  []string{"GET"},
			"version": []string{"HTTP/1.1"},
			"url":     []string{t.config.GetUrl.Raw},
			"host":    []string{t.config.GetUrl.Host},
			"scheme":  []string{t.config.GetUrl.Scheme}}

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
		t.RunTest(func(t *SpdyTester) {
			bytes := CreateControlFrameBytes(
				2, uint16(spdy.TypeWindowUpdate), 0, uint8(validLength))
			t.SendDataAndExpectGoAway(bytes, 0)
		},
			fmt.Sprintf("GOAWAY after invalid WINDOW_UPDATE size: %d", i))
	}
}

func CheckSettingsSupport(t *TestRunner) {
	t.RunTest(func(t *SpdyTester) {
		bytes := CreateControlFrameBytes(
			2, uint16(spdy.TypeSettings), 0, 0)
		t.SendDataAndExpectGoAway(bytes, 0)
	},
		"GOAWAY after empty SETTINGS")

	t.RunTest(func(t *SpdyTester) {
		bytes := CreateControlFrameBytes(
			2, uint16(spdy.TypeSettings), 0, 4)
		bytes[11] = 0
		t.SendDataAndExpectGoAway(bytes, 0)
	},
		"GOAWAY after SETTINGS with no id/values")

	t.RunTest(func(t *SpdyTester) {
		bytes := CreateControlFrameBytes(
			2, uint16(spdy.TypeSettings), 0, 8)
		bytes[11] = 1
		bytes[12] = 1 // SETTINGS_UPLOAD_BANDWIDTH
		bytes[14] = 4
		// TODO: test accepted in some way
		t.SendDataAndExpectGoAway(bytes, 0)
	},
		"GOAWAY after SETTINGS with valid id / value")

	t.RunTest(func(t *SpdyTester) {
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
	t.RunTest(func(t *SpdyTester) {
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
		t.RunTest(func(t *SpdyTester) { t.SendDataAndExpectGoAway(bytes) }, 
			"GOAWAY after SETTINGS with invalid setting flag")
	*/
}

func CheckDataSupport(t *TestRunner) {
	// 2.2.2: If an endpoint receives a data frame for a stream-id which is not
	// open and the endpoint has not sent a GOAWAY (Section 2.6.6) frame, it 
	// MUST send issue a stream error (Section 2.4.2) with the error code 
	// INVALID_STREAM for the stream-id.
	t.RunTest(func(t *SpdyTester) {
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
	/*
		out, _ := os.Stdout.Stat()
		tty, _ := os.Stat("/dev/tty")
		fmt.Printf("%s\n", tty)
		fmt.Printf("%s\n", out)
	*/
	useColor := true
	t := NewTestRunner(useColor, os.Args[1], os.Args[2:])

	CheckNextProtocolNegotiationSupport(t)
	CheckInvalidControlFrameDetection(t)
	CheckSynStreamSupport(t)
	CheckSynReplySupport(t)
	CheckRstStreamSupport(t)
	CheckSettingsSupport(t)
	CheckPingSupport(t)
	CheckGoAwaySupport(t)
	CheckHeadersSupport(t)
	//CheckWindowUpdateSupport(t)
	CheckCredentialSupport(t)
	CheckDataSupport(t)

	// HTTP layering
	// If a client sends a HEADERS without all of the method, host, path, scheme, and version headers, the server MUST reply with a HTTP 400 Bad Request reply.
	// If a server receives a request where the sum of the data frame payload lengths does not equal the size of the Content-Length header, the server MUST return a 400 (Bad Request) error.
	// check that response headers are all lowercase

	if !t.Summarize() {
		os.Exit(1)
	}
}
