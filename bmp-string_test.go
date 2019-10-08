// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkcs12

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

type bpmStringSizeBytesTest struct {
	input                         string
	expectedSizeSliceLen          byte
	expectedSizeSliceBytes        []byte
	expectedSizeSliceBytesDisplay string
}

type bmpSliceSizeBytesTest struct {
	stringSlice  []byte
	computedSize int
	expectError  bool
}

type bmpMarshalTest struct {
	stringVersion     string
	marshalledVersion []byte
	expectError       bool
}

var (
	bmpStringTests = []struct {
		in          string
		expectedHex string
		shouldFail  bool
	}{
		{"", "0000", false},
		// Example from https://tools.ietf.org/html/rfc7292#appendix-B.
		{"Beavis", "0042006500610076006900730000", false},
		// Some characters from the "Letterlike Symbols Unicode block".
		{"\u2115 - Double-struck N", "21150020002d00200044006f00750062006c0065002d00730074007200750063006b0020004e0000", false},
		// any character outside the BMP should trigger an error.
		{"\U0001f000 East wind (Mahjong)", "", true},
	}

	marshalTest = []bmpMarshalTest{
		{
			stringVersion:     "",
			marshalledVersion: []byte{30, 0},
		},
		{
			stringVersion: "short string",
			marshalledVersion: []byte{30, 24, 0, 115, 0, 104, 0, 111, 0, 114, 0, 116, 0,
				32, 0, 115, 0, 116, 0, 114, 0, 105, 0, 110, 0, 103},
		},
		{
			stringVersion: "137 character long string - 137 character long string - 137 character long string" +
				" - 137 character long string - 137 character long string",
			marshalledVersion: []byte{30, 130, 1, 18, 0, 49, 0, 51, 0, 55, 0, 32, 0, 99, 0, 104, 0, 97,
				0, 114, 0, 97, 0, 99, 0, 116, 0, 101, 0, 114, 0, 32, 0, 108, 0, 111, 0,
				110, 0, 103, 0, 32, 0, 115, 0, 116, 0, 114, 0, 105, 0, 110, 0, 103, 0,
				32, 0, 45, 0, 32, 0, 49, 0, 51, 0, 55, 0, 32, 0, 99, 0, 104, 0, 97, 0,
				114, 0, 97, 0, 99, 0, 116, 0, 101, 0, 114, 0, 32, 0, 108, 0, 111, 0, 110,
				0, 103, 0, 32, 0, 115, 0, 116, 0, 114, 0, 105, 0, 110, 0, 103, 0, 32, 0,
				45, 0, 32, 0, 49, 0, 51, 0, 55, 0, 32, 0, 99, 0, 104, 0, 97, 0, 114, 0,
				97, 0, 99, 0, 116, 0, 101, 0, 114, 0, 32, 0, 108, 0, 111, 0, 110, 0, 103,
				0, 32, 0, 115, 0, 116, 0, 114, 0, 105, 0, 110, 0, 103, 0, 32, 0, 45, 0,
				32, 0, 49, 0, 51, 0, 55, 0, 32, 0, 99, 0, 104, 0, 97, 0, 114, 0, 97, 0,
				99, 0, 116, 0, 101, 0, 114, 0, 32, 0, 108, 0, 111, 0, 110, 0, 103, 0, 32,
				0, 115, 0, 116, 0, 114, 0, 105, 0, 110, 0, 103, 0, 32, 0, 45, 0, 32, 0,
				49, 0, 51, 0, 55, 0, 32, 0, 99, 0, 104, 0, 97, 0, 114, 0, 97, 0, 99, 0,
				116, 0, 101, 0, 114, 0, 32, 0, 108, 0, 111, 0, 110, 0, 103, 0, 32, 0, 115,
				0, 116, 0, 114, 0, 105, 0, 110, 0, 103},
		},
	}
)

func TestBMPString(t *testing.T) {
	for i, test := range bmpStringTests {
		expected, err := hex.DecodeString(test.expectedHex)
		if err != nil {
			t.Fatalf("#%d: failed to decode expectation", i)
		}

		out, err := bmpString(test.in)
		if err == nil && test.shouldFail {
			t.Errorf("#%d: expected to fail, but produced %x", i, out)
			continue
		}

		if err != nil && !test.shouldFail {
			t.Errorf("#%d: failed unexpectedly: %s", i, err)
			continue
		}

		if !test.shouldFail {
			if !bytes.Equal(out, expected) {
				t.Errorf("#%d: expected %s, got %x", i, test.expectedHex, out)
				continue
			}

			roundTrip, err := decodeBMPString(out)
			if err != nil {
				t.Errorf("#%d: decoding output gave an error: %s", i, err)
				continue
			}

			if roundTrip != test.in {
				t.Errorf("#%d: decoding output resulted in %q, but it should have been %q", i, roundTrip, test.in)
				continue
			}
		}
	}
}

func TestComputeBmpStringSizeBytes(t *testing.T) {
	testData := []bpmStringSizeBytesTest{
		{
			input:                  "testInput",
			expectedSizeSliceLen:   1,
			expectedSizeSliceBytes: []byte{18},
		},
		{
			input:                  "",
			expectedSizeSliceLen:   1,
			expectedSizeSliceBytes: []byte{0},
		},
		{
			input:                  "71 character long test string - 71 character long test string - 71 char",
			expectedSizeSliceLen:   2,
			expectedSizeSliceBytes: []byte{129, 142},
		},
		{
			expectedSizeSliceLen:          4,
			expectedSizeSliceBytes:        []byte{131, 2, 34, 224},
			expectedSizeSliceBytesDisplay: "70000 't' characters",
		},
	}

	testData[3].input = strings.Repeat("t", 70000)

	for _, testItem := range testData {
		lenBytes, sliceLen := computeBmpStringSizeBytes(testItem.input)

		if sliceLen != testItem.expectedSizeSliceLen {
			t.Error("Invalid length definition slice length:", sliceLen, "expected:", testItem.expectedSizeSliceLen)
		}

		if !bytes.Equal(lenBytes, testItem.expectedSizeSliceBytes) {
			var errorParam interface{}
			if len(testItem.expectedSizeSliceBytesDisplay) != 0 {
				errorParam = testItem.expectedSizeSliceBytesDisplay
			} else {
				errorParam = testItem.expectedSizeSliceBytes
			}

			t.Error("Invalid length definition bytes:", lenBytes, "expected:", errorParam)
		}
	}
}

func TestComputeBmpStringSize(t *testing.T) {
	testData := []bmpSliceSizeBytesTest{
		{
			// Small size
			stringSlice:  []byte{30, 4, 0, 0, 0, 0},
			computedSize: 4,
			expectError:  false,
		},
		{
			// Large size
			stringSlice:  []byte{},
			computedSize: 300,
			expectError:  false,
		},
		{
			// Invalid size byte small
			stringSlice:  []byte{30, 4, 0, 0, 0},
			computedSize: -1,
			expectError:  true,
		},
		{
			// Invalid size small - even size
			stringSlice:  []byte{30, 5, 0, 0, 0, 0, 0},
			computedSize: -1,
			expectError:  true,
		},
		{
			// Invalid size long
			stringSlice:  []byte{},
			computedSize: -1,
			expectError:  true,
		},
		{
			// Invalid size long - even size
			stringSlice:  []byte{},
			computedSize: -1,
			expectError:  true,
		},
		{
			// Empty input
			stringSlice:  []byte{},
			computedSize: -1,
			expectError:  true,
		},
		{
			// Too short input
			stringSlice:  []byte{30, 1},
			computedSize: -1,
			expectError:  true,
		},
		{
			// Invalid type
			stringSlice:  []byte{30, 1, 2, 3, 4, 5},
			computedSize: -1,
			expectError:  true,
		},
		{
			// Empty string
			stringSlice:  []byte{30, 0},
			computedSize: 0,
			expectError:  false,
		},
	}

	// Prepare larger slices
	// Valid long slice
	payloadSlice := make([]byte, 300)
	testData[1].stringSlice = []byte{30, 130, 1, 44}
	testData[1].stringSlice = append(testData[1].stringSlice, payloadSlice...)
	// Invalid long size
	testData[4].stringSlice = []byte{30, 130, 1, 42}
	testData[4].stringSlice = append(testData[4].stringSlice, payloadSlice...)
	// Invalid long size - even
	payloadSlice = make([]byte, 301)
	testData[5].stringSlice = []byte{30, 130, 1, 45}
	testData[5].stringSlice = append(testData[5].stringSlice, payloadSlice...)

	for _, testItem := range testData {
		computedSize, err := computeBmpStringSize(testItem.stringSlice)

		if err != nil && !testItem.expectError {
			t.Error("There was an unexpected error:", err, " - input:", testItem.stringSlice)
		}

		if err == nil && testItem.expectError {
			t.Error("Error was expected to happen but it did not happened", " - input:", testItem.stringSlice)
		}

		if computedSize != testItem.computedSize {
			t.Error("Computed size:", computedSize, " does not matches expected size:", testItem.computedSize, " - input:", testItem.stringSlice)
		}
	}
}

func TestMarshalBmpString(t *testing.T) {
	for _, testItem := range marshalTest {
		marshalledBytes, err := marshalBmpString(testItem.stringVersion)

		if err != nil && !testItem.expectError {
			t.Error("There was an unexpected error:", err, " - input:", testItem.stringVersion)
		}

		if err == nil && testItem.expectError {
			t.Error("Error was expected to happen but it did not happened", " - input:", testItem.stringVersion)
		}

		if bytes.Compare(marshalledBytes, testItem.marshalledVersion) != 0 {
			t.Error("Marshalling error. Expected:", testItem.marshalledVersion, " got:", marshalledBytes, " - input:", testItem.stringVersion)
		}
	}
}

func TestUnmarshalBmpString(t *testing.T) {
	for _, testItem := range marshalTest {
		unmarshalledString, err := unmarshalBmpString(testItem.marshalledVersion)

		if err != nil && !testItem.expectError {
			t.Error("There was an unexpected error:", err, " - input:", testItem.marshalledVersion)
		}

		if err == nil && testItem.expectError {
			t.Error("Error was expected to happen but it did not happened", " - input:", testItem.marshalledVersion)
		}

		if unmarshalledString != testItem.stringVersion {
			t.Error("Unmarshalling error. Expected:", testItem.stringVersion, " got:", unmarshalledString, " - input:", testItem.marshalledVersion)
		}
	}
}
