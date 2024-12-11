package types

import (
	"strings"
	"testing"
)

func TestEvaluateMetadata(t *testing.T) {
	tests := []struct {
		data            string
		allowedMetadata []DataMetadata
		expectedResults map[DataMetadata]bool
	}{
		{
			data:            "abc123",
			allowedMetadata: []DataMetadata{ValueMetadataAlphanumeric},
			expectedResults: map[DataMetadata]bool{
				ValueMetadataAlphanumeric: true,
			},
		},
		{
			data:            "abc123!",
			allowedMetadata: []DataMetadata{ValueMetadataAlphanumeric, ValueMetadataAscii},
			expectedResults: map[DataMetadata]bool{
				ValueMetadataAlphanumeric: false,
				ValueMetadataAscii:        true,
			},
		},
		{
			data:            "http://example.com",
			allowedMetadata: []DataMetadata{ValueMetadataURI},
			expectedResults: map[DataMetadata]bool{
				ValueMetadataURI: true,
			},
		},
		{
			data:            "not-a-uri",
			allowedMetadata: []DataMetadata{ValueMetadataURI},
			expectedResults: map[DataMetadata]bool{
				ValueMetadataURI: false,
			},
		},
		{
			data:            "12345",
			allowedMetadata: []DataMetadata{ValueMetadataNumeric},
			expectedResults: map[DataMetadata]bool{
				ValueMetadataNumeric: true,
			},
		},
		{
			data:            "true",
			allowedMetadata: []DataMetadata{ValueMetadataBoolean},
			expectedResults: map[DataMetadata]bool{
				ValueMetadataBoolean: true,
			},
		},
		{
			data:            "false",
			allowedMetadata: []DataMetadata{ValueMetadataBoolean},
			expectedResults: map[DataMetadata]bool{
				ValueMetadataBoolean: true,
			},
		},
		{
			data:            "123abc",
			allowedMetadata: []DataMetadata{ValueMetadataAscii, ValueMetadataUnicode},
			expectedResults: map[DataMetadata]bool{
				ValueMetadataAscii:   true,
				ValueMetadataUnicode: false,
			},
		},
	}

	for _, test := range tests {
		dataList := NewDataMetadataList()
		dataList.EvaluateMetadata(test.data, test.allowedMetadata)
		for metadata, expected := range test.expectedResults {
			if dataList.EvaluationMap[metadata].Result != expected {
				t.Errorf("For data '%s' and metadata '%v', expected %v but got %v",
					test.data, metadata, expected, dataList.EvaluationMap[metadata].Result)
			}
		}
	}

}

// Test to try out multiple iterations of adding metadata to the list
func TestEvaluateMetadataMultiple(t *testing.T) {
	// dataList := NewDataMetadataList()
	// dataList.EvaluateMetadata("abc123", []DataMetadata{NotValueMetadataURI})

	dataList := NewDataMetadataList()
	dataList.EvaluateMetadata(strings.Repeat("a", 1000)+"bcdefghijklmnopqrstuvwxyz", []DataMetadata{NotValueMetadataAlphanumeric})

	if !dataList.EvaluationMap[ValueMetadataAlphanumeric].Evaluated {
		t.Errorf("Expected alphanumeric evaluation not done, but got true")
	}
	if dataList.EvaluationMap[ValueMetadataNumeric].Result {
		t.Errorf("The result should be false, but got true. since it is not numeric")
	}
	if dataList.IsInScope([]DataMetadata{NotValueMetadataAlphanumeric}) {
		t.Errorf("Expected to be out of scope, but got in scope")
	}
}
