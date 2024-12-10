package types

import (
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
			allowedMetadata: []DataMetadata{ValueMetadataAlphanumeric},
			expectedResults: map[DataMetadata]bool{
				ValueMetadataAlphanumeric: false,
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
			if dataList.metadata[metadata] != expected {
				t.Errorf("For data '%s' and metadata '%v', expected %v but got %v",
					test.data, metadata, expected, dataList.metadata[metadata])
			}
		}
	}
}
