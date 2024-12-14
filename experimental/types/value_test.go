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

func TestEvaluateMultipleMetadata(t *testing.T) {
	dataList := NewDataMetadataList()
	dataList.EvaluateMetadata("abc123", []DataMetadata{ValueMetadataAlphanumeric, ValueMetadataAscii, ValueMetadataNumeric})

	if !dataList.EvaluationMap[ValueMetadataAlphanumeric].Result {
		t.Errorf("Expected alphanumeric evaluation to be true, but got false")
	}

	if !dataList.EvaluationMap[ValueMetadataAscii].Result {
		t.Errorf("Expected ascii evaluation to be true, but got false")
	}
	if dataList.EvaluationMap[ValueMetadataNumeric].Result {
		t.Errorf("Expected numeric evaluation to be false, but got true")
	}
	// Make sure that other metadata evaluations are not done
	if dataList.EvaluationMap[ValueMetadataURI].Evaluated {
		t.Errorf("Expected URI evaluation to not be done, but got true")
	}
	if dataList.EvaluationMap[ValueMetadataBoolean].Evaluated {
		t.Errorf("Expected boolean evaluation to not be done, but got true")
	}
}
