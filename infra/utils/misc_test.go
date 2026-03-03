package utils

import "testing"

func TestExtractRootDomain(t *testing.T) {
	cases := []struct {
		input  string
		expect string
	}{
		{"https://www.example.com/path", "example.com"},
		{"http://127.0.0.1:9008", "127.0.0.1"},
		{"example.com", "example.com"},
		{"https://sub.example.co.uk", "example.co.uk"},
	}
	for _, item := range cases {
		got, err := ExtractRootDomain(item.input)
		if err != nil {
			t.Fatalf("extract root domain: %v", err)
		}
		if got != item.expect {
			t.Fatalf("expect %s got %s", item.expect, got)
		}
	}
}
