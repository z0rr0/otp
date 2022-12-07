package otp

import (
	"testing"
	"time"
)

func TestSecret(t *testing.T) {
	secret, err := Secret(20)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(secret)
}

func TestCode(t *testing.T) {
	cases := []struct {
		name     string
		counter  int64
		secret   string
		expected string
	}{
		{
			name:     "one counter",
			counter:  0,
			secret:   "PLH5US7K4JYU3DAP7KBXNFLQ66PSRNNH",
			expected: "038572",
		},
		{
			name:     "some time",
			counter:  time.Date(2020, 1, 2, 3, 0, 0, 0, time.UTC).Unix() / 30,
			secret:   "PLH5US7K4JYU3DAP7KBXNFLQ66PSRNNH",
			expected: "300755",
		},
		{
			name:     "some time and 10 seconds",
			counter:  time.Date(2020, 1, 2, 3, 0, 10, 0, time.UTC).Unix() / 30,
			secret:   "PLH5US7K4JYU3DAP7KBXNFLQ66PSRNNH",
			expected: "300755",
		},
		{
			name:     "some time and 40 seconds",
			counter:  time.Date(2020, 1, 2, 3, 0, 40, 0, time.UTC).Unix() / 30,
			secret:   "PLH5US7K4JYU3DAP7KBXNFLQ66PSRNNH",
			expected: "602895",
		},
		{
			name:     "same time and another secret",
			counter:  time.Date(2020, 1, 2, 3, 0, 40, 0, time.UTC).Unix() / 30,
			secret:   "AJIS553K23JWRJ4J3GDL7B6PBRWKL4AP",
			expected: "507727",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(tt *testing.T) {
			code, err := Code(c.secret, c.counter)
			if err != nil {
				tt.Fatal(err)
			}
			if code != c.expected {
				tt.Errorf("expected %s, got %s", c.expected, code)
			}
		})
	}
}
