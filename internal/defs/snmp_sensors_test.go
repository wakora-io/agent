package defs

import "testing"

func TestScaleSensor(t *testing.T) {
	cases := []struct {
		name             string
		raw, scale, prec int
		want             float64
	}{
		{"celsius units prec0", 42, 9, 0, 42},
		{"celsius units prec1 (42.5C)", 425, 9, 1, 42.5},
		{"volts milli->units (3300mV=3.3V)", 3300, 8, 0, 3.3},
		{"dBm negative prec2 (-5.23dBm)", -523, 9, 2, -5.23},
		{"watts kilo (2kW as 2*1000)", 2, 10, 0, 2000},
		{"scale missing defaults units", 60, 0, 0, 60},
	}
	for _, c := range cases {
		if got := scaleSensor(c.raw, c.scale, c.prec); got != c.want {
			t.Errorf("%s: scaleSensor(%d,%d,%d)=%v want %v", c.name, c.raw, c.scale, c.prec, got, c.want)
		}
	}
}
