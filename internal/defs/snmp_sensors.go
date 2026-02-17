package defs

import (
	"math"

	"github.com/gosnmp/gosnmp"

	"wakora.io/agent/internal/protocol"
)

const (
	oidEntSensorType   = ".1.3.6.1.2.1.99.1.1.1.1"
	oidEntSensorScale  = ".1.3.6.1.2.1.99.1.1.1.2"
	oidEntSensorPrec   = ".1.3.6.1.2.1.99.1.1.1.3"
	oidEntSensorValue  = ".1.3.6.1.2.1.99.1.1.1.4"
	oidEntSensorStatus = ".1.3.6.1.2.1.99.1.1.1.5"
	oidEntPhysName     = ".1.3.6.1.2.1.47.1.1.1.1.7"
	oidEntPhysDescr    = ".1.3.6.1.2.1.47.1.1.1.1.2"
)

var sensorTypeUnit = map[int]string{
	3: "voltsAC", 4: "voltsDC", 5: "amperes", 6: "watts", 7: "hertz",
	8: "celsius", 9: "percentRH", 10: "rpm", 11: "cmm", 14: "dBm",
}

func scaleSensor(raw, scale, precision int) float64 {
	if scale == 0 {
		scale = 9
	}
	real := float64(raw) * math.Pow(10, float64(3*(scale-9))) * math.Pow(10, float64(-precision))
	return math.Round(real*1000) / 1000
}

func walkSensors(g *gosnmp.GoSNMP, deviceTag map[string]string, o *Outcome) (bool, string) {
	types := walkInts(g, oidEntSensorType)
	if len(types) == 0 {
		return false, "no entPhySensor table"
	}
	scales := walkInts(g, oidEntSensorScale)
	precs := walkInts(g, oidEntSensorPrec)
	status := walkInts(g, oidEntSensorStatus)
	values := walkInts(g, oidEntSensorValue)
	names := walkStrings(g, oidEntPhysName)
	if len(names) == 0 {
		names = walkStrings(g, oidEntPhysDescr)
	}

	for idx, raw := range values {
		unit := sensorTypeUnit[types[idx]]
		if unit == "" {
			unit = "other"
		}
		real := scaleSensor(raw, scales[idx], precs[idx])
		tags := copyTags(deviceTag)
		tags["index"] = idx
		tags["type"] = unit
		if n := names[idx]; n != "" {
			tags["sensor"] = n
		}
		o.Metrics = append(o.Metrics, protocol.MetricPoint{
			Name: "dev.sensor.value", Value: real, Tags: tags,
		})
		if st, ok := status[idx]; ok {
			ok10 := 0.0
			if st == 1 {
				ok10 = 1
			}
			o.Metrics = append(o.Metrics, protocol.MetricPoint{
				Name: "dev.sensor.ok", Value: ok10, Tags: copyTags(tags),
			})
		}
	}
	return true, ""
}

const (
	oidPethAdmin     = ".1.3.6.1.2.1.105.1.1.1.3"
	oidPethDetection = ".1.3.6.1.2.1.105.1.1.1.6"
	oidPethPriority  = ".1.3.6.1.2.1.105.1.1.1.7"
	oidPethClass     = ".1.3.6.1.2.1.105.1.1.1.10"
	oidPethMainPower = ".1.3.6.1.2.1.105.1.3.1.1.4"
)

func walkPoE(g *gosnmp.GoSNMP, deviceTag map[string]string, o *Outcome) (bool, string) {
	detection := walkInts(g, oidPethDetection)
	if len(detection) == 0 {
		return false, "no pethPsePort table"
	}
	admin := walkInts(g, oidPethAdmin)
	class := walkInts(g, oidPethClass)
	priority := walkInts(g, oidPethPriority)

	delivering := 0
	for idx, det := range detection {
		tags := copyTags(deviceTag)
		tags["port"] = idx
		o.Metrics = append(o.Metrics, protocol.MetricPoint{Name: "dev.poe.detection_status", Value: float64(det), Tags: tags})
		if det == 3 {
			delivering++
		}
		if a, ok := admin[idx]; ok {
			o.Metrics = append(o.Metrics, protocol.MetricPoint{Name: "dev.poe.admin", Value: float64(a), Tags: copyTags(tags)})
		}
		if c, ok := class[idx]; ok {
			o.Metrics = append(o.Metrics, protocol.MetricPoint{Name: "dev.poe.class", Value: float64(c), Tags: copyTags(tags)})
		}
		if pr, ok := priority[idx]; ok {
			o.Metrics = append(o.Metrics, protocol.MetricPoint{Name: "dev.poe.priority", Value: float64(pr), Tags: copyTags(tags)})
		}
	}
	for gidx, w := range walkInts(g, oidPethMainPower) {
		tags := copyTags(deviceTag)
		tags["group"] = gidx
		o.Metrics = append(o.Metrics, protocol.MetricPoint{Name: "dev.poe.consumption_watts", Value: float64(w), Tags: tags})
	}
	o.Metrics = append(o.Metrics, protocol.MetricPoint{Name: "dev.poe.ports_delivering", Value: float64(delivering), Tags: copyTags(deviceTag)})
	return true, ""
}

func walkInts(g *gosnmp.GoSNMP, base string) map[string]int {
	out := map[string]int{}
	_ = g.Walk(base, func(pdu gosnmp.SnmpPDU) error {
		if v, ok := pduNum(pdu); ok {
			out[indexOf(base, pdu.Name)] = int(v)
		}
		return nil
	})
	return out
}

func walkStrings(g *gosnmp.GoSNMP, base string) map[string]string {
	out := map[string]string{}
	_ = g.Walk(base, func(pdu gosnmp.SnmpPDU) error {
		out[indexOf(base, pdu.Name)] = pduString(pdu)
		return nil
	})
	return out
}
