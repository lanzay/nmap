package nmap

import (
	"encoding/xml"
	"time"
)

// Nmap is the root object that holds all data
type rawScan struct {
	xMLName xml.Name `xml:"nmaprun"`

	DisplayArgs string `xml:"args,attr"`
	StartTime   string `xml:"start,attr"`

	ScanInfo rawScanInfo `xml:"scaninfo"`
	Hosts    []rawHost   `xml:"host"`

	ScanHosts []string
	ScanPorts []int
	ScanOpts  []string
}

// ScanInfo holds data about what the was scanned
type rawScanInfo struct {
	xMLName xml.Name `xml:"scaninfo"`

	Type        string `xml:"type,attr"`
	Protocol    string `xml:"protocol,attr"`
	NumServices string `xml:"numservices,attr"`
	Services    string `xml:"services,attr"`
}

// Host holds the information about the port including what address it has and
// the information about the ports
type rawHost struct {
	xMLName xml.Name `xml:"host"`

	Status    rawStatus    `xml:"status"`
	Address   rawAddress   `xml:"address" json:"address"`
	Hostnames rawHostnames `xml:"hostnames"`
	Ports     rawPorts     `xml:"ports" json:"ports"`
	OS        rawOS        `xml:"os" json:"os"`
	Times     rawTimes     `xml:"times" json:"times"`
}
type rawTimes struct {
	Srtt   time.Duration `xml:"srtt,attr" json:"srtt"`
	RttVar time.Duration `xml:"rttvar,attr" json:"rtt_var"`
	To     time.Duration `xml:"to,attr" json:"to"`
}

// Status gives the status of the host
type rawStatus struct {
	xMLName xml.Name `xml:"status"`

	State  string `xml:"state,attr"`
	Reason string `xml:"reason,attr"`
}

// Address has the address of the server. This is only used when multiple hosts
// are scanned at the same time
type rawAddress struct {
	xMLName xml.Name `xml:"address"`

	Address     string `xml:"addr,attr"`
	AddressType string `xml:"addrtype,attr"`
}

// Hostnames are a list of hostnames
type rawHostnames struct {
	xMLName xml.Name `xml:"hostnames"`

	Hostnames []rawHostname `xml:"hostname"`
}

// Hostname is an entry that gives the user different hostnames that the IP
// may own
type rawHostname struct {
	xMLName xml.Name `xml:"hostname"`

	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

// Ports is the array of ports
type rawPorts struct {
	xMLName xml.Name `xml:"ports"`

	Ports []rawPort `xml:"port"`
}
type (
	rawOS struct {
		xMLName xml.Name     `xml:"ports"`
		OsMatch []rawOsMatch `xml:"osmatch"`
	}
	rawOsMatch struct {
		xMLName  xml.Name   `xml:"osmatch"`
		Name     string     `xml:"name,attr" json:"name"`
		Accuracy string     `xml:"accuracy,attr" json:"accuracy"`
		Line     string     `xml:"line,attr" json:"line"`
		OsClass  rawOsClass `xml:"osclass"`
	}
	rawOsClass struct {
		xMLName  xml.Name `xml:"osclass"`
		Type     string   `xml:"type,attr" json:"type"`
		Vendor   string   `xml:"vendor,attr" json:"vendor"`
		OsFamily string   `xml:"osfamily,attr" json:"osfamily"`
		OsGen    string   `xml:"osgen,attr" json:"osgen"`
		Accuracy string   `xml:"accuracy,attr" json:"accuracy"`
		Cpe      rawCpe   `xml:"cpe"`
	}
	rawCpe struct {
		xMLName xml.Name `xml:"cpe"`
		Data    string   `xml:",chardata"`
	}
)

// Port has all of the information about the port in question
type rawPort struct {
	xMLName xml.Name `xml:"port"`

	Protocol string `xml:"protocol,attr" json:"protocol"`
	Port     uint32 `xml:"portid,attr" json:"port"`

	State   rawState    `xml:"state" json:"state"`
	Service rawService  `xml:"service"`
	Scripts []rawScript `xml:"script"`
}

// Status gives the status of "open, closed, filtered"
type rawState struct {
	xMLName xml.Name `xml:"state"`

	State  string `xml:"state,attr"`
	Reason string `xml:"reason,attr"`
}

// Service is the name of the service. Ex: "ssh, rdp, etc."
type rawService struct {
	xMLName xml.Name `xml:"service"`

	Name        string `xml:"name,attr"`
	Product     string `xml:"product,attr"`
	Fingerprint string `xml:"servicefp"`

	Version    string `xml:"version,attr"`
	Hostname   string `xml:"hostname,attr"`
	Devicetype string `xml:"devicetype,attr"`
	Method     string `xml:"method,attr"`
	Conf       string `xml:"conf,attr"`
	Extrainfo  string `xml:"extrainfo,attr"`
	Servicefp  string `xml:"servicefp,attr"`

	//cpe <cpe>cpe:/o:mikrotik:routeros</cpe>
}

// Script defines the output for various scripts
type rawScript struct {
	xMLName xml.Name `xml:"script"`

	Name   string `xml:"id,attr"`
	Output string `xml:"output,attr"`

	Elements []rawElement `xml:"elem"`
}

// Element defines an element of a script
type rawElement struct {
	xMLName xml.Name `xml:"elem"`

	Key string `xml:"key"`

	Value string
}

func parseXML(inputFile []byte) (*rawScan, error) {
	var result rawScan

	if err := xml.Unmarshal(inputFile, &result); err != nil {
		return nil, err
	}

	return &result, nil
}

func ParseXML(inputFile []byte) (*rawScan, error) {
	var result rawScan

	if err := xml.Unmarshal(inputFile, &result); err != nil {
		return nil, err
	}

	return &result, nil
}
