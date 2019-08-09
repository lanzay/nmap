package nmap

import (
	"fmt"
	"strings"
	"time"
)

// Port represents nmap port information
type Port struct {
	Protocol string
	// ID is the port number
	ID      uint32
	State   string
	Reason  string
	Scripts []Script
	Service Service
}
type (
	OS struct {
		//TODO os.OsMatch[]
		Name     string
		Accuracy string
		Line     string
		OSClass  OSClass
	}
	OSClass struct {
		Type     string
		Vendor   string
		OSFamily string
		OSGen    string
		Accuracy string
		Cpe      string
	}
)

type Service struct {
	Name        string
	Product     string
	Fingerprint string
	Version     string
	Hostname    string
	Devicetype  string
	Method      string
	Conf        string
	Extrainfo   string
	Servicefp   string //Nmap Fingerprint https://nmap.org/book/osdetect-fingerprint-format.html
}

type Times struct {
	Srtt   time.Duration
	RttVar time.Duration
	To     time.Duration
}

// Script are used for gathering nmap NSE script information
type Script struct {
	Name     string
	Output   string
	Elements []Element
}

// Element are returned from NSE scripts
type Element struct {
	Key   string
	Value string
}

func (port rawPort) cleanPort() Port {
	output := Port{
		Protocol: port.Protocol,
		ID:       port.Port,
		State:    port.State.State,
		Reason:   port.State.Reason,
		Scripts:  []Script{},
		Service: Service{
			Name:        port.Service.Name,
			Product:     port.Service.Product,
			Fingerprint: port.Service.Fingerprint,
			Version:     port.Service.Version,
			Hostname:    port.Service.Hostname,
			Devicetype:  port.Service.Devicetype,
			Method:      port.Service.Method,
			Conf:        port.Service.Conf,
			Extrainfo:   port.Service.Extrainfo,
			Servicefp:   port.Service.Servicefp,
		},
	}
	for _, script := range port.Scripts {
		s := Script{script.Name, script.Output, []Element{}}
		for _, elem := range script.Elements {
			element := Element{elem.Key, elem.Value}
			s.Elements = append(s.Elements, element)
		}
		output.Scripts = append(output.Scripts, s)
	}

	return output
}

func (os rawOS) cleanOS() OS {

	if len(os.OsMatch) == 0 {
		return OS{}
	}

	output := OS{
		//TODO os.OsMatch[]
		Name:     os.OsMatch[0].Name,
		Accuracy: os.OsMatch[0].Accuracy,
		Line:     os.OsMatch[0].Line,
		OSClass: OSClass{
			Type:     os.OsMatch[0].OsClass.Type,
			Vendor:   os.OsMatch[0].OsClass.Vendor,
			OSFamily: os.OsMatch[0].OsClass.OsFamily,
			OSGen:    os.OsMatch[0].OsClass.OsGen,
			Accuracy: os.OsMatch[0].OsClass.Accuracy,
			Cpe:      os.OsMatch[0].OsClass.Cpe.Data,
		},
	}
	return output

}

// ToString returns port information in a pretty-printed format
func (p Port) ToString() (out string) {
	out += fmt.Sprintf("Port %d/%s is %s\n", p.ID, p.Protocol, p.State)
	for _, script := range p.Scripts {
		output := ""
		for _, line := range strings.Split(script.Output, "\n") {
			output += fmt.Sprintf("      %s\n", line)
		}
		out += fmt.Sprintf("  Script: %s\n%s\n", script.Name, output)
	}
	return
}

func (s Service) ToString() string {

	//b,_ := json.Marshal(s)
	//return string(b)
	service := strings.TrimSpace(fmt.Sprintf("%s; v:%s; cfg:%s; %s %s %s", s.Product, s.Version, s.Conf, s.Method, s.Extrainfo, s.Fingerprint))
	return service
}
