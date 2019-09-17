package nmap

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	//"github.com/t94j0/array"
	"github.com/lanzay/nmap/array"
)

// CreateNmapArgs takes a Scan object and returns a list of strings that map to
// arguments for an nmap scan.
func (s *Scan) CreateNmapArgs() ([]string, error) {
	// Parse arguments
	args := []string{}
	const seperator string = ","

	// Set up ports
	portList := ""
	portList += strings.Join(intListToStringList(s.configPorts), seperator)
	if len(s.configUDPPorts) != 0 {
		if portList != "" {
			portList += ","
		}
		portList += "U:"
	}
	portList += strings.Join(intListToStringList(s.configUDPPorts), seperator)
	if len(s.configTCPPorts) != 0 {
		if portList != "" {
			portList += ","
		}
		portList += "T:"
	}
	portList += strings.Join(intListToStringList(s.configTCPPorts), seperator)

	// Check to make sure all TCP/UDP flags are correct
	// Check TCP flags
	tcpOptions := []string{"-sS", "-sT", "-sA", "-sW", "-sM"}
	iflag := array.Intersection(tcpOptions, s.configOpts).([]string)
	if len(iflag) == 0 {
		s.configOpts = append(s.configOpts, tcpOptions[1])
	}

	// Check UDP flag
	if len(s.configUDPPorts) != 0 && !array.In("-sU", s.configOpts) {
		s.configOpts = append(s.configOpts, "-sU")
	}

	// Append arguments
	args = append(args, s.configOpts...)

	// Append port list
	if portList != "" {
		args = append(args, "-p"+portList)
	}
	// Append hosts
	if len(s.configHosts) == 0 {
		s.configErr = errors.New("No hosts added")
	}

	if len(s.Args) == 0 {
		s.Args = fmt.Sprint(strings.Join(args, " "))
	}
	args = append(args, s.configHosts...)

	fmt.Println(args)
	return args, nil
}

// uint16ListToStringList is used to reduce lines for joining strings in
// the CreateNmapArgs function
func uint16ListToStringList(source []uint16) (o []string) {
	for _, s := range source {
		o = append(o, strconv.FormatUint(uint64(s), 10))
	}
	return
}

func intListToStringList(source []int) (o []string) {
	for _, s := range source {
		o = append(o, strconv.Itoa(s))
	}
	return
}
