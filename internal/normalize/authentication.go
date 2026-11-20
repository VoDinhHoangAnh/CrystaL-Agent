package normalize

import (
	"strings"

	"AegisPlus/CrystaL/internal/model"
)

// applyAuthentication phân loại event auth mà không tự khẳng định brute-force.
// 1149 chỉ cho biết xác thực RDP; không được coi như logon thành công hoàn chỉnh.
func applyAuthentication(n *model.Normalized, ev model.WinEvent, data map[string]string) {
	code := int(atoi64(ev.System.EventID))
	isSecurity := strings.EqualFold(ev.System.Channel, "Security")
	isRDP := strings.EqualFold(ev.System.Channel, "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational")
	if !isSecurity && !isRDP {
		return
	}
	a := &model.AuthenticationFacts{EventCode: code}
	switch {
	case isSecurity && code == 4625:
		a.Result = "failure"
	case isSecurity && code == 4624:
		a.Result = "success"
	case isSecurity && code == 4740:
		a.Result = "lockout"
	case isSecurity && code == 4771:
		a.Result = "kerberos_failure"
	case isSecurity && code == 4776:
		a.Result = "ntlm_validation"
		if strings.EqualFold(first(data, "Status"), "0x0") {
			a.Result = "ntlm_success"
		}
	case isSecurity && code == 4648:
		a.Result = "explicit_credentials"
	case isSecurity && (code == 4768 || code == 4769):
		a.Result = "kerberos_ticket"
	case isRDP && code == 1149:
		a.Result = "rdp_authentication"
	default:
		return
	}
	a.Username = first(data, "TargetUserName", "AccountName", "RDPUser")
	a.Domain = first(data, "TargetDomainName", "TargetDomain", "RDPDomain")
	a.SourceIP = CanonicalIP(first(data, "IpAddress", "ClientAddress", "SourceNetworkAddress", "SourceAddress", "RDPSourceIP"))
	if a.SourceIP == "-" || a.SourceIP == "::1" {
		a.SourceIP = ""
	}
	a.Workstation = first(data, "WorkstationName", "CallerComputerName")
	a.LogonType = int(atoi64(first(data, "LogonType")))
	a.FailureCode = first(data, "Status", "SubStatus", "FailureCode")
	n.EventType = "authentication"
	n.Authentication = a
}
