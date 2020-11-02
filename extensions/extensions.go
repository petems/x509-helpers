package extensions

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"strings"

	"github.com/petems/x509-helpers/format"
	certformat "github.com/petems/x509-helpers/format"
)

// Extension
var (
	oidMicrosoftCertSrv                      = []int{1, 3, 6, 1, 4, 1, 311, 21, 1}
	oidMicrosoftPreviousCertHash             = []int{1, 3, 6, 1, 4, 1, 311, 21, 2}
	oidMicrosoftCertificateTemplate          = []int{1, 3, 6, 1, 4, 1, 311, 21, 7}
	oidMicrsoftApplicationPolicies           = []int{1, 3, 6, 1, 4, 1, 311, 21, 10}
	oidExtensionAuthorityInfoAccess          = []int{1, 3, 6, 1, 5, 5, 7, 1, 1}
	oidExtensionLogotype                     = []int{1, 3, 6, 1, 5, 5, 7, 1, 12}
	oidExtensionSubjectKeyID                 = []int{2, 5, 29, 14}
	oidExtensionKeyUsage                     = []int{2, 5, 29, 15}
	oidExtensionSubjectAltName               = []int{2, 5, 29, 17}
	oidExtensionBasicConstraints             = []int{2, 5, 29, 19}
	oidExtensionNameConstraints              = []int{2, 5, 29, 30}
	oidExtensionCRLDistributionPoints        = []int{2, 5, 29, 31}
	oidExtensionCertificatePolicies          = []int{2, 5, 29, 32}
	oidExtensionAuthorityKeyID               = []int{2, 5, 29, 35}
	oidExtensionExtendedKeyUsage             = []int{2, 5, 29, 37}
	oidExtensionNSCertType                   = []int{2, 16, 840, 1, 113730, 1, 1}
	oidExtensionNSBaseURL                    = []int{2, 16, 840, 1, 113730, 1, 2}
	oidExtensionNSRevocationURL              = []int{2, 16, 840, 1, 113730, 1, 3}
	oidExtensionNSCARevocationURL            = []int{2, 16, 840, 1, 113730, 1, 4}
	oidExtensionNSRenewalURL                 = []int{2, 16, 840, 1, 113730, 1, 7}
	oidExtensionNSCAPolicyURL                = []int{2, 16, 840, 1, 113730, 1, 8}
	oidExtensionNSSSLServerName              = []int{2, 16, 840, 1, 113730, 1, 12}
	oidExtensionNSCertificateComment         = []int{2, 16, 840, 1, 113730, 1, 13}
	oidExtKeyUsageAny                        = asn1.ObjectIdentifier{2, 5, 29, 37, 0}
	oidExtBasicConstraints                   = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidExtKeyUsageServerAuth                 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1}
	oidExtKeyUsageClientAuth                 = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 2}
	oidExtKeyUsageCodeSigning                = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 3}
	oidExtKeyUsageEmailProtection            = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 4}
	oidExtKeyUsageIPSECEndSystem             = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 5}
	oidExtKeyUsageIPSECTunnel                = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 6}
	oidExtKeyUsageIPSECUser                  = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 7}
	oidExtKeyUsageTimeStamping               = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}
	oidExtKeyUsageOCSPSigning                = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 9}
	oidExtKeyUsageMicrosoftServerGatedCrypto = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 3}
	oidExtKeyUsageNetscapeServerGatedCrypto  = asn1.ObjectIdentifier{2, 16, 840, 1, 113730, 4, 1}
)

// Key Usage
var keyUsages = []string{
	"digital signature",
	"content commitment",
	"key encipherment",
	"data encipherment",
	"key agreement",
	"certificate signing",
	"CRL signing",
	"encipher only",
	"decipher only",
}

// AuthorityKeyID RFC 5280,  4.2.1.1
type AuthorityKeyID struct {
	ID           []byte        `asn1:"optional,tag:0"`
	Issuer       asn1.RawValue `asn1:"optional,tag:1"`
	SerialNumber *big.Int      `asn1:"optional,tag:2"`
}

// DumpOID dumps the decoded OID to the terminal if available, else it will
// show the OID in dotted notation.
func DumpOID(oid asn1.ObjectIdentifier, pad int, writer io.Writer) {
	fmt.Print(strings.Repeat("  ", pad))
	switch {
	// RFC 5280, 4.2.1.12. Extended Key Usage
	case oid.Equal(oidExtKeyUsageAny):
		fmt.Fprintf(writer, "any (%s)\n", oid)
	case oid.Equal(oidExtKeyUsageServerAuth):
		fmt.Fprintf(writer, "server authentication (%s)\n", oid)
	case oid.Equal(oidExtKeyUsageClientAuth):
		fmt.Fprintf(writer, "client authentication (%s)\n", oid)
	case oid.Equal(oidExtKeyUsageCodeSigning):
		fmt.Fprintf(writer, "code signing (%s)\n", oid)
	case oid.Equal(oidExtKeyUsageEmailProtection):
		fmt.Fprintf(writer, "email protection (%s)\n", oid)
	case oid.Equal(oidExtKeyUsageIPSECEndSystem):
		fmt.Fprintf(writer, "IPSEC end system (%s)\n", oid)
	case oid.Equal(oidExtKeyUsageIPSECTunnel):
		fmt.Fprintf(writer, "IPSEC tunnel (%s)\n", oid)
	case oid.Equal(oidExtKeyUsageIPSECUser):
		fmt.Fprintf(writer, "IPSEC user (%s)\n", oid)
	case oid.Equal(oidExtKeyUsageTimeStamping):
		fmt.Fprintf(writer, "time stamping (%s)\n", oid)
	case oid.Equal(oidExtKeyUsageOCSPSigning):
		fmt.Fprintf(writer, "OCSP signing (%s)\n", oid)
	case oid.Equal(oidExtKeyUsageMicrosoftServerGatedCrypto):
		fmt.Fprintf(writer, "Microsoft server gated crypto (%s)\n", oid)
	case oid.Equal(oidExtKeyUsageNetscapeServerGatedCrypto):
		fmt.Fprintf(writer, "Netscape server gated crypto (%s)\n", oid)
	// RFC 5280 4.2.1.4. Certificate Policies
	// - https://cabforum.org/object-registry/
	case oid.Equal([]int{2, 23, 140, 1, 1}):
		fmt.Fprintf(writer, "extended validation (%s)\n", oid)
	case oid.Equal([]int{2, 23, 140, 1, 2}):
		fmt.Fprintf(writer, "baseline requirements (%s)\n", oid)
	case oid.Equal([]int{2, 23, 140, 1, 2, 1}):
		fmt.Fprintf(writer, "CABF domain validated (%s)\n", oid)
	case oid.Equal([]int{2, 23, 140, 1, 2, 2}):
		fmt.Fprintf(writer, "CABF subject identity validated (%s)\n", oid)
	case oid.Equal([]int{2, 16, 840, 1, 114412, 1, 1}):
		fmt.Fprintf(writer, "Digicert organization validation (%s)\n", oid)
	case oid.Equal([]int{2, 16, 840, 1, 114412, 2, 1}):
		fmt.Fprintf(writer, "Digicert extended validation (%s)\n", oid)
	case oid.Equal([]int{1, 3, 6, 1, 4, 1, 4788, 2, 200, 1}):
		fmt.Fprintf(writer, "D-Trust organization validation (%s)\n", oid)
	case oid.Equal([]int{1, 3, 6, 1, 4, 1, 4788, 2, 202, 1}):
		fmt.Fprintf(writer, "D-Trust extended validation (%s)\n", oid)
	case oid.Equal([]int{2, 16, 840, 1, 114413, 1, 7, 23, 1}):
		fmt.Fprintf(writer, "GoDaddy domain validation (%s)\n", oid)
	case oid.Equal([]int{2, 16, 840, 1, 114413, 1, 7, 23, 2}):
		fmt.Fprintf(writer, "GoDaddy organization validation (%s)\n", oid)
	case oid.Equal([]int{2, 16, 840, 1, 114413, 1, 7, 23, 3}):
		fmt.Fprintf(writer, "GoDaddy extended validation (%s)\n", oid)
	case oid.Equal([]int{2, 16, 840, 1, 113839, 0, 6, 3}):
		fmt.Fprintf(writer, "Identrust commercial domain validation (%s)\n", oid)
	case oid.Equal([]int{2, 16, 840, 1, 101, 3, 2, 1, 1, 5}):
		fmt.Fprintf(writer, "Identrust public sector domain validation (%s)\n", oid)
	case oid.Equal([]int{1, 3, 6, 1, 4, 1, 14777, 1, 2, 1}):
		fmt.Fprintf(writer, "Izenpe domain validation (%s)\n", oid)
	case oid.Equal([]int{2, 16, 528, 1, 1003, 1, 2, 5, 6}):
		fmt.Fprintf(writer, "Logius organization validation (%s)\n", oid)
	case oid.Equal([]int{1, 3, 6, 1, 4, 1, 8024, 0, 2, 100, 1, 1}):
		fmt.Fprintf(writer, "QuoVadis organization validation (%s)\n", oid)
	case oid.Equal([]int{1, 3, 6, 1, 4, 1, 8024, 0, 2, 100, 1, 2}):
		fmt.Fprintf(writer, "QuoVadis extended validation (%s)\n", oid)
	case oid.Equal([]int{2, 16, 840, 1, 114414, 1, 7, 23, 1}):
		fmt.Fprintf(writer, "Starfield domain validation (%s)\n", oid)
	case oid.Equal([]int{2, 16, 840, 1, 114414, 1, 7, 23, 2}):
		fmt.Fprintf(writer, "Starfield organization validation (%s)\n", oid)
	case oid.Equal([]int{2, 16, 840, 1, 114414, 1, 7, 23, 3}):
		fmt.Fprintf(writer, "Starfield extended validation (%s)\n", oid)
	case oid.Equal([]int{2, 16, 756, 1, 89, 1, 2, 1, 1}):
		fmt.Fprintf(writer, "SwissSign extended validation (%s)\n", oid)
	case oid.Equal([]int{2, 16, 840, 1, 113733, 1, 7, 54}):
		fmt.Fprintf(writer, "Symantec extended validation (%s)\n", oid)
	case oid.Equal([]int{1, 3, 6, 1, 4, 1, 34697, 1, 1}):
		fmt.Fprintf(writer, "Trend validation (%s)\n", oid)
	case oid.Equal([]int{1, 3, 6, 1, 4, 1, 5237, 1, 1, 3}):
		fmt.Fprintf(writer, "Trustis validation (%s)\n", oid)
	case oid.Equal([]int{1, 3, 6, 1, 4, 1, 30360, 3, 3, 3, 3, 4, 4, 3, 0}):
		fmt.Fprintf(writer, "Trustwave validation (%s)\n", oid)
	case oid.Equal([]int{2, 16, 792, 3, 0, 3, 1, 1, 2}):
		fmt.Fprintf(writer, "TurkTrust organization validation (%s)\n", oid)
	case oid.Equal([]int{2, 16, 792, 3, 0, 3, 1, 1, 5}):
		fmt.Fprintf(writer, "TurkTrust extended validation (%s)\n", oid)
	// - https://www.globalsign.com/repository/GlobalSign_CA_CP_v3.1.pdf
	case oid.Equal([]int{1, 3, 6, 1, 4, 1, 4146, 1, 1}):
		fmt.Fprintf(writer, "GlobalSign extended validation (%s)\n", oid)
	case oid.Equal([]int{1, 3, 6, 1, 4, 1, 4146, 1, 10}):
		fmt.Fprintf(writer, "GlobalSign domain validation (%s)\n", oid)
	case oid.Equal([]int{1, 3, 6, 1, 4, 1, 4146, 1, 20}):
		fmt.Fprintf(writer, "GlobalSign organization validation (%s)\n", oid)
	case oid.Equal([]int{1, 3, 6, 1, 4, 1, 4146, 1, 30}):
		fmt.Fprintf(writer, "GlobalSign time stamping (%s)\n", oid)
	case oid.Equal([]int{1, 3, 6, 1, 4, 1, 4146, 1, 40}):
		fmt.Fprintf(writer, "GlobalSign client certificate (%s)\n", oid)
	case oid.Equal([]int{1, 3, 6, 1, 4, 1, 4146, 1, 50}):
		fmt.Fprintf(writer, "GlobalSign code signing certificate (%s)\n", oid)
	case oid.Equal([]int{1, 3, 6, 1, 4, 1, 4146, 1, 60}):
		fmt.Fprintf(writer, "GlobalSign root signing certificate (%s)\n", oid)
	case oid.Equal([]int{1, 3, 6, 1, 4, 1, 4146, 1, 70}):
		fmt.Fprintf(writer, "GlobalSign trusted root certificate (%s)\n", oid)
	case oid.Equal([]int{1, 3, 6, 1, 4, 1, 4146, 1, 80}):
		fmt.Fprintf(writer, "GlobalSign retail industry EDI client certificate (%s)\n", oid)
	case oid.Equal([]int{1, 3, 6, 1, 4, 1, 4146, 1, 81}):
		fmt.Fprintf(writer, "GlobalSign retail industry EDI server certificate (%s)\n", oid)
	// - http://www.entrust.net/CPS/pdf/webcps090809.pdf
	case oid.Equal([]int{1, 2, 840, 113533, 7, 75, 2}):
		fmt.Fprintf(writer, "Entrust SSL certificate (%s)\n", oid)
	case oid.Equal([]int{2, 16, 840, 1, 114028, 10, 1, 3}):
		fmt.Fprintf(writer, "Entrust code signing certificate (%s)\n", oid)
	case oid.Equal([]int{2, 16, 840, 1, 114028, 10, 1, 4}):
		fmt.Fprintf(writer, "Entrust client certificate (%s)\n", oid)
	// - http://www.symantec.com/content/en/us/about/media/repository/nf-ssp-pki-cps.pdf
	case oid.Equal([]int{2, 16, 840, 1, 113733, 1, 7, 23, 1}):
		fmt.Fprintf(writer, "Symantec Trust Network class 1 (%s)\n", oid)
	case oid.Equal([]int{2, 16, 840, 1, 113733, 1, 7, 23, 2}):
		fmt.Fprintf(writer, "Symantec Trust Network class 2 (%s)\n", oid)
	case oid.Equal([]int{2, 16, 840, 1, 113733, 1, 7, 23, 3}):
		fmt.Fprintf(writer, "Symantec Trust Network class 3 (%s)\n", oid)
	default:
		attr := oid.String()
		if value, ok := attributeNameMap[attr]; ok {
			fmt.Fprintf(writer, "%s (%s)\n", value, attr)
		} else {
			fmt.Fprintf(writer, "Unknown (%s)\n", oid)
		}
	}
}

var attributeNameMap = map[string]string{
	"0.9.2342.19200300.100.1.1":  "user ID",
	"0.9.2342.19200300.100.1.2":  "address",
	"0.9.2342.19200300.100.1.3":  "mailbox",
	"0.9.2342.19200300.100.1.4":  "info",
	"0.9.2342.19200300.100.1.5":  "favourite drink",
	"0.9.2342.19200300.100.1.6":  "room number",
	"0.9.2342.19200300.100.1.8":  "user class",
	"0.9.2342.19200300.100.1.9":  "host",
	"0.9.2342.19200300.100.1.10": "manager",
	"0.9.2342.19200300.100.1.11": "document identifier",
	"0.9.2342.19200300.100.1.12": "document title",
	"0.9.2342.19200300.100.1.13": "document version",
	"0.9.2342.19200300.100.1.14": "document author",
	"0.9.2342.19200300.100.1.15": "document location",
	"0.9.2342.19200300.100.1.25": "domain component",
	"0.9.2342.19200300.100.1.26": "a record",
	"0.9.2342.19200300.100.1.27": "md record",
	"0.9.2342.19200300.100.1.28": "mx record",
	"0.9.2342.19200300.100.1.29": "ns record",
	"0.9.2342.19200300.100.1.30": "soa record",
	"0.9.2342.19200300.100.1.31": "cname record",
	"0.9.2342.19200300.100.1.42": "pager",
	"0.9.2342.19200300.100.1.44": "uniqueidentifier",
	"1.2.840.113549.1.9.1":       "e-mail address",
	"1.2.840.113549.1.9.2":       "unstructured name",
	"1.2.840.113549.1.9.3":       "content type",
	"1.2.840.113549.1.9.4":       "message digest",
	"1.2.840.113549.1.9.5":       "signing time",
	"1.2.840.113549.1.9.7":       "challenge password",
	"1.2.840.113549.1.9.8":       "unstructured address",
	"1.2.840.113549.1.9.13":      "signing description",
	"1.2.840.113549.1.9.14":      "extension request",
	"1.2.840.113549.1.9.15":      "S/MIME capabilities",
	"1.2.840.113549.1.9.16":      "S/MIME object identifier registry",
	"1.2.840.113549.1.9.20":      "friendly name",
	"1.2.840.113549.1.9.22":      "cert types",
	"2.5.4.0":                    "object class",
	"2.5.4.1":                    "aliased entry",
	"2.5.4.2":                    "knowldgeinformation",
	"2.5.4.3":                    "common name",
	"2.5.4.4":                    "surname",
	"2.5.4.5":                    "serial number",
	"2.5.4.6":                    "country",
	"2.5.4.7":                    "locality",
	"2.5.4.8":                    "state or province",
	"2.5.4.9":                    "street address",
	"2.5.4.10":                   "organization",
	"2.5.4.11":                   "organizational unit",
	"2.5.4.12":                   "title",
	"2.5.4.13":                   "description",
	"2.5.4.14":                   "search guide",
	"2.5.4.15":                   "business category",
	"2.5.4.16":                   "postal address",
	"2.5.4.17":                   "postal code",
	"2.5.4.18":                   "post office box",
	"2.5.4.19":                   "physical delivery office name",
	"2.5.4.20":                   "telephone number",
	"2.5.4.21":                   "telex number",
	"2.5.4.22":                   "teletex terminal identifier",
	"2.5.4.23":                   "facsimile telephone number",
	"2.5.4.24":                   "x121 address",
	"2.5.4.25":                   "international ISDN number",
	"2.5.4.26":                   "registered address",
	"2.5.4.27":                   "destination indicator",
	"2.5.4.28":                   "preferred delivery method",
	"2.5.4.29":                   "presentation address",
	"2.5.4.30":                   "supported application context",
	"2.5.4.31":                   "member",
	"2.5.4.32":                   "owner",
	"2.5.4.33":                   "role occupant",
	"2.5.4.34":                   "see also",
	"2.5.4.35":                   "user password",
	"2.5.4.36":                   "user certificate",
	"2.5.4.37":                   "CA certificate",
	"2.5.4.38":                   "authority revocation list",
	"2.5.4.39":                   "certificate revocation list",
	"2.5.4.40":                   "cross certificate pair",
	"2.5.4.41":                   "name",
	"2.5.4.42":                   "given name",
	"2.5.4.43":                   "initials",
	"2.5.4.44":                   "generation qualifier",
	"2.5.4.45":                   "unique identifier",
	"2.5.4.46":                   "DN qualifier",
	"2.5.4.47":                   "enhanced search guide",
	"2.5.4.48":                   "protocol information",
	"2.5.4.49":                   "distinguished name",
	"2.5.4.50":                   "unique member",
	"2.5.4.51":                   "house identifier",
	"2.5.4.52":                   "supported algorithms",
	"2.5.4.53":                   "delta revocation list",
	"2.5.4.58":                   "attribute certificate",
	"2.5.4.65":                   "pseudonym",
}

// DumpData dumps any structure as colon padded data to the terminal, mainly
// used to dump (long) integers or byte slices.
func DumpData(i interface{}, pad int, writer io.Writer) {
	var pads = strings.Repeat("  ", pad)
	var x = 80 - pad

	switch v := i.(type) {
	case *big.Int:
		var p = certformat.Formater(fmt.Sprintf("%x", v), ":", "0")
		w := (x / 3) * 3
		for j := 0; j < len(p); j += w {
			m := j + w
			if m > len(p) {
				m = len(p)
			}
			fmt.Fprintf(writer, "%s%s\n", pads, p[j:m])
		}

	case string:
		for j := 0; j < len(v); j += x {
			m := j + x
			if m > len(v) {
				m = len(v)
			}
			fmt.Fprintf(writer, "%s%s\n", pads, v[j:m])
		}

	case *string:
		DumpData(*v, pad, writer)

	case []uint8: // aka []byte
		var p = certformat.Formater(hex.EncodeToString(v), ":", "0")
		w := (x / 3) * 3
		for j := 0; j < len(p); j += w {
			m := j + w
			if m > len(p) {
				m = len(p)
			}
			fmt.Fprintf(writer, "%s%s\n", pads, p[j:m])
		}

	default:
		panic(fmt.Sprintf("don't know how to dump %T", v))
	}
}

// DumpX509Extension dumps an X.509 certificate extension to the terminal.
func DumpX509Extension(ext pkix.Extension, pad int, writer io.Writer) {
	var pads = strings.Repeat("  ", pad)
	var crit = "critical"
	if !ext.Critical {
		crit = ""
	}

	switch {
	case ext.Id.Equal(oidMicrosoftCertSrv):
		// http://msdn.microsoft.com/en-us/library/windows/desktop/aa376550(v=vs.85).aspx
		fmt.Fprintf(writer, "%sMicrosoft certificate server:\n", pads)
		var version int
		_, err := asn1.Unmarshal(ext.Value, &version)
		if err == nil {
			ci := version & 0xff
			ki := version >> 16
			fmt.Fprintf(writer, "%s  Certificate index: %d\n", pads, ci)
			fmt.Fprintf(writer, "%s  Key index: %d\n", pads, ki)
		}

	case ext.Id.Equal(oidMicrosoftPreviousCertHash):
		fmt.Fprintf(writer, "%sMicrosoft previous CA certificate hash:\n", pads)
		var hash asn1.RawValue
		_, err := asn1.Unmarshal(ext.Value, &hash)
		if err == nil {
			DumpData(hash.Bytes, pad+1, writer)
		}

	case ext.Id.Equal(oidMicrosoftCertificateTemplate):
		// http://msdn.microsoft.com/en-us/library/cc250012.aspx
		fmt.Fprintf(writer, "%sMicrosoft certificate template (v2):\n", pads)
		var template struct {
			ID         asn1.ObjectIdentifier
			MajVersion int64 `asn1:"optional"`
			MinVersion int64 `asn1:"optional"`
		}
		_, err := asn1.Unmarshal(ext.Value, &template)
		if err == nil {
			fmt.Fprintf(writer, "%s  ID: %s\n", pads, template.ID)
			if template.MinVersion > 0 {
				fmt.Fprintf(writer, "%s  minor version: %d\n", pads, template.MinVersion)
			}
			if template.MajVersion > 0 {
				fmt.Fprintf(writer, "%s  major version: %d\n", pads, template.MajVersion)
			}
		}

	case ext.Id.Equal(oidExtensionAuthorityKeyID):
		fmt.Fprintf(writer, "%sX509v3 Authority key identifier: %s\n", pads, crit)
		aki := &AuthorityKeyID{}
		_, err := asn1.Unmarshal(ext.Value, aki)
		if err == nil {
			s := fmt.Sprintf("keyid:֬%s", certformat.HexColonFormat(aki.ID, ":"))
			DumpData(s, pad+1, writer)
		}

	case ext.Id.Equal(oidExtBasicConstraints):
		fmt.Fprintf(writer, "%sX509v3 Basic Constraints: %s\n", pads, crit)
		var b struct {
			IsCA       bool `asn1:"optional"`
			MaxPathLen int  `asn1:"optional,default:-1"`
		}
		_, err := asn1.Unmarshal(ext.Value, &b)
		if err == nil {
			s := fmt.Sprintf("CA:֬%v", b.IsCA)
			s = strings.ToUpper(s)
			DumpData(s, pad+1, writer)
		}

	case ext.Id.Equal(oidExtensionKeyUsage):
		// RFC 5280, 4.2.1.3
		fmt.Fprintf(writer, "%sKey usage: %s\n", pads, crit)
		var usageBits asn1.BitString
		_, err := asn1.Unmarshal(ext.Value, &usageBits)
		if err == nil {
			for i := 0; i < len(keyUsages); i++ {
				if usageBits.At(i) != 0 {
					fmt.Fprintf(writer, "%s  %s (%d)\n", pads, keyUsages[i], i)
				}
			}
		}

	case ext.Id.Equal(oidExtensionSubjectKeyID):
		fmt.Fprintf(writer, "%sSubject key identifier: %s\n", pads, crit)
		var keyid []byte
		_, err := asn1.Unmarshal(ext.Value, &keyid)
		if err == nil {
			DumpData(keyid, pad+1, writer)
		}

	case ext.Id.Equal(oidExtensionExtendedKeyUsage):
		// RFC 5280, 4.2.1.12.  Extended Key Usage
		fmt.Fprintf(writer, "%sExtended key usage: %s\n", pads, crit)
		var extKeyUsage []asn1.ObjectIdentifier
		_, err := asn1.Unmarshal(ext.Value, &extKeyUsage)
		if err == nil {
			for _, oid := range extKeyUsage {
				DumpOID(oid, pad+1, writer)
			}
		}

	case ext.Id.Equal(oidExtensionNSCertificateComment):
		fmt.Fprintf(writer, "%sNetscape certificate comment:\n", pads)
		var comment string
		_, err := asn1.Unmarshal(ext.Value, &comment)
		if err == nil {
			fmt.Fprintf(writer, "%s  %s\n", pads, comment)
		}

	case ext.Id.Equal(oidExtensionLogotype):
		// Logotype is quite complex, and contains mostly images, we'll skip parsing it for now and
		// only print the name of the extension type.
		fmt.Fprintf(writer, "%sLogo type: %s\n", pads, crit)
		format.Hexdump(ext.Value, writer)

	default:
		DumpOID(ext.Id, pad, writer)
		format.Hexdump(ext.Value, writer)
	}
}
