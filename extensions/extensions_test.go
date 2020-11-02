package extensions

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"regexp"
	"testing"

	"github.com/alecthomas/assert"
)

func TestDumpX509Extension(t *testing.T) {

	tests := []struct {
		inputcert string
		width     int
		expected  *regexp.Regexp
	}{
		{
			inputcert: `-----BEGIN CERTIFICATE-----
MIIFfjCCA2agAwIBAgIBBDANBgkqhkiG9w0BAQsFADAfMR0wGwYDVQQDDBRQdXBw
ZXQgQ0E6IHB1cHBldC52bTAeFw0yMDEwMjIxMzAzMzZaFw0yNTEwMjIxMzAzMzZa
MBMxETAPBgNVBAMMCG5vZGUxLnZtMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
CgKCAgEAwuku3pXXt9SPyESY0eMOSqu+TSadrlHSqyZ0clqf85B06oXjEnMHWsNq
67OdHA1rc2UHdSxafqKdfJlHD4V/hwyBG6FqtF6WsMd1edsxI63a3PXCh21SrxKv
BzXrntmWhdtJz5ivq3TyrEYEZwVWCU2GinwGagkvQEdUdqfAlAeZx+PyDq0hz+px
S709cXNIQpcstOF217oEmvsROQcUurqCwOHXTMXa5wLKDNxY9TdG6brDF+46giap
a1t+Eht4CB182v+kNBhDx+XKL+CVSsIzsvkjWpo99KASiiz4tHR99V2KPzPoCN/M
hMQKslehu5FnawKNtdHXPEy6CODikAxHKo/Fm5juvApziBrTMURYeY3b++0fJhsh
NyVzmc5TlRDc6l3TkVjkLaEYQHAKMMwFW+4WTmdSYomXUoo4AFtWeLx/uaXOY0NL
YJ/nlJZTaMxRbz7IA9nh0jOAoqoxvnXaUj/Zsl8+bhKllRNC/PswgA4wPS4qF1WL
RdHuo8zUs8geF6kAPpeaQ2iy5rnUx5O7KcXzR3ZNo27JaT3t3E5/9LROo0XCR2Cn
lxzbzMomKCdSqXKFAzSUFF2yLbPbXPjlRsYP4mccS88wxG5vUY/jp3PYjBqnLbBP
hdWNtr45rjqWnGoVcrMsp8ViVeS9AiHIxUM73msE1ozzc9VYfR8CAwEAAaOB0DCB
zTAxBglghkgBhvhCAQ0EJBYiUHVwcGV0IFNlcnZlciBJbnRlcm5hbCBDZXJ0aWZp
Y2F0ZTAfBgNVHSMEGDAWgBTWrON2HXLNhIXOOw/viiU5kKIY4DAdBgNVHQ4EFgQU
w+9WFEhP8DhoC4oaxJreaomAFRAwGAYLKwYBBAGCjEwBARYECQwHdmF1bHRvazAM
BgNVHRMBAf8EAjAAMCAGA1UdJQEB/wQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAO
BgNVHQ8BAf8EBAMCBaAwDQYJKoZIhvcNAQELBQADggIBAD5D5n4UKi8k0rFYITQg
cfv/7uyPc0PWT+N9xjs6QW8iMiEBUouv8doqOmmvAEXFaucPXukUJBmnMszfoN1i
t8xdKASNNbn6OzKq6Yw/G6OAJ9K8KJzN2o7gGv8zEyMPeh0Sthl3QjgeCqlzcp7X
DfWji3vhn1KPaGE9aE/Hb35BMo4ttBDIENmXb7AHdBfDkmAcX6mM+lGKZTpFIc90
Db0L7IdlXlR7S8Y7z9aUI20Vsv92Z+6qWrff1rjmiHN1hRvD1Cvi0xRIH3D64CQ+
Oy6WUD8wk650COB891/LWv2VUqiQ3gpjOQov2BlV8htO9bOzSs2aNMq0l0FVk4/T
ZpsmpSmki07diN1c6AgpdLxKL8yIfgGbUVefFZjnop7gZY6RU/O7m/EB/5KeLAxY
pThD6SbaroaQ2nmxsSkbm3qFC8hVI2b8TC8+o+P/+iHnxyaXsLlOTf1IJQrvWd6m
0IewOcjnsSVpeZadElFTJMo4753PCRJRwIbe7XiyDD6aiGKauHMb95s5i+Is9QGe
dW1AYTherUbOrYQ2FpWn1fcM8QpXS+2k9pMLYue/mVAcbJNM0DxwjOuG9uJFOqzB
rV+y9tkNbTPsiv3hMhkaKOoMs2qW8f3E7BI1UiRbNxsuOVV7WycFBPW8TKwBmcRj
GHG6b/SnmObT3lQ7VnGtVc1f
-----END CERTIFICATE-----`,
			expected: regexp.MustCompile(`Unknown \(1.3.6.1.4.1.34380.1.1.22\)`),
		},
	}

	for _, tc := range tests {

		pemBlock, _ := pem.Decode([]byte(tc.inputcert))

		cert, err := x509.ParseCertificate(pemBlock.Bytes)

		if err != nil {
			t.Fatalf("Error when reading cert: %v", err)
		}

		var b bytes.Buffer

		if len(cert.Extensions) > 0 {
			for _, ext := range cert.Extensions {
				DumpX509Extension(ext, 8, &b)
			}
		}

		assert.Regexp(t, tc.expected, b.String())
	}

}
