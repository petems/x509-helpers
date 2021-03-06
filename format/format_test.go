package format

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
)

func TestASNOneModulusFormat(t *testing.T) {

	tests := []struct {
		input    string
		width    int
		expected string
	}{
		{
			input: "795166980387013379670506314725293893890728055512518865314585833155352240869159034738233615672361214029303886145100028868258629912617953840215576047571875627028546153245913740827523232201685482982444484728059915791002239104862055438404845085825996719487084488309482533844892506959860056908675483301711801520192178450346787289933502391647532748197629962108435786242586145659090816934931857752845326293074819716461502867430460467277440855565514161951329717737378354803914394547651150831033184143716534472105993193897089831909744792422955513615934405051814828487591740413616069423045830033906097300950809785397885248838288844056229649171799814738411810785685746958822475011824143181607561853403237288031325591760392274962153719813683511558805612717718477951080265402443668227732728635530840656932290540669805546615829682204876621921202448153684215576267587031612875139355597336060812203566831060682874389509751966737873517226392326491132402812601366716625175051968172049897283036926394067608607155217328807718798335530088533017202810156135410160256604241247477737140752981730320031854797310451676137931399891308925836141152549183004718795370900973244477547482001051173330685497364246485811391403868004080807096388894865698783194810711327",
			width: 45,
			expected: `00:c2:e9:2e:de:95:d7:b7:d4:8f:c8:44:98:d1:e3:
0e:4a:ab:be:4d:26:9d:ae:51:d2:ab:26:74:72:5a:
9f:f3:90:74:ea:85:e3:12:73:07:5a:c3:6a:eb:b3:
9d:1c:0d:6b:73:65:07:75:2c:5a:7e:a2:9d:7c:99:
47:0f:85:7f:87:0c:81:1b:a1:6a:b4:5e:96:b0:c7:
75:79:db:31:23:ad:da:dc:f5:c2:87:6d:52:af:12:
af:07:35:eb:9e:d9:96:85:db:49:cf:98:af:ab:74:
f2:ac:46:04:67:05:56:09:4d:86:8a:7c:06:6a:09:
2f:40:47:54:76:a7:c0:94:07:99:c7:e3:f2:0e:ad:
21:cf:ea:71:4b:bd:3d:71:73:48:42:97:2c:b4:e1:
76:d7:ba:04:9a:fb:11:39:07:14:ba:ba:82:c0:e1:
d7:4c:c5:da:e7:02:ca:0c:dc:58:f5:37:46:e9:ba:
c3:17:ee:3a:82:26:a9:6b:5b:7e:12:1b:78:08:1d:
7c:da:ff:a4:34:18:43:c7:e5:ca:2f:e0:95:4a:c2:
33:b2:f9:23:5a:9a:3d:f4:a0:12:8a:2c:f8:b4:74:
7d:f5:5d:8a:3f:33:e8:08:df:cc:84:c4:0a:b2:57:
a1:bb:91:67:6b:02:8d:b5:d1:d7:3c:4c:ba:08:e0:
e2:90:0c:47:2a:8f:c5:9b:98:ee:bc:0a:73:88:1a:
d3:31:44:58:79:8d:db:fb:ed:1f:26:1b:21:37:25:
73:99:ce:53:95:10:dc:ea:5d:d3:91:58:e4:2d:a1:
18:40:70:0a:30:cc:05:5b:ee:16:4e:67:52:62:89:
97:52:8a:38:00:5b:56:78:bc:7f:b9:a5:ce:63:43:
4b:60:9f:e7:94:96:53:68:cc:51:6f:3e:c8:03:d9:
e1:d2:33:80:a2:aa:31:be:75:da:52:3f:d9:b2:5f:
3e:6e:12:a5:95:13:42:fc:fb:30:80:0e:30:3d:2e:
2a:17:55:8b:45:d1:ee:a3:cc:d4:b3:c8:1e:17:a9:
00:3e:97:9a:43:68:b2:e6:b9:d4:c7:93:bb:29:c5:
f3:47:76:4d:a3:6e:c9:69:3d:ed:dc:4e:7f:f4:b4:
4e:a3:45:c2:47:60:a7:97:1c:db:cc:ca:26:28:27:
52:a9:72:85:03:34:94:14:5d:b2:2d:b3:db:5c:f8:
e5:46:c6:0f:e2:67:1c:4b:cf:30:c4:6e:6f:51:8f:
e3:a7:73:d8:8c:1a:a7:2d:b0:4f:85:d5:8d:b6:be:
39:ae:3a:96:9c:6a:15:72:b3:2c:a7:c5:62:55:e4:
bd:02:21:c8:c5:43:3b:de:6b:04:d6:8c:f3:73:d5:
58:7d:1f`,
		},
		{
			input: "795166980387013379670506314725293893890728055512518865314585833155352240869159034738233615672361214029303886145100028868258629912617953840215576047571875627028546153245913740827523232201685482982444484728059915791002239104862055438404845085825996719487084488309482533844892506959860056908675483301711801520192178450346787289933502391647532748197629962108435786242586145659090816934931857752845326293074819716461502867430460467277440855565514161951329717737378354803914394547651150831033184143716534472105993193897089831909744792422955513615934405051814828487591740413616069423045830033906097300950809785397885248838288844056229649171799814738411810785685746958822475011824143181607561853403237288031325591760392274962153719813683511558805612717718477951080265402443668227732728635530840656932290540669805546615829682204876621921202448153684215576267587031612875139355597336060812203566831060682874389509751966737873517226392326491132402812601366716625175051968172049897283036926394067608607155217328807718798335530088533017202810156135410160256604241247477737140752981730320031854797310451676137931399891308925836141152549183004718795370900973244477547482001051173330685497364246485811391403868004080807096388894865698783194810711327",
			width: 78,
			expected: `00:c2:e9:2e:de:95:d7:b7:d4:8f:c8:44:98:d1:e3:0e:4a:ab:be:4d:26:9d:ae:51:d2:ab:
26:74:72:5a:9f:f3:90:74:ea:85:e3:12:73:07:5a:c3:6a:eb:b3:9d:1c:0d:6b:73:65:07:
75:2c:5a:7e:a2:9d:7c:99:47:0f:85:7f:87:0c:81:1b:a1:6a:b4:5e:96:b0:c7:75:79:db:
31:23:ad:da:dc:f5:c2:87:6d:52:af:12:af:07:35:eb:9e:d9:96:85:db:49:cf:98:af:ab:
74:f2:ac:46:04:67:05:56:09:4d:86:8a:7c:06:6a:09:2f:40:47:54:76:a7:c0:94:07:99:
c7:e3:f2:0e:ad:21:cf:ea:71:4b:bd:3d:71:73:48:42:97:2c:b4:e1:76:d7:ba:04:9a:fb:
11:39:07:14:ba:ba:82:c0:e1:d7:4c:c5:da:e7:02:ca:0c:dc:58:f5:37:46:e9:ba:c3:17:
ee:3a:82:26:a9:6b:5b:7e:12:1b:78:08:1d:7c:da:ff:a4:34:18:43:c7:e5:ca:2f:e0:95:
4a:c2:33:b2:f9:23:5a:9a:3d:f4:a0:12:8a:2c:f8:b4:74:7d:f5:5d:8a:3f:33:e8:08:df:
cc:84:c4:0a:b2:57:a1:bb:91:67:6b:02:8d:b5:d1:d7:3c:4c:ba:08:e0:e2:90:0c:47:2a:
8f:c5:9b:98:ee:bc:0a:73:88:1a:d3:31:44:58:79:8d:db:fb:ed:1f:26:1b:21:37:25:73:
99:ce:53:95:10:dc:ea:5d:d3:91:58:e4:2d:a1:18:40:70:0a:30:cc:05:5b:ee:16:4e:67:
52:62:89:97:52:8a:38:00:5b:56:78:bc:7f:b9:a5:ce:63:43:4b:60:9f:e7:94:96:53:68:
cc:51:6f:3e:c8:03:d9:e1:d2:33:80:a2:aa:31:be:75:da:52:3f:d9:b2:5f:3e:6e:12:a5:
95:13:42:fc:fb:30:80:0e:30:3d:2e:2a:17:55:8b:45:d1:ee:a3:cc:d4:b3:c8:1e:17:a9:
00:3e:97:9a:43:68:b2:e6:b9:d4:c7:93:bb:29:c5:f3:47:76:4d:a3:6e:c9:69:3d:ed:dc:
4e:7f:f4:b4:4e:a3:45:c2:47:60:a7:97:1c:db:cc:ca:26:28:27:52:a9:72:85:03:34:94:
14:5d:b2:2d:b3:db:5c:f8:e5:46:c6:0f:e2:67:1c:4b:cf:30:c4:6e:6f:51:8f:e3:a7:73:
d8:8c:1a:a7:2d:b0:4f:85:d5:8d:b6:be:39:ae:3a:96:9c:6a:15:72:b3:2c:a7:c5:62:55:
e4:bd:02:21:c8:c5:43:3b:de:6b:04:d6:8c:f3:73:d5:58:7d:1f`,
		},
		{
			input:    "10",
			width:    45,
			expected: `00:0a`,
		},
		{
			input:    "9999999999",
			width:    45,
			expected: `00:02:54:0b:e3:ff`,
		},
	}

	for _, tc := range tests {
		i := new(big.Int)
		_, err := fmt.Sscan(tc.input, i)

		if err != nil {
			t.Fatalf("Error when reading bigInt: %v", err)
		}

		got := ASNOneModulusFormat(i, tc.width)

		assert.Equal(t, tc.expected, got)
	}

}

func TestDumpHex(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{
			input: `When shall we three meet again`,
			expected: `00000000  57 68 65 6e 20 73 68 61  6c 6c 20 77 65 20 74 68  |When shall we th|
00000010  72 65 65 20 6d 65 65 74  20 61 67 61 69 6e        |ree meet again|
`,
		},
	}

	for _, tc := range tests {
		var b bytes.Buffer

		Hexdump([]byte(tc.input), &b)

		if diff := cmp.Diff(tc.expected, b.String()); diff != "" {
			t.Error(diff)
		}

	}
}

func ExampleASNOneModulusFormat() {

	// Example dummy certificate
	pemExample := `-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----`

	pemBlock, _ := pem.Decode([]byte(pemExample))

	cert, _ := x509.ParseCertificate(pemBlock.Bytes)

	publicKey := cert.PublicKey.(*rsa.PublicKey).N

	i := new(big.Int)
	_, err := fmt.Sscan(fmt.Sprintf("%v", publicKey), i)

	if err != nil {
		panic(err)
	}

	fmt.Println(ASNOneModulusFormat(i, 45))
	// Output:
	// 00:c2:e9:2e:de:95:d7:b7:d4:8f:c8:44:98:d1:e3:
	// 0e:4a:ab:be:4d:26:9d:ae:51:d2:ab:26:74:72:5a:
	// 9f:f3:90:74:ea:85:e3:12:73:07:5a:c3:6a:eb:b3:
	// 9d:1c:0d:6b:73:65:07:75:2c:5a:7e:a2:9d:7c:99:
	// 47:0f:85:7f:87:0c:81:1b:a1:6a:b4:5e:96:b0:c7:
	// 75:79:db:31:23:ad:da:dc:f5:c2:87:6d:52:af:12:
	// af:07:35:eb:9e:d9:96:85:db:49:cf:98:af:ab:74:
	// f2:ac:46:04:67:05:56:09:4d:86:8a:7c:06:6a:09:
	// 2f:40:47:54:76:a7:c0:94:07:99:c7:e3:f2:0e:ad:
	// 21:cf:ea:71:4b:bd:3d:71:73:48:42:97:2c:b4:e1:
	// 76:d7:ba:04:9a:fb:11:39:07:14:ba:ba:82:c0:e1:
	// d7:4c:c5:da:e7:02:ca:0c:dc:58:f5:37:46:e9:ba:
	// c3:17:ee:3a:82:26:a9:6b:5b:7e:12:1b:78:08:1d:
	// 7c:da:ff:a4:34:18:43:c7:e5:ca:2f:e0:95:4a:c2:
	// 33:b2:f9:23:5a:9a:3d:f4:a0:12:8a:2c:f8:b4:74:
	// 7d:f5:5d:8a:3f:33:e8:08:df:cc:84:c4:0a:b2:57:
	// a1:bb:91:67:6b:02:8d:b5:d1:d7:3c:4c:ba:08:e0:
	// e2:90:0c:47:2a:8f:c5:9b:98:ee:bc:0a:73:88:1a:
	// d3:31:44:58:79:8d:db:fb:ed:1f:26:1b:21:37:25:
	// 73:99:ce:53:95:10:dc:ea:5d:d3:91:58:e4:2d:a1:
	// 18:40:70:0a:30:cc:05:5b:ee:16:4e:67:52:62:89:
	// 97:52:8a:38:00:5b:56:78:bc:7f:b9:a5:ce:63:43:
	// 4b:60:9f:e7:94:96:53:68:cc:51:6f:3e:c8:03:d9:
	// e1:d2:33:80:a2:aa:31:be:75:da:52:3f:d9:b2:5f:
	// 3e:6e:12:a5:95:13:42:fc:fb:30:80:0e:30:3d:2e:
	// 2a:17:55:8b:45:d1:ee:a3:cc:d4:b3:c8:1e:17:a9:
	// 00:3e:97:9a:43:68:b2:e6:b9:d4:c7:93:bb:29:c5:
	// f3:47:76:4d:a3:6e:c9:69:3d:ed:dc:4e:7f:f4:b4:
	// 4e:a3:45:c2:47:60:a7:97:1c:db:cc:ca:26:28:27:
	// 52:a9:72:85:03:34:94:14:5d:b2:2d:b3:db:5c:f8:
	// e5:46:c6:0f:e2:67:1c:4b:cf:30:c4:6e:6f:51:8f:
	// e3:a7:73:d8:8c:1a:a7:2d:b0:4f:85:d5:8d:b6:be:
	// 39:ae:3a:96:9c:6a:15:72:b3:2c:a7:c5:62:55:e4:
	// bd:02:21:c8:c5:43:3b:de:6b:04:d6:8c:f3:73:d5:
	// 58:7d:1f
}
