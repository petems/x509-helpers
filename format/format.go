package format

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"strings"
	"unicode/utf8"
)

// Hexdump dumps a byte sequence in `hexdump -C` style to a given writer
func Hexdump(d []byte, writer io.Writer) {
	fmt.Fprintf(writer, hex.Dump(d))
}

// HexColonFormat returns the byte buffer formatted in hex with a colon seperator
func HexColonFormat(buf []byte, sep string) string {
	var ret bytes.Buffer
	for _, cur := range buf {
		if ret.Len() > 0 {
			fmt.Fprintf(&ret, ":")
		}
		fmt.Fprintf(&ret, "%02x", cur)
	}
	return ret.String()
}

// Formater takes a given string an splits via a given sepeator
func Formater(s, sep, fill string) string {
	if len(s)%2 > 0 {
		s = fill + s
	}
	var p = []string{}
	for j := 0; j < len(s); j += 2 {
		p = append(p, s[j:j+2])
	}
	return strings.Join(p, sep)
}

func splitSubN(s string, n int) string {
	if len(s) == 0 {
		return ""
	}
	m := 0
	i := 0
	j := 1
	var result []string
	for ; j < len(s); j++ {
		if utf8.RuneStart(s[j]) {
			if (m+1)%n == 0 {
				result = append(result, s[i:j])
				i = j
			}
			m++
		}
	}
	if j > i {
		result = append(result, s[i:j])
	}

	return strings.Join(result, "\n")
}

// ASNOneModulusFormat takes a given modulus from an RSA key and returns it as a formated hexadecimal with a leading 00
// We have to add in the leading zero as it's a quirk of the ASN formatting
// See https://web.archive.org/web/20201102210932/https://crypto.stackexchange.com/questions/30608/leading-00-in-rsa-public-private-key-file/30616 for full context
func ASNOneModulusFormat(i *big.Int, width int) string {
	var p = Formater(fmt.Sprintf("%x", i), ":", "0")
	p = fmt.Sprintf("00:%s", p)
	output := splitSubN(p, width)

	return output
}
