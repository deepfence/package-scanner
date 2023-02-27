package utils

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

const metasploitURLPattern = "github.com/rapid7/metasploit-framework"

const (
	charset = "abcdefghijklmnopqrstuvwxyz" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

func GetIntTimestamp() int64 {
	return time.Now().UTC().UnixNano() / 1000000
}

func GetDateTimeNow() string {
	return time.Now().UTC().Format("2006-01-02T15:04:05.000")
}

func GetHostname() string {
	if hostname := os.Getenv("SCOPE_HOSTNAME"); hostname != "" {
		return hostname
	}
	hostname, err := os.Hostname()
	if err != nil {
		return "(unknown)"
	}
	return hostname
}

var seededRand *rand.Rand = rand.New(rand.NewSource(time.Now().UnixNano()))

func RandomStringWithCharset(length int, charset string) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}

func RandomString(length int) string {
	return RandomStringWithCharset(length, charset)
}

// data needs to be in this format for kafka rest proxy
// {"records":[{"value":<record1>},{"value":record2}]}
func ToKafkaRestFormat(data []map[string]interface{}) *bytes.Buffer {
	values := make([]string, len(data))
	for i, d := range data {
		encoded, err := json.Marshal(&d)
		if err != nil {
			log.Errorf("failed to encode doc: %s", err)
			continue
		}
		values[i] = "{\"value\":" + string(encoded) + "}"
	}
	return bytes.NewBuffer([]byte("{\"records\":[" + strings.Join(values, ",") + "]}"))
}

func ValidateSbom(userInput []byte) error {
	return nil
}

// Escape escapes the user input to be used as a command line argument
// removes all the double quotes
func Escape(userInput []byte) []byte {
	st := string(userInput)
	// re is \"
	re := `\"`
	st = strings.Replace(st, "\"", re, -1)
	return []byte(st)
}

func CreateTempFile(userInput []byte) (*os.File, error) {
	file, err := ioutil.TempFile("/tmp", "sbom.*.json")
	if err != nil {
		return nil, err
	}
	_, err = file.Write(userInput)
	if err != nil {
		return nil, err
	}

	return file, err
}

func TrimSuffix(s, suffix string) string {
	if strings.HasSuffix(s, suffix) {
		s = s[:len(s)-len(suffix)]
	}
	return s
}

func Contains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}

	return false
}

func ExtractExploitPocUrl(url []string) (string, []string) {
	if len(url) == 0 {
		return "", nil
	}
	var nonExploitPocUrls []string
	var metasploitURL string
	for _, u := range url {
		if strings.Contains(u, metasploitURLPattern) {
			metasploitURL = u
		} else {
			nonExploitPocUrls = append(nonExploitPocUrls, u)
		}
	}
	return metasploitURL, nonExploitPocUrls
}

func getTimestamp() string {
	return strconv.FormatInt(time.Now().UTC().UnixNano(), 10)
}

func getIntTimestamp() int64 {
	return time.Now().UTC().UnixNano() / 1000000
}

func getDatetimeNow() string {
	return time.Now().UTC().Format("2006-01-02T15:04:05.000")
}
