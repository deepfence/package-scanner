package util

import (
	"bytes"
	"encoding/json"
	"math/rand"
	"os"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	charset = "abcdefghijklmnopqrstuvwxyz" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

func GetIntTimestamp() int64 {
	return time.Now().UTC().UnixNano() / 1000000
}

func GetDatetimeNow() string {
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
