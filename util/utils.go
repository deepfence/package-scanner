package util

import (
	"math/rand"
	"os"
	"time"

	"github.com/deepfence/vessel"
	vesselConstants "github.com/deepfence/vessel/constants"
	containerdRuntime "github.com/deepfence/vessel/containerd"
	log "github.com/sirupsen/logrus"
)

const (
	charset = "abcdefghijklmnopqrstuvwxyz" + "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

var ContainerRuntimeInterface vessel.Runtime

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

func SetContainerRuntimeInterface(containerdSock string) {
	containerRuntime, _, err := vessel.AutoDetectRuntime()
	if err != nil {
		log.Errorf("Error detecting container runtime: %v", err)
		os.Exit(1)
	}
	log.Debugf("Detected container runtime: %s", containerRuntime)

	switch containerRuntime {
	case vesselConstants.CONTAINERD:
		ContainerRuntimeInterface = containerdRuntime.New(containerdSock)
	}
}
