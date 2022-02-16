module github.com/deepfence/package-scanner

go 1.17

require (
	github.com/deepfence/agent-plugins-grpc v0.0.0
	github.com/sirupsen/logrus v1.8.1
	google.golang.org/grpc v1.43.0
)

require (
	github.com/golang/protobuf v1.5.2 // indirect
	golang.org/x/net v0.0.0-20200822124328-c89045814202 // indirect
	golang.org/x/sys v0.0.0-20200323222414-85ca7c5b95cd // indirect
	golang.org/x/text v0.3.0 // indirect
	google.golang.org/genproto v0.0.0-20200526211855-cb27e3aa2013 // indirect
	google.golang.org/protobuf v1.26.0 // indirect
)

replace github.com/deepfence/agent-plugins-grpc => ./agent-plugins-grpc
