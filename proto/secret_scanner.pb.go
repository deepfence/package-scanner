// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.1
// 	protoc        v3.12.4
// source: secret_scanner.proto

package proto

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type DockerImage struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Id   string `protobuf:"bytes,2,opt,name=id,proto3" json:"id,omitempty"`
}

func (x *DockerImage) Reset() {
	*x = DockerImage{}
	if protoimpl.UnsafeEnabled {
		mi := &file_secret_scanner_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DockerImage) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DockerImage) ProtoMessage() {}

func (x *DockerImage) ProtoReflect() protoreflect.Message {
	mi := &file_secret_scanner_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DockerImage.ProtoReflect.Descriptor instead.
func (*DockerImage) Descriptor() ([]byte, []int) {
	return file_secret_scanner_proto_rawDescGZIP(), []int{0}
}

func (x *DockerImage) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *DockerImage) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

type Container struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id        string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	Namespace string `protobuf:"bytes,2,opt,name=namespace,proto3" json:"namespace,omitempty"`
}

func (x *Container) Reset() {
	*x = Container{}
	if protoimpl.UnsafeEnabled {
		mi := &file_secret_scanner_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Container) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Container) ProtoMessage() {}

func (x *Container) ProtoReflect() protoreflect.Message {
	mi := &file_secret_scanner_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Container.ProtoReflect.Descriptor instead.
func (*Container) Descriptor() ([]byte, []int) {
	return file_secret_scanner_proto_rawDescGZIP(), []int{1}
}

func (x *Container) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *Container) GetNamespace() string {
	if x != nil {
		return x.Namespace
	}
	return ""
}

type FindRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Types that are assignable to Input:
	//	*FindRequest_Path
	//	*FindRequest_Image
	//	*FindRequest_Container
	Input isFindRequest_Input `protobuf_oneof:"input"`
}

func (x *FindRequest) Reset() {
	*x = FindRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_secret_scanner_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *FindRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*FindRequest) ProtoMessage() {}

func (x *FindRequest) ProtoReflect() protoreflect.Message {
	mi := &file_secret_scanner_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use FindRequest.ProtoReflect.Descriptor instead.
func (*FindRequest) Descriptor() ([]byte, []int) {
	return file_secret_scanner_proto_rawDescGZIP(), []int{2}
}

func (m *FindRequest) GetInput() isFindRequest_Input {
	if m != nil {
		return m.Input
	}
	return nil
}

func (x *FindRequest) GetPath() string {
	if x, ok := x.GetInput().(*FindRequest_Path); ok {
		return x.Path
	}
	return ""
}

func (x *FindRequest) GetImage() *DockerImage {
	if x, ok := x.GetInput().(*FindRequest_Image); ok {
		return x.Image
	}
	return nil
}

func (x *FindRequest) GetContainer() *Container {
	if x, ok := x.GetInput().(*FindRequest_Container); ok {
		return x.Container
	}
	return nil
}

type isFindRequest_Input interface {
	isFindRequest_Input()
}

type FindRequest_Path struct {
	Path string `protobuf:"bytes,1,opt,name=path,proto3,oneof"`
}

type FindRequest_Image struct {
	Image *DockerImage `protobuf:"bytes,2,opt,name=image,proto3,oneof"`
}

type FindRequest_Container struct {
	Container *Container `protobuf:"bytes,3,opt,name=container,proto3,oneof"`
}

func (*FindRequest_Path) isFindRequest_Input() {}

func (*FindRequest_Image) isFindRequest_Input() {}

func (*FindRequest_Container) isFindRequest_Input() {}

type FindResult struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Types that are assignable to Input:
	//	*FindResult_Path
	//	*FindResult_Image
	//	*FindResult_Container
	Input     isFindResult_Input `protobuf_oneof:"input"`
	Timestamp string             `protobuf:"bytes,4,opt,name=timestamp,proto3" json:"timestamp,omitempty"`
	Secrets   []*SecretInfo      `protobuf:"bytes,5,rep,name=secrets,proto3" json:"secrets,omitempty"`
}

func (x *FindResult) Reset() {
	*x = FindResult{}
	if protoimpl.UnsafeEnabled {
		mi := &file_secret_scanner_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *FindResult) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*FindResult) ProtoMessage() {}

func (x *FindResult) ProtoReflect() protoreflect.Message {
	mi := &file_secret_scanner_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use FindResult.ProtoReflect.Descriptor instead.
func (*FindResult) Descriptor() ([]byte, []int) {
	return file_secret_scanner_proto_rawDescGZIP(), []int{3}
}

func (m *FindResult) GetInput() isFindResult_Input {
	if m != nil {
		return m.Input
	}
	return nil
}

func (x *FindResult) GetPath() string {
	if x, ok := x.GetInput().(*FindResult_Path); ok {
		return x.Path
	}
	return ""
}

func (x *FindResult) GetImage() *DockerImage {
	if x, ok := x.GetInput().(*FindResult_Image); ok {
		return x.Image
	}
	return nil
}

func (x *FindResult) GetContainer() *Container {
	if x, ok := x.GetInput().(*FindResult_Container); ok {
		return x.Container
	}
	return nil
}

func (x *FindResult) GetTimestamp() string {
	if x != nil {
		return x.Timestamp
	}
	return ""
}

func (x *FindResult) GetSecrets() []*SecretInfo {
	if x != nil {
		return x.Secrets
	}
	return nil
}

type isFindResult_Input interface {
	isFindResult_Input()
}

type FindResult_Path struct {
	Path string `protobuf:"bytes,1,opt,name=path,proto3,oneof"`
}

type FindResult_Image struct {
	Image *DockerImage `protobuf:"bytes,2,opt,name=image,proto3,oneof"`
}

type FindResult_Container struct {
	Container *Container `protobuf:"bytes,3,opt,name=container,proto3,oneof"`
}

func (*FindResult_Path) isFindResult_Input() {}

func (*FindResult_Image) isFindResult_Input() {}

func (*FindResult_Container) isFindResult_Input() {}

type MatchRule struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id               int32  `protobuf:"varint,1,opt,name=id,proto3" json:"id,omitempty"`
	Name             string `protobuf:"bytes,2,opt,name=name,proto3" json:"name,omitempty"`
	Part             string `protobuf:"bytes,3,opt,name=part,proto3" json:"part,omitempty"`
	StringToMatch    string `protobuf:"bytes,4,opt,name=string_to_match,json=stringToMatch,proto3" json:"string_to_match,omitempty"`
	SignatureToMatch string `protobuf:"bytes,5,opt,name=signature_to_match,json=signatureToMatch,proto3" json:"signature_to_match,omitempty"`
}

func (x *MatchRule) Reset() {
	*x = MatchRule{}
	if protoimpl.UnsafeEnabled {
		mi := &file_secret_scanner_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *MatchRule) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*MatchRule) ProtoMessage() {}

func (x *MatchRule) ProtoReflect() protoreflect.Message {
	mi := &file_secret_scanner_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use MatchRule.ProtoReflect.Descriptor instead.
func (*MatchRule) Descriptor() ([]byte, []int) {
	return file_secret_scanner_proto_rawDescGZIP(), []int{4}
}

func (x *MatchRule) GetId() int32 {
	if x != nil {
		return x.Id
	}
	return 0
}

func (x *MatchRule) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (x *MatchRule) GetPart() string {
	if x != nil {
		return x.Part
	}
	return ""
}

func (x *MatchRule) GetStringToMatch() string {
	if x != nil {
		return x.StringToMatch
	}
	return ""
}

func (x *MatchRule) GetSignatureToMatch() string {
	if x != nil {
		return x.SignatureToMatch
	}
	return ""
}

type Match struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	StartingIndex         int64  `protobuf:"varint,1,opt,name=starting_index,json=startingIndex,proto3" json:"starting_index,omitempty"`
	RelativeStartingIndex int64  `protobuf:"varint,2,opt,name=relative_starting_index,json=relativeStartingIndex,proto3" json:"relative_starting_index,omitempty"`
	RelativeEndingIndex   int64  `protobuf:"varint,3,opt,name=relative_ending_index,json=relativeEndingIndex,proto3" json:"relative_ending_index,omitempty"`
	FullFilename          string `protobuf:"bytes,4,opt,name=full_filename,json=fullFilename,proto3" json:"full_filename,omitempty"`
	MatchedContent        string `protobuf:"bytes,5,opt,name=matched_content,json=matchedContent,proto3" json:"matched_content,omitempty"`
}

func (x *Match) Reset() {
	*x = Match{}
	if protoimpl.UnsafeEnabled {
		mi := &file_secret_scanner_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Match) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Match) ProtoMessage() {}

func (x *Match) ProtoReflect() protoreflect.Message {
	mi := &file_secret_scanner_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Match.ProtoReflect.Descriptor instead.
func (*Match) Descriptor() ([]byte, []int) {
	return file_secret_scanner_proto_rawDescGZIP(), []int{5}
}

func (x *Match) GetStartingIndex() int64 {
	if x != nil {
		return x.StartingIndex
	}
	return 0
}

func (x *Match) GetRelativeStartingIndex() int64 {
	if x != nil {
		return x.RelativeStartingIndex
	}
	return 0
}

func (x *Match) GetRelativeEndingIndex() int64 {
	if x != nil {
		return x.RelativeEndingIndex
	}
	return 0
}

func (x *Match) GetFullFilename() string {
	if x != nil {
		return x.FullFilename
	}
	return ""
}

func (x *Match) GetMatchedContent() string {
	if x != nil {
		return x.MatchedContent
	}
	return ""
}

type Severity struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Level string  `protobuf:"bytes,1,opt,name=level,proto3" json:"level,omitempty"`
	Score float32 `protobuf:"fixed32,2,opt,name=score,proto3" json:"score,omitempty"`
}

func (x *Severity) Reset() {
	*x = Severity{}
	if protoimpl.UnsafeEnabled {
		mi := &file_secret_scanner_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Severity) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Severity) ProtoMessage() {}

func (x *Severity) ProtoReflect() protoreflect.Message {
	mi := &file_secret_scanner_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Severity.ProtoReflect.Descriptor instead.
func (*Severity) Descriptor() ([]byte, []int) {
	return file_secret_scanner_proto_rawDescGZIP(), []int{6}
}

func (x *Severity) GetLevel() string {
	if x != nil {
		return x.Level
	}
	return ""
}

func (x *Severity) GetScore() float32 {
	if x != nil {
		return x.Score
	}
	return 0
}

type SecretInfo struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ImageLayerId string     `protobuf:"bytes,1,opt,name=image_layer_id,json=imageLayerId,proto3" json:"image_layer_id,omitempty"`
	Rule         *MatchRule `protobuf:"bytes,2,opt,name=rule,proto3" json:"rule,omitempty"`
	Match        *Match     `protobuf:"bytes,3,opt,name=match,proto3" json:"match,omitempty"`
	Severity     *Severity  `protobuf:"bytes,4,opt,name=severity,proto3" json:"severity,omitempty"`
}

func (x *SecretInfo) Reset() {
	*x = SecretInfo{}
	if protoimpl.UnsafeEnabled {
		mi := &file_secret_scanner_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SecretInfo) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SecretInfo) ProtoMessage() {}

func (x *SecretInfo) ProtoReflect() protoreflect.Message {
	mi := &file_secret_scanner_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SecretInfo.ProtoReflect.Descriptor instead.
func (*SecretInfo) Descriptor() ([]byte, []int) {
	return file_secret_scanner_proto_rawDescGZIP(), []int{7}
}

func (x *SecretInfo) GetImageLayerId() string {
	if x != nil {
		return x.ImageLayerId
	}
	return ""
}

func (x *SecretInfo) GetRule() *MatchRule {
	if x != nil {
		return x.Rule
	}
	return nil
}

func (x *SecretInfo) GetMatch() *Match {
	if x != nil {
		return x.Match
	}
	return nil
}

func (x *SecretInfo) GetSeverity() *Severity {
	if x != nil {
		return x.Severity
	}
	return nil
}

var File_secret_scanner_proto protoreflect.FileDescriptor

var file_secret_scanner_proto_rawDesc = []byte{
	0x0a, 0x14, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x5f, 0x73, 0x63, 0x61, 0x6e, 0x6e, 0x65, 0x72,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0e, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x5f, 0x73,
	0x63, 0x61, 0x6e, 0x6e, 0x65, 0x72, 0x22, 0x31, 0x0a, 0x0b, 0x44, 0x6f, 0x63, 0x6b, 0x65, 0x72,
	0x49, 0x6d, 0x61, 0x67, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x69, 0x64, 0x22, 0x39, 0x0a, 0x09, 0x43, 0x6f, 0x6e,
	0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x02, 0x69, 0x64, 0x12, 0x1c, 0x0a, 0x09, 0x6e, 0x61, 0x6d, 0x65, 0x73, 0x70,
	0x61, 0x63, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x6e, 0x61, 0x6d, 0x65, 0x73,
	0x70, 0x61, 0x63, 0x65, 0x22, 0x9c, 0x01, 0x0a, 0x0b, 0x46, 0x69, 0x6e, 0x64, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x12, 0x14, 0x0a, 0x04, 0x70, 0x61, 0x74, 0x68, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x09, 0x48, 0x00, 0x52, 0x04, 0x70, 0x61, 0x74, 0x68, 0x12, 0x33, 0x0a, 0x05, 0x69, 0x6d,
	0x61, 0x67, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1b, 0x2e, 0x73, 0x65, 0x63, 0x72,
	0x65, 0x74, 0x5f, 0x73, 0x63, 0x61, 0x6e, 0x6e, 0x65, 0x72, 0x2e, 0x44, 0x6f, 0x63, 0x6b, 0x65,
	0x72, 0x49, 0x6d, 0x61, 0x67, 0x65, 0x48, 0x00, 0x52, 0x05, 0x69, 0x6d, 0x61, 0x67, 0x65, 0x12,
	0x39, 0x0a, 0x09, 0x63, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x18, 0x03, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x19, 0x2e, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x5f, 0x73, 0x63, 0x61, 0x6e,
	0x6e, 0x65, 0x72, 0x2e, 0x43, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x48, 0x00, 0x52,
	0x09, 0x63, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x42, 0x07, 0x0a, 0x05, 0x69, 0x6e,
	0x70, 0x75, 0x74, 0x22, 0xef, 0x01, 0x0a, 0x0a, 0x46, 0x69, 0x6e, 0x64, 0x52, 0x65, 0x73, 0x75,
	0x6c, 0x74, 0x12, 0x14, 0x0a, 0x04, 0x70, 0x61, 0x74, 0x68, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09,
	0x48, 0x00, 0x52, 0x04, 0x70, 0x61, 0x74, 0x68, 0x12, 0x33, 0x0a, 0x05, 0x69, 0x6d, 0x61, 0x67,
	0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1b, 0x2e, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74,
	0x5f, 0x73, 0x63, 0x61, 0x6e, 0x6e, 0x65, 0x72, 0x2e, 0x44, 0x6f, 0x63, 0x6b, 0x65, 0x72, 0x49,
	0x6d, 0x61, 0x67, 0x65, 0x48, 0x00, 0x52, 0x05, 0x69, 0x6d, 0x61, 0x67, 0x65, 0x12, 0x39, 0x0a,
	0x09, 0x63, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x19, 0x2e, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x5f, 0x73, 0x63, 0x61, 0x6e, 0x6e, 0x65,
	0x72, 0x2e, 0x43, 0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x48, 0x00, 0x52, 0x09, 0x63,
	0x6f, 0x6e, 0x74, 0x61, 0x69, 0x6e, 0x65, 0x72, 0x12, 0x1c, 0x0a, 0x09, 0x74, 0x69, 0x6d, 0x65,
	0x73, 0x74, 0x61, 0x6d, 0x70, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x74, 0x69, 0x6d,
	0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x12, 0x34, 0x0a, 0x07, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74,
	0x73, 0x18, 0x05, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74,
	0x5f, 0x73, 0x63, 0x61, 0x6e, 0x6e, 0x65, 0x72, 0x2e, 0x53, 0x65, 0x63, 0x72, 0x65, 0x74, 0x49,
	0x6e, 0x66, 0x6f, 0x52, 0x07, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x73, 0x42, 0x07, 0x0a, 0x05,
	0x69, 0x6e, 0x70, 0x75, 0x74, 0x22, 0x99, 0x01, 0x0a, 0x09, 0x4d, 0x61, 0x74, 0x63, 0x68, 0x52,
	0x75, 0x6c, 0x65, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x05, 0x52,
	0x02, 0x69, 0x64, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x70, 0x61, 0x72, 0x74, 0x18,
	0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x70, 0x61, 0x72, 0x74, 0x12, 0x26, 0x0a, 0x0f, 0x73,
	0x74, 0x72, 0x69, 0x6e, 0x67, 0x5f, 0x74, 0x6f, 0x5f, 0x6d, 0x61, 0x74, 0x63, 0x68, 0x18, 0x04,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x0d, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x54, 0x6f, 0x4d, 0x61,
	0x74, 0x63, 0x68, 0x12, 0x2c, 0x0a, 0x12, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65,
	0x5f, 0x74, 0x6f, 0x5f, 0x6d, 0x61, 0x74, 0x63, 0x68, 0x18, 0x05, 0x20, 0x01, 0x28, 0x09, 0x52,
	0x10, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x54, 0x6f, 0x4d, 0x61, 0x74, 0x63,
	0x68, 0x22, 0xe8, 0x01, 0x0a, 0x05, 0x4d, 0x61, 0x74, 0x63, 0x68, 0x12, 0x25, 0x0a, 0x0e, 0x73,
	0x74, 0x61, 0x72, 0x74, 0x69, 0x6e, 0x67, 0x5f, 0x69, 0x6e, 0x64, 0x65, 0x78, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x03, 0x52, 0x0d, 0x73, 0x74, 0x61, 0x72, 0x74, 0x69, 0x6e, 0x67, 0x49, 0x6e, 0x64,
	0x65, 0x78, 0x12, 0x36, 0x0a, 0x17, 0x72, 0x65, 0x6c, 0x61, 0x74, 0x69, 0x76, 0x65, 0x5f, 0x73,
	0x74, 0x61, 0x72, 0x74, 0x69, 0x6e, 0x67, 0x5f, 0x69, 0x6e, 0x64, 0x65, 0x78, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x03, 0x52, 0x15, 0x72, 0x65, 0x6c, 0x61, 0x74, 0x69, 0x76, 0x65, 0x53, 0x74, 0x61,
	0x72, 0x74, 0x69, 0x6e, 0x67, 0x49, 0x6e, 0x64, 0x65, 0x78, 0x12, 0x32, 0x0a, 0x15, 0x72, 0x65,
	0x6c, 0x61, 0x74, 0x69, 0x76, 0x65, 0x5f, 0x65, 0x6e, 0x64, 0x69, 0x6e, 0x67, 0x5f, 0x69, 0x6e,
	0x64, 0x65, 0x78, 0x18, 0x03, 0x20, 0x01, 0x28, 0x03, 0x52, 0x13, 0x72, 0x65, 0x6c, 0x61, 0x74,
	0x69, 0x76, 0x65, 0x45, 0x6e, 0x64, 0x69, 0x6e, 0x67, 0x49, 0x6e, 0x64, 0x65, 0x78, 0x12, 0x23,
	0x0a, 0x0d, 0x66, 0x75, 0x6c, 0x6c, 0x5f, 0x66, 0x69, 0x6c, 0x65, 0x6e, 0x61, 0x6d, 0x65, 0x18,
	0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0c, 0x66, 0x75, 0x6c, 0x6c, 0x46, 0x69, 0x6c, 0x65, 0x6e,
	0x61, 0x6d, 0x65, 0x12, 0x27, 0x0a, 0x0f, 0x6d, 0x61, 0x74, 0x63, 0x68, 0x65, 0x64, 0x5f, 0x63,
	0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x18, 0x05, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0e, 0x6d, 0x61,
	0x74, 0x63, 0x68, 0x65, 0x64, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x22, 0x36, 0x0a, 0x08,
	0x53, 0x65, 0x76, 0x65, 0x72, 0x69, 0x74, 0x79, 0x12, 0x14, 0x0a, 0x05, 0x6c, 0x65, 0x76, 0x65,
	0x6c, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x6c, 0x65, 0x76, 0x65, 0x6c, 0x12, 0x14,
	0x0a, 0x05, 0x73, 0x63, 0x6f, 0x72, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x02, 0x52, 0x05, 0x73,
	0x63, 0x6f, 0x72, 0x65, 0x22, 0xc4, 0x01, 0x0a, 0x0a, 0x53, 0x65, 0x63, 0x72, 0x65, 0x74, 0x49,
	0x6e, 0x66, 0x6f, 0x12, 0x24, 0x0a, 0x0e, 0x69, 0x6d, 0x61, 0x67, 0x65, 0x5f, 0x6c, 0x61, 0x79,
	0x65, 0x72, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0c, 0x69, 0x6d, 0x61,
	0x67, 0x65, 0x4c, 0x61, 0x79, 0x65, 0x72, 0x49, 0x64, 0x12, 0x2d, 0x0a, 0x04, 0x72, 0x75, 0x6c,
	0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x19, 0x2e, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74,
	0x5f, 0x73, 0x63, 0x61, 0x6e, 0x6e, 0x65, 0x72, 0x2e, 0x4d, 0x61, 0x74, 0x63, 0x68, 0x52, 0x75,
	0x6c, 0x65, 0x52, 0x04, 0x72, 0x75, 0x6c, 0x65, 0x12, 0x2b, 0x0a, 0x05, 0x6d, 0x61, 0x74, 0x63,
	0x68, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x15, 0x2e, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74,
	0x5f, 0x73, 0x63, 0x61, 0x6e, 0x6e, 0x65, 0x72, 0x2e, 0x4d, 0x61, 0x74, 0x63, 0x68, 0x52, 0x05,
	0x6d, 0x61, 0x74, 0x63, 0x68, 0x12, 0x34, 0x0a, 0x08, 0x73, 0x65, 0x76, 0x65, 0x72, 0x69, 0x74,
	0x79, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x18, 0x2e, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74,
	0x5f, 0x73, 0x63, 0x61, 0x6e, 0x6e, 0x65, 0x72, 0x2e, 0x53, 0x65, 0x76, 0x65, 0x72, 0x69, 0x74,
	0x79, 0x52, 0x08, 0x73, 0x65, 0x76, 0x65, 0x72, 0x69, 0x74, 0x79, 0x32, 0x5a, 0x0a, 0x0d, 0x53,
	0x65, 0x63, 0x72, 0x65, 0x74, 0x53, 0x63, 0x61, 0x6e, 0x6e, 0x65, 0x72, 0x12, 0x49, 0x0a, 0x0e,
	0x46, 0x69, 0x6e, 0x64, 0x53, 0x65, 0x63, 0x72, 0x65, 0x74, 0x49, 0x6e, 0x66, 0x6f, 0x12, 0x1b,
	0x2e, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x5f, 0x73, 0x63, 0x61, 0x6e, 0x6e, 0x65, 0x72, 0x2e,
	0x46, 0x69, 0x6e, 0x64, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x1a, 0x2e, 0x73, 0x65,
	0x63, 0x72, 0x65, 0x74, 0x5f, 0x73, 0x63, 0x61, 0x6e, 0x6e, 0x65, 0x72, 0x2e, 0x46, 0x69, 0x6e,
	0x64, 0x52, 0x65, 0x73, 0x75, 0x6c, 0x74, 0x42, 0x2e, 0x5a, 0x2c, 0x67, 0x69, 0x74, 0x68, 0x75,
	0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x64, 0x65, 0x65, 0x70, 0x66, 0x65, 0x6e, 0x63, 0x65, 0x2f,
	0x61, 0x67, 0x65, 0x6e, 0x74, 0x2d, 0x70, 0x6c, 0x75, 0x67, 0x69, 0x6e, 0x2d, 0x67, 0x72, 0x70,
	0x63, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_secret_scanner_proto_rawDescOnce sync.Once
	file_secret_scanner_proto_rawDescData = file_secret_scanner_proto_rawDesc
)

func file_secret_scanner_proto_rawDescGZIP() []byte {
	file_secret_scanner_proto_rawDescOnce.Do(func() {
		file_secret_scanner_proto_rawDescData = protoimpl.X.CompressGZIP(file_secret_scanner_proto_rawDescData)
	})
	return file_secret_scanner_proto_rawDescData
}

var file_secret_scanner_proto_msgTypes = make([]protoimpl.MessageInfo, 8)
var file_secret_scanner_proto_goTypes = []interface{}{
	(*DockerImage)(nil), // 0: secret_scanner.DockerImage
	(*Container)(nil),   // 1: secret_scanner.Container
	(*FindRequest)(nil), // 2: secret_scanner.FindRequest
	(*FindResult)(nil),  // 3: secret_scanner.FindResult
	(*MatchRule)(nil),   // 4: secret_scanner.MatchRule
	(*Match)(nil),       // 5: secret_scanner.Match
	(*Severity)(nil),    // 6: secret_scanner.Severity
	(*SecretInfo)(nil),  // 7: secret_scanner.SecretInfo
}
var file_secret_scanner_proto_depIdxs = []int32{
	0, // 0: secret_scanner.FindRequest.image:type_name -> secret_scanner.DockerImage
	1, // 1: secret_scanner.FindRequest.container:type_name -> secret_scanner.Container
	0, // 2: secret_scanner.FindResult.image:type_name -> secret_scanner.DockerImage
	1, // 3: secret_scanner.FindResult.container:type_name -> secret_scanner.Container
	7, // 4: secret_scanner.FindResult.secrets:type_name -> secret_scanner.SecretInfo
	4, // 5: secret_scanner.SecretInfo.rule:type_name -> secret_scanner.MatchRule
	5, // 6: secret_scanner.SecretInfo.match:type_name -> secret_scanner.Match
	6, // 7: secret_scanner.SecretInfo.severity:type_name -> secret_scanner.Severity
	2, // 8: secret_scanner.SecretScanner.FindSecretInfo:input_type -> secret_scanner.FindRequest
	3, // 9: secret_scanner.SecretScanner.FindSecretInfo:output_type -> secret_scanner.FindResult
	9, // [9:10] is the sub-list for method output_type
	8, // [8:9] is the sub-list for method input_type
	8, // [8:8] is the sub-list for extension type_name
	8, // [8:8] is the sub-list for extension extendee
	0, // [0:8] is the sub-list for field type_name
}

func init() { file_secret_scanner_proto_init() }
func file_secret_scanner_proto_init() {
	if File_secret_scanner_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_secret_scanner_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*DockerImage); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_secret_scanner_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Container); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_secret_scanner_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*FindRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_secret_scanner_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*FindResult); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_secret_scanner_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*MatchRule); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_secret_scanner_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Match); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_secret_scanner_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Severity); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_secret_scanner_proto_msgTypes[7].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SecretInfo); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	file_secret_scanner_proto_msgTypes[2].OneofWrappers = []interface{}{
		(*FindRequest_Path)(nil),
		(*FindRequest_Image)(nil),
		(*FindRequest_Container)(nil),
	}
	file_secret_scanner_proto_msgTypes[3].OneofWrappers = []interface{}{
		(*FindResult_Path)(nil),
		(*FindResult_Image)(nil),
		(*FindResult_Container)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_secret_scanner_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   8,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_secret_scanner_proto_goTypes,
		DependencyIndexes: file_secret_scanner_proto_depIdxs,
		MessageInfos:      file_secret_scanner_proto_msgTypes,
	}.Build()
	File_secret_scanner_proto = out.File
	file_secret_scanner_proto_rawDesc = nil
	file_secret_scanner_proto_goTypes = nil
	file_secret_scanner_proto_depIdxs = nil
}
