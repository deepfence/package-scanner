// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.1
// 	protoc        v3.12.4
// source: kernel_tracer.proto

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

type Feature int32

const (
	Feature_eBPF Feature = 0
)

// Enum value maps for Feature.
var (
	Feature_name = map[int32]string{
		0: "eBPF",
	}
	Feature_value = map[string]int32{
		"eBPF": 0,
	}
)

func (x Feature) Enum() *Feature {
	p := new(Feature)
	*p = x
	return p
}

func (x Feature) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (Feature) Descriptor() protoreflect.EnumDescriptor {
	return file_kernel_tracer_proto_enumTypes[0].Descriptor()
}

func (Feature) Type() protoreflect.EnumType {
	return &file_kernel_tracer_proto_enumTypes[0]
}

func (x Feature) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use Feature.Descriptor instead.
func (Feature) EnumDescriptor() ([]byte, []int) {
	return file_kernel_tracer_proto_rawDescGZIP(), []int{0}
}

type Metrics struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	EventFailureCount uint64 `protobuf:"varint,1,opt,name=event_failure_count,json=eventFailureCount,proto3" json:"event_failure_count,omitempty"`
	EventSuccessCount uint64 `protobuf:"varint,2,opt,name=event_success_count,json=eventSuccessCount,proto3" json:"event_success_count,omitempty"`
	EbfBufferCapacity uint64 `protobuf:"varint,3,opt,name=ebf_buffer_capacity,json=ebfBufferCapacity,proto3" json:"ebf_buffer_capacity,omitempty"`
	EventSkipCount    uint64 `protobuf:"varint,4,opt,name=event_skip_count,json=eventSkipCount,proto3" json:"event_skip_count,omitempty"`
}

func (x *Metrics) Reset() {
	*x = Metrics{}
	if protoimpl.UnsafeEnabled {
		mi := &file_kernel_tracer_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Metrics) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Metrics) ProtoMessage() {}

func (x *Metrics) ProtoReflect() protoreflect.Message {
	mi := &file_kernel_tracer_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Metrics.ProtoReflect.Descriptor instead.
func (*Metrics) Descriptor() ([]byte, []int) {
	return file_kernel_tracer_proto_rawDescGZIP(), []int{0}
}

func (x *Metrics) GetEventFailureCount() uint64 {
	if x != nil {
		return x.EventFailureCount
	}
	return 0
}

func (x *Metrics) GetEventSuccessCount() uint64 {
	if x != nil {
		return x.EventSuccessCount
	}
	return 0
}

func (x *Metrics) GetEbfBufferCapacity() uint64 {
	if x != nil {
		return x.EbfBufferCapacity
	}
	return 0
}

func (x *Metrics) GetEventSkipCount() uint64 {
	if x != nil {
		return x.EventSkipCount
	}
	return 0
}

type KernelVersion struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Major string `protobuf:"bytes,1,opt,name=major,proto3" json:"major,omitempty"`
	Minor string `protobuf:"bytes,2,opt,name=minor,proto3" json:"minor,omitempty"`
	Patch string `protobuf:"bytes,3,opt,name=patch,proto3" json:"patch,omitempty"`
}

func (x *KernelVersion) Reset() {
	*x = KernelVersion{}
	if protoimpl.UnsafeEnabled {
		mi := &file_kernel_tracer_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *KernelVersion) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*KernelVersion) ProtoMessage() {}

func (x *KernelVersion) ProtoReflect() protoreflect.Message {
	mi := &file_kernel_tracer_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use KernelVersion.ProtoReflect.Descriptor instead.
func (*KernelVersion) Descriptor() ([]byte, []int) {
	return file_kernel_tracer_proto_rawDescGZIP(), []int{1}
}

func (x *KernelVersion) GetMajor() string {
	if x != nil {
		return x.Major
	}
	return ""
}

func (x *KernelVersion) GetMinor() string {
	if x != nil {
		return x.Minor
	}
	return ""
}

func (x *KernelVersion) GetPatch() string {
	if x != nil {
		return x.Patch
	}
	return ""
}

type KernelInfo struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Version *KernelVersion `protobuf:"bytes,1,opt,name=version,proto3" json:"version,omitempty"`
}

func (x *KernelInfo) Reset() {
	*x = KernelInfo{}
	if protoimpl.UnsafeEnabled {
		mi := &file_kernel_tracer_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *KernelInfo) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*KernelInfo) ProtoMessage() {}

func (x *KernelInfo) ProtoReflect() protoreflect.Message {
	mi := &file_kernel_tracer_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use KernelInfo.ProtoReflect.Descriptor instead.
func (*KernelInfo) Descriptor() ([]byte, []int) {
	return file_kernel_tracer_proto_rawDescGZIP(), []int{2}
}

func (x *KernelInfo) GetVersion() *KernelVersion {
	if x != nil {
		return x.Version
	}
	return nil
}

type KernelFeatures struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Features []Feature `protobuf:"varint,1,rep,packed,name=features,proto3,enum=kernel_tracer.Feature" json:"features,omitempty"`
}

func (x *KernelFeatures) Reset() {
	*x = KernelFeatures{}
	if protoimpl.UnsafeEnabled {
		mi := &file_kernel_tracer_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *KernelFeatures) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*KernelFeatures) ProtoMessage() {}

func (x *KernelFeatures) ProtoReflect() protoreflect.Message {
	mi := &file_kernel_tracer_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use KernelFeatures.ProtoReflect.Descriptor instead.
func (*KernelFeatures) Descriptor() ([]byte, []int) {
	return file_kernel_tracer_proto_rawDescGZIP(), []int{3}
}

func (x *KernelFeatures) GetFeatures() []Feature {
	if x != nil {
		return x.Features
	}
	return nil
}

var File_kernel_tracer_proto protoreflect.FileDescriptor

var file_kernel_tracer_proto_rawDesc = []byte{
	0x0a, 0x13, 0x6b, 0x65, 0x72, 0x6e, 0x65, 0x6c, 0x5f, 0x74, 0x72, 0x61, 0x63, 0x65, 0x72, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0d, 0x6b, 0x65, 0x72, 0x6e, 0x65, 0x6c, 0x5f, 0x74, 0x72,
	0x61, 0x63, 0x65, 0x72, 0x1a, 0x0c, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x22, 0xc3, 0x01, 0x0a, 0x07, 0x4d, 0x65, 0x74, 0x72, 0x69, 0x63, 0x73, 0x12, 0x2e,
	0x0a, 0x13, 0x65, 0x76, 0x65, 0x6e, 0x74, 0x5f, 0x66, 0x61, 0x69, 0x6c, 0x75, 0x72, 0x65, 0x5f,
	0x63, 0x6f, 0x75, 0x6e, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x04, 0x52, 0x11, 0x65, 0x76, 0x65,
	0x6e, 0x74, 0x46, 0x61, 0x69, 0x6c, 0x75, 0x72, 0x65, 0x43, 0x6f, 0x75, 0x6e, 0x74, 0x12, 0x2e,
	0x0a, 0x13, 0x65, 0x76, 0x65, 0x6e, 0x74, 0x5f, 0x73, 0x75, 0x63, 0x63, 0x65, 0x73, 0x73, 0x5f,
	0x63, 0x6f, 0x75, 0x6e, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x04, 0x52, 0x11, 0x65, 0x76, 0x65,
	0x6e, 0x74, 0x53, 0x75, 0x63, 0x63, 0x65, 0x73, 0x73, 0x43, 0x6f, 0x75, 0x6e, 0x74, 0x12, 0x2e,
	0x0a, 0x13, 0x65, 0x62, 0x66, 0x5f, 0x62, 0x75, 0x66, 0x66, 0x65, 0x72, 0x5f, 0x63, 0x61, 0x70,
	0x61, 0x63, 0x69, 0x74, 0x79, 0x18, 0x03, 0x20, 0x01, 0x28, 0x04, 0x52, 0x11, 0x65, 0x62, 0x66,
	0x42, 0x75, 0x66, 0x66, 0x65, 0x72, 0x43, 0x61, 0x70, 0x61, 0x63, 0x69, 0x74, 0x79, 0x12, 0x28,
	0x0a, 0x10, 0x65, 0x76, 0x65, 0x6e, 0x74, 0x5f, 0x73, 0x6b, 0x69, 0x70, 0x5f, 0x63, 0x6f, 0x75,
	0x6e, 0x74, 0x18, 0x04, 0x20, 0x01, 0x28, 0x04, 0x52, 0x0e, 0x65, 0x76, 0x65, 0x6e, 0x74, 0x53,
	0x6b, 0x69, 0x70, 0x43, 0x6f, 0x75, 0x6e, 0x74, 0x22, 0x51, 0x0a, 0x0d, 0x4b, 0x65, 0x72, 0x6e,
	0x65, 0x6c, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x14, 0x0a, 0x05, 0x6d, 0x61, 0x6a,
	0x6f, 0x72, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x6d, 0x61, 0x6a, 0x6f, 0x72, 0x12,
	0x14, 0x0a, 0x05, 0x6d, 0x69, 0x6e, 0x6f, 0x72, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05,
	0x6d, 0x69, 0x6e, 0x6f, 0x72, 0x12, 0x14, 0x0a, 0x05, 0x70, 0x61, 0x74, 0x63, 0x68, 0x18, 0x03,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x70, 0x61, 0x74, 0x63, 0x68, 0x22, 0x44, 0x0a, 0x0a, 0x4b,
	0x65, 0x72, 0x6e, 0x65, 0x6c, 0x49, 0x6e, 0x66, 0x6f, 0x12, 0x36, 0x0a, 0x07, 0x76, 0x65, 0x72,
	0x73, 0x69, 0x6f, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1c, 0x2e, 0x6b, 0x65, 0x72,
	0x6e, 0x65, 0x6c, 0x5f, 0x74, 0x72, 0x61, 0x63, 0x65, 0x72, 0x2e, 0x4b, 0x65, 0x72, 0x6e, 0x65,
	0x6c, 0x56, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x52, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f,
	0x6e, 0x22, 0x44, 0x0a, 0x0e, 0x4b, 0x65, 0x72, 0x6e, 0x65, 0x6c, 0x46, 0x65, 0x61, 0x74, 0x75,
	0x72, 0x65, 0x73, 0x12, 0x32, 0x0a, 0x08, 0x66, 0x65, 0x61, 0x74, 0x75, 0x72, 0x65, 0x73, 0x18,
	0x01, 0x20, 0x03, 0x28, 0x0e, 0x32, 0x16, 0x2e, 0x6b, 0x65, 0x72, 0x6e, 0x65, 0x6c, 0x5f, 0x74,
	0x72, 0x61, 0x63, 0x65, 0x72, 0x2e, 0x46, 0x65, 0x61, 0x74, 0x75, 0x72, 0x65, 0x52, 0x08, 0x66,
	0x65, 0x61, 0x74, 0x75, 0x72, 0x65, 0x73, 0x2a, 0x13, 0x0a, 0x07, 0x46, 0x65, 0x61, 0x74, 0x75,
	0x72, 0x65, 0x12, 0x08, 0x0a, 0x04, 0x65, 0x42, 0x50, 0x46, 0x10, 0x00, 0x32, 0xbe, 0x01, 0x0a,
	0x0c, 0x4b, 0x65, 0x72, 0x6e, 0x65, 0x6c, 0x54, 0x72, 0x61, 0x63, 0x65, 0x72, 0x12, 0x3c, 0x0a,
	0x10, 0x47, 0x65, 0x74, 0x4b, 0x65, 0x72, 0x6e, 0x65, 0x6c, 0x53, 0x75, 0x70, 0x70, 0x6f, 0x72,
	0x74, 0x12, 0x0d, 0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79,
	0x1a, 0x19, 0x2e, 0x6b, 0x65, 0x72, 0x6e, 0x65, 0x6c, 0x5f, 0x74, 0x72, 0x61, 0x63, 0x65, 0x72,
	0x2e, 0x4b, 0x65, 0x72, 0x6e, 0x65, 0x6c, 0x49, 0x6e, 0x66, 0x6f, 0x12, 0x33, 0x0a, 0x0a, 0x47,
	0x65, 0x74, 0x4d, 0x65, 0x74, 0x72, 0x69, 0x63, 0x73, 0x12, 0x0d, 0x2e, 0x63, 0x6f, 0x6d, 0x6d,
	0x6f, 0x6e, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x1a, 0x16, 0x2e, 0x6b, 0x65, 0x72, 0x6e, 0x65,
	0x6c, 0x5f, 0x74, 0x72, 0x61, 0x63, 0x65, 0x72, 0x2e, 0x4d, 0x65, 0x74, 0x72, 0x69, 0x63, 0x73,
	0x12, 0x3b, 0x0a, 0x0b, 0x47, 0x65, 0x74, 0x46, 0x65, 0x61, 0x74, 0x75, 0x72, 0x65, 0x73, 0x12,
	0x0d, 0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x1a, 0x1d,
	0x2e, 0x6b, 0x65, 0x72, 0x6e, 0x65, 0x6c, 0x5f, 0x74, 0x72, 0x61, 0x63, 0x65, 0x72, 0x2e, 0x4b,
	0x65, 0x72, 0x6e, 0x65, 0x6c, 0x46, 0x65, 0x61, 0x74, 0x75, 0x72, 0x65, 0x73, 0x42, 0x2e, 0x5a,
	0x2c, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x64, 0x65, 0x65, 0x70,
	0x66, 0x65, 0x6e, 0x63, 0x65, 0x2f, 0x61, 0x67, 0x65, 0x6e, 0x74, 0x2d, 0x70, 0x6c, 0x75, 0x67,
	0x69, 0x6e, 0x2d, 0x67, 0x72, 0x70, 0x63, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x06, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_kernel_tracer_proto_rawDescOnce sync.Once
	file_kernel_tracer_proto_rawDescData = file_kernel_tracer_proto_rawDesc
)

func file_kernel_tracer_proto_rawDescGZIP() []byte {
	file_kernel_tracer_proto_rawDescOnce.Do(func() {
		file_kernel_tracer_proto_rawDescData = protoimpl.X.CompressGZIP(file_kernel_tracer_proto_rawDescData)
	})
	return file_kernel_tracer_proto_rawDescData
}

var file_kernel_tracer_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_kernel_tracer_proto_msgTypes = make([]protoimpl.MessageInfo, 4)
var file_kernel_tracer_proto_goTypes = []interface{}{
	(Feature)(0),           // 0: kernel_tracer.Feature
	(*Metrics)(nil),        // 1: kernel_tracer.Metrics
	(*KernelVersion)(nil),  // 2: kernel_tracer.KernelVersion
	(*KernelInfo)(nil),     // 3: kernel_tracer.KernelInfo
	(*KernelFeatures)(nil), // 4: kernel_tracer.KernelFeatures
	(*Empty)(nil),          // 5: common.Empty
}
var file_kernel_tracer_proto_depIdxs = []int32{
	2, // 0: kernel_tracer.KernelInfo.version:type_name -> kernel_tracer.KernelVersion
	0, // 1: kernel_tracer.KernelFeatures.features:type_name -> kernel_tracer.Feature
	5, // 2: kernel_tracer.KernelTracer.GetKernelSupport:input_type -> common.Empty
	5, // 3: kernel_tracer.KernelTracer.GetMetrics:input_type -> common.Empty
	5, // 4: kernel_tracer.KernelTracer.GetFeatures:input_type -> common.Empty
	3, // 5: kernel_tracer.KernelTracer.GetKernelSupport:output_type -> kernel_tracer.KernelInfo
	1, // 6: kernel_tracer.KernelTracer.GetMetrics:output_type -> kernel_tracer.Metrics
	4, // 7: kernel_tracer.KernelTracer.GetFeatures:output_type -> kernel_tracer.KernelFeatures
	5, // [5:8] is the sub-list for method output_type
	2, // [2:5] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_kernel_tracer_proto_init() }
func file_kernel_tracer_proto_init() {
	if File_kernel_tracer_proto != nil {
		return
	}
	file_common_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_kernel_tracer_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Metrics); i {
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
		file_kernel_tracer_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*KernelVersion); i {
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
		file_kernel_tracer_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*KernelInfo); i {
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
		file_kernel_tracer_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*KernelFeatures); i {
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
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_kernel_tracer_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   4,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_kernel_tracer_proto_goTypes,
		DependencyIndexes: file_kernel_tracer_proto_depIdxs,
		EnumInfos:         file_kernel_tracer_proto_enumTypes,
		MessageInfos:      file_kernel_tracer_proto_msgTypes,
	}.Build()
	File_kernel_tracer_proto = out.File
	file_kernel_tracer_proto_rawDesc = nil
	file_kernel_tracer_proto_goTypes = nil
	file_kernel_tracer_proto_depIdxs = nil
}
