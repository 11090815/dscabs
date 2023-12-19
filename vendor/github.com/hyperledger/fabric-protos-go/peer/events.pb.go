// Code generated by protoc-gen-go. DO NOT EDIT.
// source: peer/events.proto

package peer

import (
	context "context"
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	common "github.com/hyperledger/fabric-protos-go/common"
	rwset "github.com/hyperledger/fabric-protos-go/ledger/rwset"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

// FilteredBlock is a minimal set of information about a block
type FilteredBlock struct {
	ChannelId            string                 `protobuf:"bytes,1,opt,name=channel_id,json=channelId,proto3" json:"channel_id,omitempty"`
	Number               uint64                 `protobuf:"varint,2,opt,name=number,proto3" json:"number,omitempty"`
	FilteredTransactions []*FilteredTransaction `protobuf:"bytes,4,rep,name=filtered_transactions,json=filteredTransactions,proto3" json:"filtered_transactions,omitempty"`
	XXX_NoUnkeyedLiteral struct{}               `json:"-"`
	XXX_unrecognized     []byte                 `json:"-"`
	XXX_sizecache        int32                  `json:"-"`
}

func (m *FilteredBlock) Reset()         { *m = FilteredBlock{} }
func (m *FilteredBlock) String() string { return proto.CompactTextString(m) }
func (*FilteredBlock) ProtoMessage()    {}
func (*FilteredBlock) Descriptor() ([]byte, []int) {
	return fileDescriptor_5eedcc5fab2714e6, []int{0}
}

func (m *FilteredBlock) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_FilteredBlock.Unmarshal(m, b)
}
func (m *FilteredBlock) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_FilteredBlock.Marshal(b, m, deterministic)
}
func (m *FilteredBlock) XXX_Merge(src proto.Message) {
	xxx_messageInfo_FilteredBlock.Merge(m, src)
}
func (m *FilteredBlock) XXX_Size() int {
	return xxx_messageInfo_FilteredBlock.Size(m)
}
func (m *FilteredBlock) XXX_DiscardUnknown() {
	xxx_messageInfo_FilteredBlock.DiscardUnknown(m)
}

var xxx_messageInfo_FilteredBlock proto.InternalMessageInfo

func (m *FilteredBlock) GetChannelId() string {
	if m != nil {
		return m.ChannelId
	}
	return ""
}

func (m *FilteredBlock) GetNumber() uint64 {
	if m != nil {
		return m.Number
	}
	return 0
}

func (m *FilteredBlock) GetFilteredTransactions() []*FilteredTransaction {
	if m != nil {
		return m.FilteredTransactions
	}
	return nil
}

// FilteredTransaction is a minimal set of information about a transaction
// within a block
type FilteredTransaction struct {
	Txid             string            `protobuf:"bytes,1,opt,name=txid,proto3" json:"txid,omitempty"`
	Type             common.HeaderType `protobuf:"varint,2,opt,name=type,proto3,enum=common.HeaderType" json:"type,omitempty"`
	TxValidationCode TxValidationCode  `protobuf:"varint,3,opt,name=tx_validation_code,json=txValidationCode,proto3,enum=protos.TxValidationCode" json:"tx_validation_code,omitempty"`
	// Types that are valid to be assigned to Data:
	//	*FilteredTransaction_TransactionActions
	Data                 isFilteredTransaction_Data `protobuf_oneof:"Data"`
	XXX_NoUnkeyedLiteral struct{}                   `json:"-"`
	XXX_unrecognized     []byte                     `json:"-"`
	XXX_sizecache        int32                      `json:"-"`
}

func (m *FilteredTransaction) Reset()         { *m = FilteredTransaction{} }
func (m *FilteredTransaction) String() string { return proto.CompactTextString(m) }
func (*FilteredTransaction) ProtoMessage()    {}
func (*FilteredTransaction) Descriptor() ([]byte, []int) {
	return fileDescriptor_5eedcc5fab2714e6, []int{1}
}

func (m *FilteredTransaction) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_FilteredTransaction.Unmarshal(m, b)
}
func (m *FilteredTransaction) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_FilteredTransaction.Marshal(b, m, deterministic)
}
func (m *FilteredTransaction) XXX_Merge(src proto.Message) {
	xxx_messageInfo_FilteredTransaction.Merge(m, src)
}
func (m *FilteredTransaction) XXX_Size() int {
	return xxx_messageInfo_FilteredTransaction.Size(m)
}
func (m *FilteredTransaction) XXX_DiscardUnknown() {
	xxx_messageInfo_FilteredTransaction.DiscardUnknown(m)
}

var xxx_messageInfo_FilteredTransaction proto.InternalMessageInfo

func (m *FilteredTransaction) GetTxid() string {
	if m != nil {
		return m.Txid
	}
	return ""
}

func (m *FilteredTransaction) GetType() common.HeaderType {
	if m != nil {
		return m.Type
	}
	return common.HeaderType_MESSAGE
}

func (m *FilteredTransaction) GetTxValidationCode() TxValidationCode {
	if m != nil {
		return m.TxValidationCode
	}
	return TxValidationCode_VALID
}

type isFilteredTransaction_Data interface {
	isFilteredTransaction_Data()
}

type FilteredTransaction_TransactionActions struct {
	TransactionActions *FilteredTransactionActions `protobuf:"bytes,4,opt,name=transaction_actions,json=transactionActions,proto3,oneof"`
}

func (*FilteredTransaction_TransactionActions) isFilteredTransaction_Data() {}

func (m *FilteredTransaction) GetData() isFilteredTransaction_Data {
	if m != nil {
		return m.Data
	}
	return nil
}

func (m *FilteredTransaction) GetTransactionActions() *FilteredTransactionActions {
	if x, ok := m.GetData().(*FilteredTransaction_TransactionActions); ok {
		return x.TransactionActions
	}
	return nil
}

// XXX_OneofWrappers is for the internal use of the proto package.
func (*FilteredTransaction) XXX_OneofWrappers() []interface{} {
	return []interface{}{
		(*FilteredTransaction_TransactionActions)(nil),
	}
}

// FilteredTransactionActions is a wrapper for array of TransactionAction
// message from regular block
type FilteredTransactionActions struct {
	ChaincodeActions     []*FilteredChaincodeAction `protobuf:"bytes,1,rep,name=chaincode_actions,json=chaincodeActions,proto3" json:"chaincode_actions,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                   `json:"-"`
	XXX_unrecognized     []byte                     `json:"-"`
	XXX_sizecache        int32                      `json:"-"`
}

func (m *FilteredTransactionActions) Reset()         { *m = FilteredTransactionActions{} }
func (m *FilteredTransactionActions) String() string { return proto.CompactTextString(m) }
func (*FilteredTransactionActions) ProtoMessage()    {}
func (*FilteredTransactionActions) Descriptor() ([]byte, []int) {
	return fileDescriptor_5eedcc5fab2714e6, []int{2}
}

func (m *FilteredTransactionActions) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_FilteredTransactionActions.Unmarshal(m, b)
}
func (m *FilteredTransactionActions) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_FilteredTransactionActions.Marshal(b, m, deterministic)
}
func (m *FilteredTransactionActions) XXX_Merge(src proto.Message) {
	xxx_messageInfo_FilteredTransactionActions.Merge(m, src)
}
func (m *FilteredTransactionActions) XXX_Size() int {
	return xxx_messageInfo_FilteredTransactionActions.Size(m)
}
func (m *FilteredTransactionActions) XXX_DiscardUnknown() {
	xxx_messageInfo_FilteredTransactionActions.DiscardUnknown(m)
}

var xxx_messageInfo_FilteredTransactionActions proto.InternalMessageInfo

func (m *FilteredTransactionActions) GetChaincodeActions() []*FilteredChaincodeAction {
	if m != nil {
		return m.ChaincodeActions
	}
	return nil
}

// FilteredChaincodeAction is a minimal set of information about an action
// within a transaction
type FilteredChaincodeAction struct {
	ChaincodeEvent       *ChaincodeEvent `protobuf:"bytes,1,opt,name=chaincode_event,json=chaincodeEvent,proto3" json:"chaincode_event,omitempty"`
	XXX_NoUnkeyedLiteral struct{}        `json:"-"`
	XXX_unrecognized     []byte          `json:"-"`
	XXX_sizecache        int32           `json:"-"`
}

func (m *FilteredChaincodeAction) Reset()         { *m = FilteredChaincodeAction{} }
func (m *FilteredChaincodeAction) String() string { return proto.CompactTextString(m) }
func (*FilteredChaincodeAction) ProtoMessage()    {}
func (*FilteredChaincodeAction) Descriptor() ([]byte, []int) {
	return fileDescriptor_5eedcc5fab2714e6, []int{3}
}

func (m *FilteredChaincodeAction) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_FilteredChaincodeAction.Unmarshal(m, b)
}
func (m *FilteredChaincodeAction) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_FilteredChaincodeAction.Marshal(b, m, deterministic)
}
func (m *FilteredChaincodeAction) XXX_Merge(src proto.Message) {
	xxx_messageInfo_FilteredChaincodeAction.Merge(m, src)
}
func (m *FilteredChaincodeAction) XXX_Size() int {
	return xxx_messageInfo_FilteredChaincodeAction.Size(m)
}
func (m *FilteredChaincodeAction) XXX_DiscardUnknown() {
	xxx_messageInfo_FilteredChaincodeAction.DiscardUnknown(m)
}

var xxx_messageInfo_FilteredChaincodeAction proto.InternalMessageInfo

func (m *FilteredChaincodeAction) GetChaincodeEvent() *ChaincodeEvent {
	if m != nil {
		return m.ChaincodeEvent
	}
	return nil
}

// BlockAndPrivateData contains Block and a map from tx_seq_in_block to rwset.TxPvtReadWriteSet
type BlockAndPrivateData struct {
	Block *common.Block `protobuf:"bytes,1,opt,name=block,proto3" json:"block,omitempty"`
	// map from tx_seq_in_block to rwset.TxPvtReadWriteSet
	PrivateDataMap       map[uint64]*rwset.TxPvtReadWriteSet `protobuf:"bytes,2,rep,name=private_data_map,json=privateDataMap,proto3" json:"private_data_map,omitempty" protobuf_key:"varint,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	XXX_NoUnkeyedLiteral struct{}                            `json:"-"`
	XXX_unrecognized     []byte                              `json:"-"`
	XXX_sizecache        int32                               `json:"-"`
}

func (m *BlockAndPrivateData) Reset()         { *m = BlockAndPrivateData{} }
func (m *BlockAndPrivateData) String() string { return proto.CompactTextString(m) }
func (*BlockAndPrivateData) ProtoMessage()    {}
func (*BlockAndPrivateData) Descriptor() ([]byte, []int) {
	return fileDescriptor_5eedcc5fab2714e6, []int{4}
}

func (m *BlockAndPrivateData) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_BlockAndPrivateData.Unmarshal(m, b)
}
func (m *BlockAndPrivateData) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_BlockAndPrivateData.Marshal(b, m, deterministic)
}
func (m *BlockAndPrivateData) XXX_Merge(src proto.Message) {
	xxx_messageInfo_BlockAndPrivateData.Merge(m, src)
}
func (m *BlockAndPrivateData) XXX_Size() int {
	return xxx_messageInfo_BlockAndPrivateData.Size(m)
}
func (m *BlockAndPrivateData) XXX_DiscardUnknown() {
	xxx_messageInfo_BlockAndPrivateData.DiscardUnknown(m)
}

var xxx_messageInfo_BlockAndPrivateData proto.InternalMessageInfo

func (m *BlockAndPrivateData) GetBlock() *common.Block {
	if m != nil {
		return m.Block
	}
	return nil
}

func (m *BlockAndPrivateData) GetPrivateDataMap() map[uint64]*rwset.TxPvtReadWriteSet {
	if m != nil {
		return m.PrivateDataMap
	}
	return nil
}

// DeliverResponse
type DeliverResponse struct {
	// Types that are valid to be assigned to Type:
	//	*DeliverResponse_Status
	//	*DeliverResponse_Block
	//	*DeliverResponse_FilteredBlock
	//	*DeliverResponse_BlockAndPrivateData
	Type                 isDeliverResponse_Type `protobuf_oneof:"Type"`
	XXX_NoUnkeyedLiteral struct{}               `json:"-"`
	XXX_unrecognized     []byte                 `json:"-"`
	XXX_sizecache        int32                  `json:"-"`
}

func (m *DeliverResponse) Reset()         { *m = DeliverResponse{} }
func (m *DeliverResponse) String() string { return proto.CompactTextString(m) }
func (*DeliverResponse) ProtoMessage()    {}
func (*DeliverResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_5eedcc5fab2714e6, []int{5}
}

func (m *DeliverResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_DeliverResponse.Unmarshal(m, b)
}
func (m *DeliverResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_DeliverResponse.Marshal(b, m, deterministic)
}
func (m *DeliverResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_DeliverResponse.Merge(m, src)
}
func (m *DeliverResponse) XXX_Size() int {
	return xxx_messageInfo_DeliverResponse.Size(m)
}
func (m *DeliverResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_DeliverResponse.DiscardUnknown(m)
}

var xxx_messageInfo_DeliverResponse proto.InternalMessageInfo

type isDeliverResponse_Type interface {
	isDeliverResponse_Type()
}

type DeliverResponse_Status struct {
	Status common.Status `protobuf:"varint,1,opt,name=status,proto3,enum=common.Status,oneof"`
}

type DeliverResponse_Block struct {
	Block *common.Block `protobuf:"bytes,2,opt,name=block,proto3,oneof"`
}

type DeliverResponse_FilteredBlock struct {
	FilteredBlock *FilteredBlock `protobuf:"bytes,3,opt,name=filtered_block,json=filteredBlock,proto3,oneof"`
}

type DeliverResponse_BlockAndPrivateData struct {
	BlockAndPrivateData *BlockAndPrivateData `protobuf:"bytes,4,opt,name=block_and_private_data,json=blockAndPrivateData,proto3,oneof"`
}

func (*DeliverResponse_Status) isDeliverResponse_Type() {}

func (*DeliverResponse_Block) isDeliverResponse_Type() {}

func (*DeliverResponse_FilteredBlock) isDeliverResponse_Type() {}

func (*DeliverResponse_BlockAndPrivateData) isDeliverResponse_Type() {}

func (m *DeliverResponse) GetType() isDeliverResponse_Type {
	if m != nil {
		return m.Type
	}
	return nil
}

func (m *DeliverResponse) GetStatus() common.Status {
	if x, ok := m.GetType().(*DeliverResponse_Status); ok {
		return x.Status
	}
	return common.Status_UNKNOWN
}

func (m *DeliverResponse) GetBlock() *common.Block {
	if x, ok := m.GetType().(*DeliverResponse_Block); ok {
		return x.Block
	}
	return nil
}

func (m *DeliverResponse) GetFilteredBlock() *FilteredBlock {
	if x, ok := m.GetType().(*DeliverResponse_FilteredBlock); ok {
		return x.FilteredBlock
	}
	return nil
}

func (m *DeliverResponse) GetBlockAndPrivateData() *BlockAndPrivateData {
	if x, ok := m.GetType().(*DeliverResponse_BlockAndPrivateData); ok {
		return x.BlockAndPrivateData
	}
	return nil
}

// XXX_OneofWrappers is for the internal use of the proto package.
func (*DeliverResponse) XXX_OneofWrappers() []interface{} {
	return []interface{}{
		(*DeliverResponse_Status)(nil),
		(*DeliverResponse_Block)(nil),
		(*DeliverResponse_FilteredBlock)(nil),
		(*DeliverResponse_BlockAndPrivateData)(nil),
	}
}

func init() {
	proto.RegisterType((*FilteredBlock)(nil), "protos.FilteredBlock")
	proto.RegisterType((*FilteredTransaction)(nil), "protos.FilteredTransaction")
	proto.RegisterType((*FilteredTransactionActions)(nil), "protos.FilteredTransactionActions")
	proto.RegisterType((*FilteredChaincodeAction)(nil), "protos.FilteredChaincodeAction")
	proto.RegisterType((*BlockAndPrivateData)(nil), "protos.BlockAndPrivateData")
	proto.RegisterMapType((map[uint64]*rwset.TxPvtReadWriteSet)(nil), "protos.BlockAndPrivateData.PrivateDataMapEntry")
	proto.RegisterType((*DeliverResponse)(nil), "protos.DeliverResponse")
}

func init() { proto.RegisterFile("peer/events.proto", fileDescriptor_5eedcc5fab2714e6) }

var fileDescriptor_5eedcc5fab2714e6 = []byte{
	// 700 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x94, 0x54, 0x4d, 0x6f, 0xda, 0x4a,
	0x14, 0xc5, 0x40, 0x78, 0xca, 0x45, 0x10, 0x32, 0xbc, 0x10, 0x8b, 0xe8, 0xe9, 0x45, 0x7e, 0x7a,
	0x15, 0x8b, 0xc6, 0x54, 0x74, 0x53, 0x65, 0xd1, 0x2a, 0xe4, 0x43, 0x44, 0x6a, 0x25, 0x34, 0xa1,
	0x8d, 0x9a, 0x2e, 0xac, 0xc1, 0xbe, 0x80, 0x1b, 0x63, 0x5b, 0xf6, 0x40, 0xe1, 0x9f, 0xf4, 0x87,
	0xf5, 0x97, 0x74, 0xd5, 0x55, 0x55, 0x79, 0xc6, 0xc3, 0x57, 0x48, 0xa4, 0x6c, 0xec, 0xf1, 0xbd,
	0xe7, 0x9c, 0x3b, 0xf7, 0xf8, 0xce, 0xc0, 0x7e, 0x88, 0x18, 0x35, 0x71, 0x8a, 0x3e, 0x8f, 0xcd,
	0x30, 0x0a, 0x78, 0x40, 0x0a, 0xe2, 0x15, 0xd7, 0xab, 0x76, 0x30, 0x1e, 0x07, 0x7e, 0x53, 0xbe,
	0x64, 0xb2, 0xae, 0x7b, 0xe8, 0x0c, 0x31, 0x6a, 0x46, 0xdf, 0x62, 0xe4, 0xf2, 0x99, 0x66, 0xea,
	0x42, 0xc9, 0x1e, 0x31, 0xd7, 0xb7, 0x03, 0x07, 0x2d, 0xa1, 0x99, 0xe6, 0x6a, 0x22, 0xc7, 0x23,
	0xe6, 0xc7, 0xcc, 0xe6, 0xae, 0x52, 0x33, 0xbe, 0x6b, 0x50, 0xba, 0x72, 0x3d, 0x8e, 0x11, 0x3a,
	0x6d, 0x2f, 0xb0, 0xef, 0xc9, 0x3f, 0x00, 0xf6, 0x88, 0xf9, 0x3e, 0x7a, 0x96, 0xeb, 0xe8, 0xda,
	0xb1, 0xd6, 0xd8, 0xa5, 0xbb, 0x69, 0xe4, 0xda, 0x21, 0x35, 0x28, 0xf8, 0x93, 0x71, 0x1f, 0x23,
	0x3d, 0x7b, 0xac, 0x35, 0xf2, 0x34, 0xfd, 0x22, 0x5d, 0x38, 0x18, 0xa4, 0x3a, 0xd6, 0x4a, 0x99,
	0x58, 0xcf, 0x1f, 0xe7, 0x1a, 0xc5, 0xd6, 0x91, 0xac, 0x17, 0x9b, 0xaa, 0x58, 0x6f, 0x89, 0xa1,
	0x7f, 0x0f, 0x1e, 0x06, 0x63, 0xe3, 0x97, 0x06, 0xd5, 0x2d, 0x68, 0x42, 0x20, 0xcf, 0x67, 0x8b,
	0xad, 0x89, 0x35, 0x79, 0x01, 0x79, 0x3e, 0x0f, 0x51, 0xec, 0xa9, 0xdc, 0x22, 0x66, 0xea, 0x58,
	0x07, 0x99, 0x83, 0x51, 0x6f, 0x1e, 0x22, 0x15, 0x79, 0x72, 0x05, 0x84, 0xcf, 0xac, 0x29, 0xf3,
	0x5c, 0x87, 0x25, 0x62, 0x56, 0x62, 0x94, 0x9e, 0x13, 0x2c, 0x5d, 0x6d, 0xb1, 0x37, 0xfb, 0xb4,
	0x00, 0x9c, 0x07, 0x0e, 0xd2, 0x0a, 0xdf, 0x88, 0x90, 0x8f, 0x50, 0x5d, 0x69, 0xd2, 0x5a, 0xf6,
	0xaa, 0x35, 0x8a, 0x2d, 0xe3, 0x89, 0x5e, 0xcf, 0x24, 0xb2, 0x93, 0xa1, 0x84, 0x3f, 0x88, 0xb6,
	0x0b, 0x90, 0xbf, 0x60, 0x9c, 0x19, 0x5f, 0xa1, 0xfe, 0x38, 0x97, 0xbc, 0x87, 0xfd, 0xe5, 0x4f,
	0x56, 0xa5, 0x35, 0x61, 0xf3, 0xbf, 0x9b, 0xa5, 0xcf, 0x15, 0x50, 0x92, 0x69, 0xc5, 0x5e, 0x0f,
	0xc4, 0xc6, 0x1d, 0x1c, 0x3e, 0x02, 0x26, 0xef, 0x60, 0x6f, 0x63, 0x9a, 0x84, 0xe9, 0xc5, 0x56,
	0x4d, 0x95, 0x59, 0x30, 0x2e, 0x93, 0x2c, 0x2d, 0xdb, 0x6b, 0xdf, 0xc6, 0x4f, 0x0d, 0xaa, 0x62,
	0xaa, 0xce, 0x7c, 0xa7, 0x1b, 0xb9, 0x53, 0xc6, 0x31, 0xe9, 0x8f, 0xfc, 0x07, 0x3b, 0xfd, 0x24,
	0x9c, 0xca, 0x95, 0xd4, 0xff, 0x12, 0x58, 0x2a, 0x73, 0xe4, 0x33, 0x54, 0x42, 0xc9, 0xb1, 0x1c,
	0xc6, 0x99, 0x35, 0x66, 0xa1, 0x9e, 0x15, 0x5d, 0x36, 0x55, 0xf9, 0x2d, 0xda, 0xe6, 0xca, 0xfa,
	0x03, 0x0b, 0x2f, 0x7d, 0x1e, 0xcd, 0x69, 0x39, 0x5c, 0x0b, 0xd6, 0xbf, 0x40, 0x75, 0x0b, 0x8c,
	0x54, 0x20, 0x77, 0x8f, 0x73, 0xb1, 0xa9, 0x3c, 0x4d, 0x96, 0xc4, 0x84, 0x9d, 0x29, 0xf3, 0x26,
	0x72, 0xb0, 0x8a, 0x2d, 0xdd, 0x94, 0xe7, 0xad, 0x37, 0xeb, 0x4e, 0x39, 0x45, 0xe6, 0xdc, 0x46,
	0x2e, 0xc7, 0x1b, 0xe4, 0x54, 0xc2, 0x4e, 0xb3, 0x6f, 0x34, 0xe3, 0xb7, 0x06, 0x7b, 0x17, 0xe8,
	0xb9, 0x53, 0x8c, 0x28, 0xc6, 0x61, 0xe0, 0xc7, 0x48, 0x1a, 0x50, 0x88, 0x39, 0xe3, 0x93, 0x58,
	0x88, 0x97, 0x5b, 0x65, 0xd5, 0xf1, 0x8d, 0x88, 0x76, 0x32, 0x34, 0xcd, 0x93, 0xff, 0x95, 0x35,
	0xd9, 0x2d, 0xd6, 0x74, 0x32, 0xca, 0x9c, 0xb7, 0x50, 0x5e, 0x1c, 0x37, 0x89, 0xcf, 0x09, 0xfc,
	0xc1, 0xe6, 0x00, 0x28, 0x5e, 0x69, 0xb0, 0x76, 0xca, 0x29, 0xd4, 0x04, 0xcd, 0x62, 0xbe, 0x63,
	0xad, 0xda, 0x9c, 0xce, 0xf0, 0xd1, 0x13, 0x16, 0x77, 0x32, 0xb4, 0xda, 0x7f, 0x18, 0x4e, 0xa6,
	0x37, 0x39, 0x6a, 0xad, 0x1f, 0x1a, 0xfc, 0x95, 0x1a, 0x40, 0x4e, 0x97, 0xcb, 0x8a, 0x6a, 0xe5,
	0xd2, 0x9f, 0xa2, 0x17, 0x84, 0x58, 0x3f, 0x54, 0x45, 0x36, 0xec, 0x32, 0x32, 0x0d, 0xed, 0x95,
	0x46, 0xda, 0x0b, 0x1f, 0x55, 0x33, 0xcf, 0xd7, 0xb8, 0x86, 0x5a, 0x9a, 0xb8, 0x75, 0xf9, 0x68,
	0x75, 0x06, 0x9f, 0x2b, 0xd5, 0x66, 0x60, 0x04, 0xd1, 0xd0, 0x1c, 0xcd, 0x43, 0x8c, 0xe4, 0x1d,
	0x6c, 0x0e, 0x58, 0x3f, 0x72, 0x6d, 0x45, 0x4b, 0xae, 0xd8, 0x76, 0x49, 0x4c, 0x7e, 0xdc, 0x65,
	0xf6, 0x3d, 0x1b, 0xe2, 0xdd, 0xcb, 0xa1, 0xcb, 0x47, 0x93, 0x7e, 0x52, 0xab, 0xb9, 0xc2, 0x6c,
	0x4a, 0xe6, 0x89, 0x64, 0x9e, 0x0c, 0x83, 0x66, 0x42, 0xee, 0xcb, 0x8b, 0xff, 0xf5, 0x9f, 0x00,
	0x00, 0x00, 0xff, 0xff, 0xe9, 0x5f, 0xb5, 0x2a, 0x14, 0x06, 0x00, 0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// DeliverClient is the client API for Deliver service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type DeliverClient interface {
	// Deliver first requires an Envelope of type ab.DELIVER_SEEK_INFO with
	// Payload data as a marshaled orderer.SeekInfo message,
	// then a stream of block replies is received
	Deliver(ctx context.Context, opts ...grpc.CallOption) (Deliver_DeliverClient, error)
	// DeliverFiltered first requires an Envelope of type ab.DELIVER_SEEK_INFO with
	// Payload data as a marshaled orderer.SeekInfo message,
	// then a stream of **filtered** block replies is received
	DeliverFiltered(ctx context.Context, opts ...grpc.CallOption) (Deliver_DeliverFilteredClient, error)
	// DeliverWithPrivateData first requires an Envelope of type ab.DELIVER_SEEK_INFO with
	// Payload data as a marshaled orderer.SeekInfo message,
	// then a stream of block and private data replies is received
	DeliverWithPrivateData(ctx context.Context, opts ...grpc.CallOption) (Deliver_DeliverWithPrivateDataClient, error)
}

type deliverClient struct {
	cc *grpc.ClientConn
}

func NewDeliverClient(cc *grpc.ClientConn) DeliverClient {
	return &deliverClient{cc}
}

func (c *deliverClient) Deliver(ctx context.Context, opts ...grpc.CallOption) (Deliver_DeliverClient, error) {
	stream, err := c.cc.NewStream(ctx, &_Deliver_serviceDesc.Streams[0], "/protos.Deliver/Deliver", opts...)
	if err != nil {
		return nil, err
	}
	x := &deliverDeliverClient{stream}
	return x, nil
}

type Deliver_DeliverClient interface {
	Send(*common.Envelope) error
	Recv() (*DeliverResponse, error)
	grpc.ClientStream
}

type deliverDeliverClient struct {
	grpc.ClientStream
}

func (x *deliverDeliverClient) Send(m *common.Envelope) error {
	return x.ClientStream.SendMsg(m)
}

func (x *deliverDeliverClient) Recv() (*DeliverResponse, error) {
	m := new(DeliverResponse)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *deliverClient) DeliverFiltered(ctx context.Context, opts ...grpc.CallOption) (Deliver_DeliverFilteredClient, error) {
	stream, err := c.cc.NewStream(ctx, &_Deliver_serviceDesc.Streams[1], "/protos.Deliver/DeliverFiltered", opts...)
	if err != nil {
		return nil, err
	}
	x := &deliverDeliverFilteredClient{stream}
	return x, nil
}

type Deliver_DeliverFilteredClient interface {
	Send(*common.Envelope) error
	Recv() (*DeliverResponse, error)
	grpc.ClientStream
}

type deliverDeliverFilteredClient struct {
	grpc.ClientStream
}

func (x *deliverDeliverFilteredClient) Send(m *common.Envelope) error {
	return x.ClientStream.SendMsg(m)
}

func (x *deliverDeliverFilteredClient) Recv() (*DeliverResponse, error) {
	m := new(DeliverResponse)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *deliverClient) DeliverWithPrivateData(ctx context.Context, opts ...grpc.CallOption) (Deliver_DeliverWithPrivateDataClient, error) {
	stream, err := c.cc.NewStream(ctx, &_Deliver_serviceDesc.Streams[2], "/protos.Deliver/DeliverWithPrivateData", opts...)
	if err != nil {
		return nil, err
	}
	x := &deliverDeliverWithPrivateDataClient{stream}
	return x, nil
}

type Deliver_DeliverWithPrivateDataClient interface {
	Send(*common.Envelope) error
	Recv() (*DeliverResponse, error)
	grpc.ClientStream
}

type deliverDeliverWithPrivateDataClient struct {
	grpc.ClientStream
}

func (x *deliverDeliverWithPrivateDataClient) Send(m *common.Envelope) error {
	return x.ClientStream.SendMsg(m)
}

func (x *deliverDeliverWithPrivateDataClient) Recv() (*DeliverResponse, error) {
	m := new(DeliverResponse)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// DeliverServer is the server API for Deliver service.
type DeliverServer interface {
	// Deliver first requires an Envelope of type ab.DELIVER_SEEK_INFO with
	// Payload data as a marshaled orderer.SeekInfo message,
	// then a stream of block replies is received
	Deliver(Deliver_DeliverServer) error
	// DeliverFiltered first requires an Envelope of type ab.DELIVER_SEEK_INFO with
	// Payload data as a marshaled orderer.SeekInfo message,
	// then a stream of **filtered** block replies is received
	DeliverFiltered(Deliver_DeliverFilteredServer) error
	// DeliverWithPrivateData first requires an Envelope of type ab.DELIVER_SEEK_INFO with
	// Payload data as a marshaled orderer.SeekInfo message,
	// then a stream of block and private data replies is received
	DeliverWithPrivateData(Deliver_DeliverWithPrivateDataServer) error
}

// UnimplementedDeliverServer can be embedded to have forward compatible implementations.
type UnimplementedDeliverServer struct {
}

func (*UnimplementedDeliverServer) Deliver(srv Deliver_DeliverServer) error {
	return status.Errorf(codes.Unimplemented, "method Deliver not implemented")
}
func (*UnimplementedDeliverServer) DeliverFiltered(srv Deliver_DeliverFilteredServer) error {
	return status.Errorf(codes.Unimplemented, "method DeliverFiltered not implemented")
}
func (*UnimplementedDeliverServer) DeliverWithPrivateData(srv Deliver_DeliverWithPrivateDataServer) error {
	return status.Errorf(codes.Unimplemented, "method DeliverWithPrivateData not implemented")
}

func RegisterDeliverServer(s *grpc.Server, srv DeliverServer) {
	s.RegisterService(&_Deliver_serviceDesc, srv)
}

func _Deliver_Deliver_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(DeliverServer).Deliver(&deliverDeliverServer{stream})
}

type Deliver_DeliverServer interface {
	Send(*DeliverResponse) error
	Recv() (*common.Envelope, error)
	grpc.ServerStream
}

type deliverDeliverServer struct {
	grpc.ServerStream
}

func (x *deliverDeliverServer) Send(m *DeliverResponse) error {
	return x.ServerStream.SendMsg(m)
}

func (x *deliverDeliverServer) Recv() (*common.Envelope, error) {
	m := new(common.Envelope)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func _Deliver_DeliverFiltered_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(DeliverServer).DeliverFiltered(&deliverDeliverFilteredServer{stream})
}

type Deliver_DeliverFilteredServer interface {
	Send(*DeliverResponse) error
	Recv() (*common.Envelope, error)
	grpc.ServerStream
}

type deliverDeliverFilteredServer struct {
	grpc.ServerStream
}

func (x *deliverDeliverFilteredServer) Send(m *DeliverResponse) error {
	return x.ServerStream.SendMsg(m)
}

func (x *deliverDeliverFilteredServer) Recv() (*common.Envelope, error) {
	m := new(common.Envelope)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

func _Deliver_DeliverWithPrivateData_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(DeliverServer).DeliverWithPrivateData(&deliverDeliverWithPrivateDataServer{stream})
}

type Deliver_DeliverWithPrivateDataServer interface {
	Send(*DeliverResponse) error
	Recv() (*common.Envelope, error)
	grpc.ServerStream
}

type deliverDeliverWithPrivateDataServer struct {
	grpc.ServerStream
}

func (x *deliverDeliverWithPrivateDataServer) Send(m *DeliverResponse) error {
	return x.ServerStream.SendMsg(m)
}

func (x *deliverDeliverWithPrivateDataServer) Recv() (*common.Envelope, error) {
	m := new(common.Envelope)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

var _Deliver_serviceDesc = grpc.ServiceDesc{
	ServiceName: "protos.Deliver",
	HandlerType: (*DeliverServer)(nil),
	Methods:     []grpc.MethodDesc{},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "Deliver",
			Handler:       _Deliver_Deliver_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
		{
			StreamName:    "DeliverFiltered",
			Handler:       _Deliver_DeliverFiltered_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
		{
			StreamName:    "DeliverWithPrivateData",
			Handler:       _Deliver_DeliverWithPrivateData_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
	},
	Metadata: "peer/events.proto",
}
