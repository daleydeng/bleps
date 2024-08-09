use heapless::Vec;
use binrw::{binrw, io::{Cursor, Read, Seek}, meta::WriteEndian, BinRead, BinResult, BinWrite, Endian};
use crate::debug;
use modular_bitfield::{bitfield, prelude::*};
use thiserror_no_std::Error;
use num_enum::{TryFromPrimitive, IntoPrimitive};

#[derive(Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Data {
    pub data: [u8; 256],
    pub len: usize,
}

impl Default for Data {
    fn default() -> Self {
        Self {
            data: [0; 256],
            len: 0,
        }
    }
}

impl core::fmt::Debug for Data {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}", &self.data[..self.len]).expect("Failed to format Data");
        Ok(())
    }
}


pub const EVT_PKT_HEADER_SIZE: usize = 2;
pub const EVT_PKT_PAYLOAD_MAX_SIZE: usize = 255;
pub const EVT_PKT_MAX_SIZE: usize = EVT_PKT_HEADER_SIZE + EVT_PKT_PAYLOAD_MAX_SIZE;

pub type EventPayloadBuffer = Vec<u8, EVT_PKT_PAYLOAD_MAX_SIZE>;
pub type EventPacketBuffer = Vec<u8, EVT_PKT_MAX_SIZE>;

pub const EVT_PKT_HEDER_SIZE_COMMAND_COMPLETE: usize = 3;
pub const EVT_PKT_PAYLOAD_MAX_SIZE_COMMAND_COMPLETE: usize = EVT_PKT_PAYLOAD_MAX_SIZE - EVT_PKT_HEDER_SIZE_COMMAND_COMPLETE;
pub type EvtPayloadBufferCommandComplete = Vec<u8, EVT_PKT_PAYLOAD_MAX_SIZE_COMMAND_COMPLETE>;

pub const ACL_PKT_HEADER_SIZE: usize = 4;
pub const ACL_PKT_PAYLOAD_MAX_SIZE: usize = 27;
pub const ACL_PKT_MAX_SIZE: usize =  ACL_PKT_HEADER_SIZE + ACL_PKT_PAYLOAD_MAX_SIZE;
pub type ACLDataPayloadBuffer = Vec<u8, ACL_PKT_PAYLOAD_MAX_SIZE>;
pub type ACLDataPacketBuffer = Vec<u8, ACL_PKT_MAX_SIZE>;

pub const CMD_PKT_HEADER_SIZE: usize = 3;
pub const CMD_PKT_PAYLOAD_MAX_SIZE: usize = 255;
pub const CMD_PKT_MAX_SIZE: usize = CMD_PKT_HEADER_SIZE + CMD_PKT_PAYLOAD_MAX_SIZE;
pub type CommandPacketBuffer = Vec<u8, CMD_PKT_MAX_SIZE>;

pub const CMD_LE_ADV_DATA_MAX_SIZE: usize = 31;
pub type CmdLeAdvDataBuffer = Vec<u8, CMD_LE_ADV_DATA_MAX_SIZE>;
pub const CMD_LE_SCAN_RSP_DATA_MAX_SIZE: usize = 31;
pub type CmdLeScanRspDataBuffer = Vec<u8, CMD_LE_SCAN_RSP_DATA_MAX_SIZE>;

const fn max(a: usize, b: usize) -> usize {
    [a, b][(a < b) as usize]
}

pub const HCI_PKT_MAX_SIZE: usize = max(max(EVT_PKT_MAX_SIZE, ACL_PKT_MAX_SIZE), CMD_PKT_MAX_SIZE);
pub type HCIPacketBuffer = Vec<u8, HCI_PKT_MAX_SIZE>;

// Vol 1. Part F. 1.3
#[derive(Error, TryFromPrimitive, IntoPrimitive, PartialEq, Clone, Copy, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[repr(u8)]
pub enum ControllerError {
    #[error("Unknown HCI Command")]
    UnknownHciCommand = 0x01,
    #[error("Unknown Connection Identifier")]
    UnknownConnectionIdentifier = 0x02,
    #[error("Hardware Failure")]
    HardwareFailure = 0x03,
    #[error("Page Timeout")]
    PageTimeout = 0x04,
    #[error("Authentication Failure")]
    AuthenticationFailure = 0x05,
    #[error("PIN or Key Missing")]
    PinOrKeyMissing = 0x06,
    #[error("Memory Capacity Exceeded")]
    MemoryCapacityExceeded = 0x07,
    #[error("Connection Timeout")]
    ConnectionTimeout = 0x08,
    #[error("Connection Limit Exceeded")]
    ConnectionLimitExceeded = 0x09,
    #[error("Synchronous Connection Limit To A Device Exceeded")]
    SynchronousConnectionLimitToADeviceExceeded = 0x0a,
    #[error("Connection Already Exists")]
    ConnectionAlreadyExists = 0x0b,
    #[error("Command Disallowed")]
    CommandDisallowed = 0x0c,
    #[error("Connection Rejected due to Limited Resources")]
    ConnectionRejectedDueToLimitedResources = 0x0d,
    #[error("Connection Rejected Due To Security Reasons")]
    ConnectionRejectedDueToSecurityReasons = 0x0e,
    #[error("Connection Rejected due to Unacceptable BD_ADDR")]
    ConnectionRejectedDueToUnacceptableBDADDR = 0x0f,
    #[error("Connection Accept Timeout Exceeded")]
    ConnectionAcceptTimeoutExceeded = 0x10,
    #[error("Unsupported Feature or Parameter Value")]
    UnsupportedFeatureorParameterValue = 0x11,
    #[error("Invalid HCI Command Parameters")]
    InvalidHCICommandParameters = 0x12,
    #[error("Remote User Terminated Connection")]
    RemoteUserTerminatedConnection = 0x13,
    #[error("Remote Device Terminated Connection due to Low Resources")]
    RemoteDeviceTerminatedConnectionduetoLowResources = 0x14,
    #[error("Remote Device Terminated Connection due to Power Off")]
    RemoteDeviceTerminatedConnectionduetoPowerOff = 0x15,
    #[error("Connection Terminated By Local Host")]
    ConnectionTerminatedByLocalHost = 0x16,
    #[error("Repeated Attempts")]
    RepeatedAttempts = 0x17,
    #[error("Pairing Not Allowed")]
    PairingNotAllowed = 0x18,
    #[error("Unknown LMP PDU")]
    UnknownLMPPDU = 0x19,
    #[error("Unsupported Remote Feature")]
    UnsupportedRemoteFeature = 0x1a,
    #[error("SCO Offset Rejected")]
    SCOOffsetRejected = 0x1b,
    #[error("SCO Interval Rejected")]
    SCOIntervalRejected = 0x1c,
    #[error("SCO Air Mode Rejected")]
    SCOAirModeRejected = 0x1d,
    #[error("Invalid LMP Parameters / Invalid LL Parameters")]
    InvalidLMPParametersOrInvalidLLParameters = 0x1e,
    #[error("Unspecified Error")]
    UnspecifiedError = 0x1f,
    #[error("Unsupported LMP Parameter Value / Unsupported LL Parameter Value")]
    UnsupportedLMPParameterValueOrUnsupportedLLParameterValue = 0x20,
    #[error("Role Change Not Allowed")]
    RoleChangeNotAllowed = 0x21,
    #[error("LMP Response Timeout / LL Response Timeout")]
    LMPResponseTimeoutOrLLResponseTimeout = 0x22,
    #[error("LMP Error Transaction Collision / LL Procedure Collision")]
    LMPErrorTransactionCollisionOrLLProcedureCollision = 0x23,
    #[error("LMP PDU Not Allowed")]
    LMPPDUNotAllowed = 0x24,
    #[error("Encryption Mode Not Acceptable")]
    EncryptionModeNotAcceptable = 0x25,
    #[error("Link Key cannot be Changed")]
    LinkKeycannotbeChanged = 0x26,
    #[error("Requested QoS Not Supported")]
    RequestedQoSNotSupported = 0x27,
    #[error("Instant Passed")]
    InstantPassed = 0x28,
    #[error("Pairing With Unit Key Not Supported")]
    PairingWithUnitKeyNotSupported = 0x29,
    #[error("Different Transaction Collision")]
    DifferentTransactionCollision = 0x2a,
    // Reserved for future use = 0x2b,
    #[error("QoS Unacceptable Parameter")]
    QoSUnacceptableParameter = 0x2c,
    #[error("QoS Rejected")]
    QoSRejected = 0x2d,
    #[error("Channel Classification Not Supported")]
    ChannelClassificationNotSupported = 0x2e,
    #[error("Insufficient Security")]
    InsufficientSecurity = 0x2f,
    #[error("Parameter Out Of Mandatory Range")]
    ParameterOutOfMandatoryRange = 0x30,
    // Reserved for future use = 0x31,
    #[error("Role Switch Pending")]
    RoleSwitchPending = 0x32,
    // Reserved for future use = 0x33,
    #[error("Reserved Slot Violation")]
    ReservedSlotViolation = 0x34,
    #[error("Role Switch Failed")]
    RoleSwitchFailed = 0x35,
    #[error("Extended Inquiry Response Too Large")]
    ExtendedInquiryResponseTooLarge = 0x36,
    #[error("Secure Simple Pairing Not Supported By Host")]
    SecureSimplePairingNotSupportedByHost = 0x37,
    #[error("Host Busy - Pairing")]
    HostBusyPairing = 0x38,
    #[error("Connection Rejected due to No Suitable Channel Found")]
    ConnectionRejectedDueToNoSuitableChannelFound = 0x39,
    #[error("Controller Busy")]
    ControllerBusy = 0x3a,
    #[error("Unacceptable Connection Parameters")]
    UnacceptableConnectionParameters = 0x3b,
    #[error("Advertising Timeout")]
    AdvertisingTimeout = 0x3c,
    #[error("Connection Terminated due to MIC Failure")]
    ConnectionTerminatedduetoMICFailure = 0x3d,
    #[error("Connection Failed to be Established / Synchronization Timeout")]
    ConnectionFailedToBeEstablishedOrSynchronizationTimeout = 0x3e,
    // Previously used = 0x3f
    #[error("Coarse Clock Adjustment Rejected but Will Try to Adjust Using Clock Dragging")]
    CoarseClockAdjustmentRejectedbutWillTrytoAdjustUsingClockDragging = 0x40,
    #[error("Type0 Submap Not Defined")]
    Type0SubmapNotDefined = 0x41,
    #[error("Unknown Advertising Identifier")]
    UnknownAdvertisingIdentifier = 0x42,
    #[error("Limit Reached")]
    LimitReached = 0x43,
    #[error("Operation Cancelled by Host")]
    OperationCancelledbyHost = 0x44,
    #[error("Packet Too Long")]
    PacketTooLong = 0x45,
    #[error("Too Late")]
    TooLate = 0x46,
    #[error("Too Early")]
    TooEarly = 0x47,
}

#[derive(BinRead, BinWrite, PartialEq, Clone, Copy, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[brw(little)]
#[br(map = |x: u8| if x == 0 { Status::Ok } else {Status::Err(ControllerError::try_from(x).unwrap())})]
#[bw(map = |&x| if let Status::Err(x) = x {x.into()} else {0u8})]
pub enum Status{
    Ok,
    Err(ControllerError),
}

impl From<Status> for Result<u8, ControllerError> {
    fn from(value: Status) -> Self {
        if let Status::Err(x) = value {
            Err(x)
        } else {
            Ok(0u8)
        }
    }
}

#[derive(BinRead, BinWrite, PartialEq, Clone, Copy, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[brw(repr(u8))]
pub enum Role {
    Central = 0x00,
    Peripheral = 0x01,
}

#[derive(BinRead, BinWrite, PartialEq, Clone, Copy, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[brw(repr(u8))]
pub enum CentralClockAccuracy {
    PPM500 = 0x00,
    PPM250 = 0x01,
    PPM150 = 0x02,
    PPM100 = 0x03,
    PPM75 = 0x04,
    PPM50 = 0x05,
    PPM30 = 0x06,
    PPM20 = 0x07,
}

fn parse_vec<R: Read + Seek, const N: usize>(count: usize, reader: &mut R, endian: Endian) -> BinResult<Vec<u8, N>> {
    let mut ret = Vec::new();
    for _ in 0..count {
        ret.push(<_>::read_options(reader, endian, ())?).unwrap();
    }
    Ok(ret)
}

#[derive(BinRead, BinWrite, Debug, PartialEq, Clone)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[brw(little)]
pub enum HCIPacket {
    #[brw(magic = 0x01u8)]
    Command(CommandPacket),
    #[brw(magic = 0x02u8)]
    ACLData(ACLDataPacket),
    #[brw(magic = 0x03u8)]
    SyncData,
    #[brw(magic = 0x04u8)]
    Event(EventPacket),
    #[brw(magic = 0x05u8)]
    ISOData,
}

pub fn encode<T: BinWrite + WriteEndian, const SIZE: usize>(data: &T) -> Vec<u8, SIZE>
    where for<'a> <T as BinWrite>::Args<'a>: Default
{
    let mut buf = [0u8; SIZE];
    let mut writer = Cursor::new(&mut buf[..]);
    data.write(&mut writer).unwrap();
    let len = writer.position() as usize;
    Vec::from_slice(&buf[..len]).unwrap()
}

impl HCIPacket {
    pub fn encode(&self) -> HCIPacketBuffer {
        encode(self)
    }
}

#[binrw::parser(reader, endian)]
fn parse_vec_event_command_complete(count: u8) -> BinResult<EvtPayloadBufferCommandComplete> {
    parse_vec(count as usize, reader, endian)
}

#[derive(BinRead, BinWrite, PartialEq, Clone, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[brw(little)]
pub enum EventPacket {
    #[br(magic = 0x05u8)]
    DisconnectionComplete {
        len: u8,
        status: Status,
        connection_handle: u16,
        reason: Status,
    },
    #[br(magic = 0x0eu8)]
    CommandComplete {
        len: u8,
        num_hci_command_packets: u8,
        command_opcode: u16,
        #[br(parse_with = parse_vec_event_command_complete, args(len - 3))]
        #[bw(map = |x| x.as_slice())]
        return_parameters: EvtPayloadBufferCommandComplete,
    },
    #[br(magic = 0x13u8)]
    NumberOfCompletedPackets {
        len: u8,
        num_handles: u8,
        connection_handle_i: u16,     // should be list
        num_completed_packets_i: u16, // should be lis
    },
    #[br(magic = 0x3eu8)]
    LEMeta {
        len: u8,
        packet: LEEventPacket
    },
    #[br(magic = 0xffu8)]
    Unknown,
}

type Address = [u8; 6];

#[derive(BinRead, BinWrite, PartialEq, Clone, Copy, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum LEEventPacket {
    #[br(magic = 0x01u8)]
    ConnectionComplete {
        status: Status,
        connection_handle: u16,
        role: Role,
        peer_address_type: PeerAddressType,
        peer_address: Address,
        #[br(map = |x: u16| x as u32 * 1250)] // us V.4 P.E 7.7.65
        connection_interval: u32,
        peripheral_latency: u16,
        #[br(map = |x: u16| x as u32 * 10)] // ms V.4 P.E 7.7.65
        supervision_timeout: u32,
        central_clock_accuracy: CentralClockAccuracy,
    },
    #[br(magic = 0x03u8)]
    ConnectionUpdateComplete {
        status: Status,
        connection_handle: u16,
        #[br(map = |x: u16| x as u32 * 1250)] // us V.4 P.E 7.7.65
        connection_interval: u32,
        peripheral_latency: u16,
        #[br(map = |x: u16| x as u32 * 10)] // ms V.4 P.E 7.7.65
        supervision_timeout: u32,
    },
    #[br(magic = 0x05u8)]
    LongTermKeyRequest {
        connection_handle: u16,
        random_number: u64,
        encrypted_diversifier: u16,
    },
}

#[binrw::parser(reader, endian)]
fn parse_acl_payload(count: u16) -> BinResult<ACLDataPayloadBuffer> {
    parse_vec(count as usize, reader, endian)
}


#[derive(BinRead, BinWrite, PartialEq, Clone, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[brw(little)]
pub struct ACLDataPacket {
    pub header: ACLDataPacketHeader,
    pub len: u16,
    #[br(parse_with = parse_acl_payload, args(len))]
    #[bw(map = |x| x.as_slice())]
    pub data: ACLDataPayloadBuffer,
}

impl ACLDataPacket {
    pub fn encode(&self) -> ACLDataPacketBuffer {
        encode(self)
    }
}

#[bitfield]
#[derive(BinRead, BinWrite, PartialEq, Clone, Copy, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[br(map = Self::from_bytes)]
#[bw(map = |&x| Self::into_bytes(x))]
pub struct ACLDataPacketHeader {
    pub handle: B12,
    pub packet_boundary_flag: ACLBoundaryFlag,
    pub broadcast_flag: ACLBroadcastFlag,
}

#[derive(BitfieldSpecifier, Clone, Copy, PartialEq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[bits=2]
pub enum ACLBoundaryFlag {
    FirstNonAutoFlushable,
    Continuing,
    FirstAutoFlushable,
    Unused,
}

#[derive(BitfieldSpecifier, Clone, Copy, PartialEq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[bits=2]
pub enum ACLBroadcastFlag {
    PointToPoint,
    BREDRBroadcast,
    Reserved1,
    Reserved2,
}

#[binrw::parser(reader, endian)]
fn parse_le_adv_data(data_len: u8) -> BinResult<CmdLeAdvDataBuffer> {
    parse_vec(data_len as usize, reader, endian)
}
#[binrw::parser(reader, endian)]
fn parse_le_scan_rsp_data(data_len: u8) -> BinResult<CmdLeScanRspDataBuffer> {
    parse_vec(data_len as usize, reader, endian)
}

#[binrw]
#[brw(little)]
#[derive(PartialEq, Clone, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum CommandPacket {
    #[brw(magic = 0x0c03u16)] // 0x3 << 10 + 0x3
    Reset {
        #[bw(calc(0u8))]
        #[br(assert(len == 0, "len({}) != 0", len))]
        len: u8,
    },
    #[brw(magic = 0x2006u16)]
    LeSetAdvertisingParameters {
        #[bw(calc(15u8))]
        #[br(assert(len == 15, "len({}) != 15", len))]
        len: u8,
        params: AdvertisingParameters,
    },
    #[brw(magic = 0x2008u16)]
    #[br(assert(len == data.len() as u8 + 1, "len({}) != {}", len, data.len() as u8 + 1))]
    #[br(assert(data_len == data.len() as u8, "len({}) != {}", len, data.len() as u8))]
    LeSetAdvertisingData {
        #[bw(calc((data.len() + 1) as u8))]
        len: u8,
        #[bw(calc(data.len() as u8))]
        data_len: u8,
        #[br(parse_with = parse_le_adv_data, args(data_len))]
        #[bw(map = |x| x.as_slice())]
        data: CmdLeAdvDataBuffer,
    },
    #[brw(magic = 0x2009u16)]
    #[br(assert(len == data.len() as u8 + 1, "len({}) != {}", len, data.len() as u8 + 1))]
    #[br(assert(data_len == data.len() as u8, "len({}) != {}", len, data.len() as u8))]
    LeSetScanRspData {
        #[bw(calc((data.len() + 1) as u8))]
        len: u8,
        #[bw(calc(data.len() as u8))]
        data_len: u8,
        #[br(parse_with = parse_le_scan_rsp_data, args(data_len))]
        #[bw(map = |x| x.as_slice())]
        data: CmdLeScanRspDataBuffer,
    },
    #[brw(magic = 0x200au16)]
    LeSetAdvertiseEnable{
        #[bw(calc(1u8))]
        #[br(assert(len == 1, "len({}) != 1", len))]
        len: u8,
        #[br(map = |x: u8| x == 0x01)] // us V.4 P.E 7.8.5
        #[bw(map = |x: &bool| if *x {0x01} else {0x00})]
        enable: bool,
    },
    #[brw(magic = 0x201au16)]
    LeLongTermKeyRequestReply {
        #[bw(calc(18u8))]
        #[br(assert(len == 18, "len({}) != 18", len))]
        len: u8,
        connection_handle: u16,
        ltk: u128
    },
    #[brw(magic = 0x2001u16)]
    LeSetEventMask {
        #[bw(calc(8u8))]
        #[br(assert(len == 8, "len({}) != 8", len))]
        len: u8,
        event_mask: u64
    },
    #[brw(magic = 0x0c01u16)]
    SetEventMask {
        #[bw(calc(8u8))]
        #[br(assert(len == 8, "len({}) != 8", len))]
        len: u8,
        event_mask: u64
    },
    #[brw(magic = 0x0406u16)]
    Disconnect {
        #[bw(calc(3u8))]
        #[br(assert(len == 3, "len({}) != 3", len))]
        len: u8,
        connection_handle: u16,
        reason: Status,
    },
    #[brw(magic = 0x1009u16)]
    ReadBdAddr {
        #[bw(calc(0u8))]
        #[br(assert(len == 0, "len({}) != 0", len))]
        len: u8,
    }
}

#[derive(BinRead, BinWrite, PartialEq, Clone, Copy, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[brw(little)]
pub struct AdvertisingParameters {
    #[br(map = |x: u16| x as u32 * 625)] // us V.4 P.E 7.8.5
    #[bw(map = |x: &u32| (x / 625) as u16)]
    advertising_interval_min: u32,
    #[br(map = |x: u16| x as u32 * 625)] // us V.4 P.E 7.8.5
    #[bw(map = |x: &u32| (x / 625) as u16)]
    advertising_interval_max: u32,
    advertising_type: AdvertisingType,
    own_address_type: OwnAddressType,
    peer_address_type: PeerAddressType,
    peer_address: Address,
    advertising_channel_map: u8,
    filter_policy: AdvertisingFilterPolicy,
}

impl Default for AdvertisingParameters {
    fn default() -> Self {
        Self {
            advertising_interval_min: 160_000,
            advertising_interval_max: 160_000,
            advertising_type: AdvertisingType::AdvInd,
            own_address_type: OwnAddressType::Public,
            peer_address_type: PeerAddressType::Public,
            peer_address: [0u8;6],
            advertising_channel_map: 0x7,
            filter_policy: AdvertisingFilterPolicy::All,
        }
    }
}

impl CommandPacket {
    pub fn encode(&self) -> CommandPacketBuffer {
        encode(self)
    }
}

#[bitfield]
#[derive(BinRead, BinWrite, PartialEq, Clone, Copy, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[br(map = Self::from_bytes)]
#[bw(map = |&x| Self::into_bytes(x))]
pub struct Opcode {
    ocf: B10,
    ogf: OGF,
}

#[derive(BitfieldSpecifier, Clone, Copy, PartialEq, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[bits=6]
pub enum OGF {
    LinkControlCmd,
    LinkPolicyCmd,
    ControllerBasebandCmd,
    InfoParam,
    StatusParam,
    TestingCmd,
    Reserved,
    LEControllerCmd,
}

#[derive(BinRead, BinWrite, PartialEq, Clone, Copy, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[brw(repr(u8))]
pub enum AdvertisingType {
    AdvInd = 0x00,
    AdvDirectInd = 0x01,
    AdvScanInd = 0x02,
    AdvNonConnInd = 0x03,
    AdvDirectIndLowDuty = 0x04,
}

#[derive(BinRead, BinWrite, PartialEq, Clone, Copy, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[brw(repr(u8))]
pub enum OwnAddressType {
    Public = 0x00,
    Random = 0x01,
    ResolvablePrivateAddress = 0x02,
    ResolvablePrivateAddressFromIRK = 0x03,
}

#[derive(BinRead, BinWrite, PartialEq, Clone, Copy, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[brw(repr(u8))]
pub enum PeerAddressType {
    Public = 0x00,
    Random = 0x01,
}

#[derive(BinRead, BinWrite, PartialEq, Clone, Copy, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[brw(repr(u8))]
pub enum AdvertisingFilterPolicy {
    All = 0x00,
    ConnectAllScanFiltered = 0x01,
    ScanAllConnFiltered = 0x02,
    Filtered = 0x03,
}
