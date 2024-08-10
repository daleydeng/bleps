use fixedstr::str_format;
use heapless::Vec;
use binrw::{binrw, io::Cursor, meta::WriteEndian, BinRead, BinResult, BinWrite, Endian};
use maybe_async::maybe_async;
use crate::{debug, Ble, BleError, MsgStr, MsgType};
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
#[br(map = |x: u8| x.try_into().unwrap())]
#[bw(map = |x: &Status| Into::<u8>::into(*x))]
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

impl TryFrom<u8> for Status {
    type Error = BleError;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if value == 0 {
            Ok(Status::Ok)
        } else {
            let e = value.try_into().map_err(|_| BleError::InvalidParameter(MsgType(
                str_format!(MsgStr, "from u8({}) to Status invalid!", value)
            )))?;
            Ok(Status::Err(e))
        }
    }
}

impl From<Status> for u8 {
    fn from(value: Status) -> Self {
        match value {
            Status::Ok => 0,
            Status::Err(e) => e.into()
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

fn parse_vec<R: binrw::io::Read + binrw::io::Seek, const N: usize>(count: usize, reader: &mut R, endian: Endian) -> BinResult<Vec<u8, N>> {
    let mut ret = Vec::new();
    for _ in 0..count {
        ret.push(<_>::read_options(reader, endian, ())?).unwrap();
    }
    Ok(ret)
}

pub mod hcicode {
    pub const COMMAND: u8 = 0x01;
    pub const ACL_DATA: u8 = 0x02;
    pub const SYNC_DATA: u8 = 0x03;
    pub const EVENT: u8 = 0x04;
    pub const ISO_DATA: u8 = 0x05;
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

    pub fn opcode(&self) -> Result<u16, BleError> {
        match self {
            HCIPacket::Command(cmd) => Ok(cmd.opcode()),
            _ => Err(BleError::PacketFormatError),
        }
    }

    #[maybe_async]
    pub async fn read<T: crate::Read>(connector: &mut T) -> Result<Option<Self>, BleError> {
        let mut buffer = [0u8;1];
        let l = connector.read(&mut buffer).await.map_err(|_|{BleError::IOError})?;
        if l == 0 {
            return Ok(None);
        }

        if l != 1 {
            return Err(BleError::IOError);
        }

        let typ = buffer[0];

        Ok(Some(match typ {
            hcicode::COMMAND => {
                Self::Command(CommandPacket::read(connector).await)
            },
            hcicode::EVENT => {
                Self::Event(EventPacket::read(connector).await)
            },
            hcicode::ACL_DATA => {
                Self::ACLData(ACLDataPacket::read(connector).await)
            }
            _ => {
                panic!("HCI type invalid {}", typ);
            },
        }))
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
        #[br(assert(len == 4, "size error, {}", len))]
        len: u8,
        status: Status,
        connection_handle: u16,
        reason: Status,
    },
    #[br(magic = 0x0eu8)]
    CommandComplete {
        #[br(assert(len > 3, "size error, {}", len))]
        len: u8,
        num_hci_command_packets: u8,
        command_opcode: u16,
        #[br(parse_with = parse_vec_event_command_complete, args(len - 3))]
        #[bw(map = |x| x.as_slice())]
        return_parameters: EvtPayloadBufferCommandComplete,
    },
    #[br(magic = 0x13u8)]
    NumberOfCompletedPackets {
        #[br(assert(len == 5, "size error, {}", len))]
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

impl EventPacket {
    #[maybe_async]
    pub async fn read<T: crate::Read>(connector: &mut T) -> Self {
        let mut buffer = [0u8; EVT_PKT_MAX_SIZE];
        let l = connector.read(&mut buffer[..EVT_PKT_HEADER_SIZE]).await.unwrap();
        assert_eq!(l, EVT_PKT_HEADER_SIZE);
        let len = buffer[1] as usize;
        let tot_len = len + EVT_PKT_HEADER_SIZE;

        let l = connector.read(&mut buffer[EVT_PKT_HEADER_SIZE..tot_len]).await.unwrap();
        assert_eq!(l, len);

        <Self as BinRead>::read(&mut Cursor::new(&buffer[..tot_len])).unwrap()
    }
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

impl ACLDataPacket {
    pub fn new(handle: u16, pb: ACLBoundaryFlag, bc: ACLBroadcastFlag, payload: &[u8]) -> Self {
        Self {
            header: ACLDataPacketHeader::new()
                .with_handle(handle)
                .with_packet_boundary_flag(pb)
                .with_broadcast_flag(bc),
            len: payload.len() as u16,
            data: ACLDataPayloadBuffer::from_slice(payload).unwrap(),
        }
    }

    pub fn encode(&self) -> ACLDataPacketBuffer {
        encode(self)
    }

    #[maybe_async]
    pub async fn read<T: crate::Read>(connector: &mut T) -> Self {
        let mut buffer = [0u8; ACL_PKT_MAX_SIZE];
        let l = connector.read(&mut buffer[..ACL_PKT_HEADER_SIZE]).await.unwrap();
        assert_eq!(l, ACL_PKT_HEADER_SIZE);
        let len = u16::from_le_bytes(buffer[2..ACL_PKT_HEADER_SIZE].try_into().unwrap()) as usize;
        assert!(len <= 27);
        let tot_len = len + ACL_PKT_HEADER_SIZE;
        let l = connector.read(&mut buffer[ACL_PKT_HEADER_SIZE..tot_len]).await.unwrap();
        assert_eq!(l, len);
        <Self as BinRead>::read(&mut Cursor::new(&buffer[..tot_len])).unwrap()
    }
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

// pub const fn opcode(ogf: u8, ocf: u16) -> u16 {
//     ((ogf as u16) << 10) + ocf as u16
// }

pub mod opcodes {
    pub const RESET: u16 = 0x0c03;
    pub const LE_SET_ADVERTISING_PARAMETERS: u16 = 0x2006;
    pub const LE_SET_ADVERTISING_DATA: u16 = 0x2008;
    pub const LE_SET_SCAN_RSP_DATA: u16 = 0x2009;
    pub const LE_SET_ADVERTISE_ENABLE: u16 = 0x200a;
    pub const LE_LONG_TERM_KEY_REQUEST_REPLY: u16 = 0x201a;
    pub const LE_SET_EVENT_MASK: u16 = 0x2001;
    pub const SET_EVENT_MASK: u16 = 0x0c01;
    pub const DISCONNECT: u16 = 0x0406;
    pub const READ_BD_ADDR: u16 = 0x1009;
}

#[binrw]
#[brw(little)]
#[derive(PartialEq, Clone, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum CommandPacket {
    Reset {
        #[bw(calc(opcodes::RESET))]
        #[br(assert(opcode == opcodes::RESET))]
        opcode: u16,

        #[bw(calc(0u8))]
        #[br(assert(len == 0, "len({}) != 0", len))]
        len: u8,
    },

    LeSetAdvertisingParameters {
        #[bw(calc(opcodes::LE_SET_ADVERTISING_PARAMETERS))]
        #[br(assert(opcode == opcodes::LE_SET_ADVERTISING_PARAMETERS))]
        opcode: u16,

        #[bw(calc(15u8))]
        #[br(assert(len == 15, "len({}) != 15", len))]
        len: u8,
        params: AdvertisingParameters,
    },

    #[br(assert(len == data.len() as u8 + 1, "len({}) != {}", len, data.len() as u8 + 1))]
    #[br(assert(data_len == data.len() as u8, "len({}) != {}", len, data.len() as u8))]
    LeSetAdvertisingData {
        #[bw(calc(opcodes::LE_SET_ADVERTISING_DATA))]
        #[br(assert(opcode == opcodes::LE_SET_ADVERTISING_DATA))]
        opcode: u16,

        #[bw(calc((data.len() + 1) as u8))]
        len: u8,
        #[bw(calc(data.len() as u8))]
        data_len: u8,
        #[br(parse_with = parse_le_adv_data, args(data_len))]
        #[bw(map = |x| x.as_slice())]
        data: CmdLeAdvDataBuffer,
    },

    #[br(assert(len == data.len() as u8 + 1, "len({}) != {}", len, data.len() as u8 + 1))]
    #[br(assert(data_len == data.len() as u8, "len({}) != {}", len, data.len() as u8))]
    LeSetScanRspData {
        #[bw(calc(opcodes::LE_SET_SCAN_RSP_DATA))]
        #[br(assert(opcode == opcodes::LE_SET_SCAN_RSP_DATA))]
        opcode: u16,

        #[bw(calc((data.len() + 1) as u8))]
        len: u8,
        #[bw(calc(data.len() as u8))]
        data_len: u8,
        #[br(parse_with = parse_le_scan_rsp_data, args(data_len))]
        #[bw(map = |x| x.as_slice())]
        data: CmdLeScanRspDataBuffer,
    },

    LeSetAdvertiseEnable{
        #[bw(calc(opcodes::LE_SET_ADVERTISE_ENABLE))]
        #[br(assert(opcode == opcodes::LE_SET_ADVERTISE_ENABLE))]
        opcode: u16,

        #[bw(calc(1u8))]
        #[br(assert(len == 1, "len({}) != 1", len))]
        len: u8,
        #[br(map = |x: u8| x == 0x01)] // us V.4 P.E 7.8.5
        #[bw(map = |x: &bool| if *x {0x01u8} else {0x00u8})]
        enable: bool,
    },

    LeLongTermKeyRequestReply {
        #[bw(calc(opcodes::LE_LONG_TERM_KEY_REQUEST_REPLY))]
        #[br(assert(opcode == opcodes::LE_LONG_TERM_KEY_REQUEST_REPLY))]
        opcode: u16,

        #[bw(calc(18u8))]
        #[br(assert(len == 18, "len({}) != 18", len))]
        len: u8,
        connection_handle: u16,
        ltk: u128
    },

    LeSetEventMask {
        #[bw(calc(opcodes::LE_SET_EVENT_MASK))]
        #[br(assert(opcode == opcodes::LE_SET_EVENT_MASK))]
        opcode: u16,

        #[bw(calc(8u8))]
        #[br(assert(len == 8, "len({}) != 8", len))]
        len: u8,
        event_mask: u64
    },

    SetEventMask {
        #[bw(calc(opcodes::SET_EVENT_MASK))]
        #[br(assert(opcode == opcodes::SET_EVENT_MASK))]
        opcode: u16,

        #[bw(calc(8u8))]
        #[br(assert(len == 8, "len({}) != 8", len))]
        len: u8,
        event_mask: u64
    },

    Disconnect {
        #[bw(calc(opcodes::DISCONNECT))]
        #[br(assert(opcode == opcodes::DISCONNECT))]
        opcode: u16,

        #[bw(calc(3u8))]
        #[br(assert(len == 3, "len({}) != 3", len))]
        len: u8,
        connection_handle: u16,
        reason: Status,
    },

    ReadBdAddr {
        #[bw(calc(opcodes::READ_BD_ADDR))]
        #[br(assert(opcode == opcodes::READ_BD_ADDR, "opcode error {}", opcode))]
        opcode: u16,

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

    pub fn opcode(&self) -> u16 {
        use CommandPacket::*;
        match self {
            Reset {..} => opcodes::RESET,
            LeSetAdvertisingParameters{..} => opcodes::LE_SET_ADVERTISING_PARAMETERS,
            LeSetAdvertisingData{..} => opcodes::LE_SET_ADVERTISING_DATA,
            LeSetScanRspData{..} => opcodes::LE_SET_SCAN_RSP_DATA,
            LeSetAdvertiseEnable{..} => opcodes::LE_SET_ADVERTISE_ENABLE,
            LeLongTermKeyRequestReply{..} => opcodes::LE_LONG_TERM_KEY_REQUEST_REPLY,
            LeSetEventMask{..} => opcodes::LE_SET_EVENT_MASK,
            SetEventMask{..} => opcodes::SET_EVENT_MASK,
            Disconnect{..} => opcodes::DISCONNECT,
            ReadBdAddr{..} => opcodes::READ_BD_ADDR,
        }
    }

    #[maybe_async]
    pub async fn read<T: crate::Read>(connector: &mut T) -> Self {
        let mut buffer = [0u8; CMD_PKT_MAX_SIZE];
        let l = connector.read(&mut buffer[..CMD_PKT_HEADER_SIZE]).await.unwrap();
        assert_eq!(l, CMD_PKT_HEADER_SIZE);
        let len = buffer[2] as usize;
        let tot_len = len + CMD_PKT_HEADER_SIZE;
        let l = connector.read(&mut buffer[CMD_PKT_HEADER_SIZE..tot_len]).await.unwrap();
        assert_eq!(l, len);
        <Self as BinRead>::read(&mut Cursor::new(&buffer[..tot_len])).unwrap()
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
