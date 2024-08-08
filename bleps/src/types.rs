use heapless::Vec;
use binrw::{io::{Cursor, Read, Seek}, BinRead, BinResult, BinWrite, Endian};
use modular_bitfield::{bitfield, prelude::*};

#[derive(Clone, Copy)]
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
        write!(f, "{:x?}", &self.data[..self.len]).expect("Failed to format Data");
        Ok(())
    }
}


pub const EVENT_PKT_HEADER_SIZE: usize = 2;
pub const EVENT_PKT_PAYLOAD_MAX_SIZE: usize = 255;
pub const EVENT_PKT_MAX_SIZE: usize = EVENT_PKT_HEADER_SIZE + EVENT_PKT_PAYLOAD_MAX_SIZE;

pub type EventPayloadBuffer = Vec<u8, EVENT_PKT_PAYLOAD_MAX_SIZE>;
pub type EventPacketBuffer = Vec<u8, EVENT_PKT_MAX_SIZE>;

pub const EVENT_PKT_HEDER_SIZE_COMMAND_COMPLETE: usize = 3;
pub const EVENT_PKT_PAYLOAD_MAX_SIZE_COMMAND_COMPLETE: usize = EVENT_PKT_PAYLOAD_MAX_SIZE - EVENT_PKT_HEDER_SIZE_COMMAND_COMPLETE;
pub type EventPayloadBufferCommandComplete = Vec<u8, EVENT_PKT_PAYLOAD_MAX_SIZE_COMMAND_COMPLETE>;

pub const ACL_PKT_HEADER_SIZE: usize = 4;
pub const ACL_PKT_PAYLOAD_MAX_SIZE: usize = 27;
pub const ACL_PKT_MAX_SIZE: usize =  ACL_PKT_HEADER_SIZE + ACL_PKT_PAYLOAD_MAX_SIZE;
pub type ACLPayloadBuffer = Vec<u8, ACL_PKT_PAYLOAD_MAX_SIZE>;
pub type ACLPacketBuffer = Vec<u8, ACL_PKT_MAX_SIZE>;


const fn max(a: usize, b: usize) -> usize {
    [a, b][(a < b) as usize]
}

pub const HCI_PKT_MAX_SIZE: usize = max(EVENT_PKT_MAX_SIZE, ACL_PKT_MAX_SIZE);
pub type HCIPacketBuffer = Vec<u8, HCI_PKT_MAX_SIZE>;

// Vol 1. Part F. 1.3
#[derive(BinRead, BinWrite, PartialEq, Clone, Copy, Debug)]
#[brw(repr(u8))]
pub enum ErrorCode {
    Success = 0x00,
    UnknownHciCommand = 0x01,
    UnknownConnectionIdentifier = 0x02,
    HardwareFailure = 0x03,
    PageTimeout = 0x04,
    AuthenticationFailure = 0x05,
    PinOrKeyMissing = 0x06,
    MemoryCapacityExceeded = 0x07,
    ConnectionTimeout = 0x08,
    ConnectionLimitExceeded = 0x09,
    SynchronousConnectionLimitToADeviceExceeded = 0x0a,
    ConnectionAlreadyExists = 0x0b,
    CommandDisallowed = 0x0c,
    ConnectionRejectedDueToLimitedResources = 0x0d,
    ConnectionRejectedDueToSecurityReasons = 0x0e,
    ConnectionRejectedDueToUnacceptableBDADDR = 0x0f,
    ConnectionAcceptTimeoutExceeded = 0x10,
    UnsupportedFeatureorParameterValue = 0x11,
    InvalidHCICommandParameters = 0x12,
    RemoteUserTerminatedConnection = 0x13,
    RemoteDeviceTerminatedConnectionduetoLowResources = 0x14,
    RemoteDeviceTerminatedConnectionduetoPowerOff = 0x15,
    ConnectionTerminatedByLocalHost = 0x16,
    RepeatedAttempts = 0x17,
    PairingNotAllowed = 0x18,
    UnknownLMPPDU = 0x19,
    UnsupportedRemoteFeature = 0x1a,
    SCOOffsetRejected = 0x1b,
    SCOIntervalRejected = 0x1c,
    SCOAirModeRejected = 0x1d,
    InvalidLMPParametersOrInvalidLLParameters = 0x1e,
    UnspecifiedError = 0x1f,
    UnsupportedLMPParameterValueOrUnsupportedLLParameterValue = 0x20,
    RoleChangeNotAllowed = 0x21,
    LMPResponseTimeoutOrLLResponseTimeout = 0x22,
    LMPErrorTransactionCollisionOrLLProcedureCollision = 0x23,
    LMPPDUNotAllowed = 0x24,
    EncryptionModeNotAcceptable = 0x25,
    LinkKeycannotbeChanged = 0x26,
    RequestedQoSNotSupported = 0x27,
    InstantPassed = 0x28,
    PairingWithUnitKeyNotSupported = 0x29,
    DifferentTransactionCollision = 0x2a,
    // Reserved for future use = 0x2b,
    QoSUnacceptableParameter = 0x2c,
    QoSRejected = 0x2d,
    ChannelClassificationNotSupported = 0x2e,
    InsufficientSecurity = 0x2f,
    ParameterOutOfMandatoryRange = 0x30,
    // Reserved for future use = 0x31,
    RoleSwitchPending = 0x32,
    // Reserved for future use = 0x33,
    ReservedSlotViolation = 0x34,
    RoleSwitchFailed = 0x35,
    ExtendedInquiryResponseTooLarge = 0x36,
    SecureSimplePairingNotSupportedByHost = 0x37,
    HostBusyPairing = 0x38,
    ConnectionRejectedDueToNoSuitableChannelFound = 0x39,
    ControllerBusy = 0x3a,
    UnacceptableConnectionParameters = 0x3b,
    AdvertisingTimeout = 0x3c,
    ConnectionTerminatedduetoMICFailure = 0x3d,
    ConnectionFailedToBeEstablishedOrSynchronizationTimeout = 0x3e,
    // Previously used = 0x3f
    CoarseClockAdjustmentRejectedbutWillTrytoAdjustUsingClockDragging = 0x40,
    Type0SubmapNotDefined = 0x41,

    UnknownAdvertisingIdentifier = 0x42,
    LimitReached = 0x43,
    OperationCancelledbyHost = 0x44,
    PacketTooLong = 0x45,
    TooLate = 0x46,
    TooEarly = 0x47,

    Unknown = 0xff,
}

#[derive(BinRead, BinWrite, PartialEq, Clone, Copy, Debug)]
#[brw(repr(u8))]
pub enum Role {
    Central = 0x00,
    Peripheral = 0x01,
}

#[derive(BinRead, BinWrite, PartialEq, Clone, Copy, Debug)]
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

#[derive(BinRead, BinWrite, PartialEq, Clone, Copy, Debug)]
#[brw(repr(u8))]
pub enum AddrType {
    Public = 0x00,
    Random = 0x01,
}

#[derive(BinRead, BinWrite, PartialEq, Clone, Copy, Debug)]
pub enum LEEventPacket {
    #[br(magic = 0x01u8)]
    ConnectionComplete {
        status: ErrorCode,
        connection_handle: u16,
        role: Role,
        peer_address_type: AddrType,
        peer_address: [u8; 6],
        #[br(map = |x: u16| x as u32 * 1250)] // us V.4 P.E 7.7.65
        connection_interval: u32,
        peripheral_latency: u16,
        #[br(map = |x: u16| x as u32 * 10)] // ms V.4 P.E 7.7.65
        supervision_timeout: u32,
        central_clock_accuracy: CentralClockAccuracy,
    },
    #[br(magic = 0x03u8)]
    ConnectionUpdateComplete {
        status: ErrorCode,
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

fn parse_vec<R: Read + Seek, const N: usize>(count: usize, reader: &mut R, endian: Endian) -> BinResult<Vec<u8, N>> {
    let mut ret = Vec::new();
    for _ in 0..count {
        ret.push(<_>::read_options(reader, endian, ())?).unwrap();
    }
    Ok(ret)
}

#[binrw::parser(reader, endian)]
fn parse_vec_event_command_complete(count: u8) -> BinResult<EventPayloadBufferCommandComplete> {
    parse_vec(count as usize, reader, endian)
}

#[derive(BinRead, BinWrite, PartialEq, Clone, Debug)]
#[brw(little)]
pub enum EventPacket {
    #[br(magic = 0x05u8)]
    DisconnectionComplete {
        len: u8,
        status: ErrorCode,
        connection_handle: u16,
        reason: ErrorCode,
    },
    #[br(magic = 0x0eu8)]
    CommandComplete {
        len: u8,
        num_hci_command_packets: u8,
        command_opcode: u16,
        #[br(parse_with = parse_vec_event_command_complete, args(len - 3))]
        #[bw(map = |x| x.as_slice())]
        return_parameters: EventPayloadBufferCommandComplete,
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

#[derive(BitfieldSpecifier, Clone, Copy, PartialEq, Debug)]
#[bits=2]
pub enum ACLBoundaryFlag {
    FirstNonAutoFlushable,
    Continuing,
    FirstAutoFlushable,
    Unused,
}

#[derive(BitfieldSpecifier, Clone, Copy, PartialEq, Debug)]
#[bits=2]
pub enum ACLBroadcastFlag {
    PointToPoint,
    BREDRBroadcast,
    Reserved1,
    Reserved2,
}

#[binrw::parser(reader, endian)]
fn parse_acl_payload(count: u16) -> BinResult<ACLPayloadBuffer> {
    parse_vec(count as usize, reader, endian)
}

#[bitfield]
#[derive(BinRead, BinWrite, PartialEq, Clone, Copy, Debug)]
#[br(map = Self::from_bytes)]
#[bw(map = |&x| Self::into_bytes(x))]
pub struct ACLDataPacketHeader {
    pub handle: B12,
    pub packet_boundary_flag: ACLBoundaryFlag,
    pub broadcast_flag: ACLBroadcastFlag,
}

#[derive(BinRead, BinWrite, PartialEq, Clone, Debug)]
#[brw(little)]
pub struct ACLDataPacket {
    pub header: ACLDataPacketHeader,
    pub len: u16,
    #[br(parse_with = parse_acl_payload, args(len))]
    #[bw(map = |x| x.as_slice())]
    pub data: ACLPayloadBuffer,
}

#[derive(BinRead, BinWrite, Debug, PartialEq, Clone)]
#[brw(little)]
pub enum HCIPacket {
    #[brw(magic = 0x01u8)]
    Command,
    #[brw(magic = 0x02u8)]
    ACLData(ACLDataPacket),
    #[brw(magic = 0x03u8)]
    SyncData,
    #[brw(magic = 0x04u8)]
    Event(EventPacket),
    #[brw(magic = 0x05u8)]
    ISOData,
}


impl HCIPacket {
    pub fn encode(&self) -> HCIPacketBuffer {
        let mut buf = [0u8; HCI_PKT_MAX_SIZE];
        let mut writer = Cursor::new(&mut buf[..]);
        self.write(&mut writer).unwrap();
        let len = writer.position() as usize;
        HCIPacketBuffer::from_slice(&buf[..len]).unwrap()
    }
}
