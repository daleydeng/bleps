use crate::{Data, Error, HciConnection};

#[derive(Debug)]
pub struct Event {
    code: u8,
    data: Data,
}

#[derive(Debug, Clone, Copy)]
pub enum EventType {
    CommandComplete {
        num_packets: u8,
        opcode: u16,
        data: Data,
    },
    DisconnectComplete {
        handle: u16,
        status: ErrorCode,
        reason: ErrorCode,
    },
    NumberOfCompletedPackets {
        number_of_connection_handles: u8,
        connection_handles: u16, // should be list
        completed_packets: u16,  // should be list
    },
    Unknown,
}

#[derive(Debug, Clone, Copy)]
pub enum ErrorCode {
    Okay = 0x00,
    UnknownHciCommand = 0x01,
    UnknownConnectionIdentifier = 0x02,
    HardwareFailure = 0x03,
    PageTimeout = 0x04,
    AuthenticationFailure = 0x05,
    PinOrKeyMissing = 0x06,
    MemoryCapacityExceeded = 0x07,
    ConnectionTimeout = 0x08,
    ConnectionLimitExceeded = 0x09,
    AclConnectionAlreadyExists = 0x0b,
    CommandDisallowed = 0x0c,
    RemoteUserTerminatedConnection = 0x13,
    // see Error Codes Description in spec
    Unknown = 0xff,
}

impl ErrorCode {
    pub fn from_u8(value: u8) -> ErrorCode {
        match value {
            0x00 => ErrorCode::Okay,
            0x01 => ErrorCode::UnknownHciCommand,
            0x02 => ErrorCode::UnknownConnectionIdentifier,
            0x03 => ErrorCode::HardwareFailure,
            0x04 => ErrorCode::PageTimeout,
            0x05 => ErrorCode::AuthenticationFailure,
            0x06 => ErrorCode::PinOrKeyMissing,
            0x07 => ErrorCode::MemoryCapacityExceeded,
            0x08 => ErrorCode::ConnectionTimeout,
            0x09 => ErrorCode::ConnectionLimitExceeded,
            0x0b => ErrorCode::AclConnectionAlreadyExists,
            0x0c => ErrorCode::CommandDisallowed,
            0x13 => ErrorCode::RemoteUserTerminatedConnection,

            _ => ErrorCode::Unknown,
        }
    }
}

const EVENT_COMMAND_COMPLETE: u8 = 0x0e;
const EVENT_DISCONNECTION_COMPLETE: u8 = 0x05;
const EVENT_NUMBER_OF_COMPLETED_PACKETS: u8 = 0x13;

impl EventType {
    pub fn check_command_completed(self) -> Result<Self, Error> {
        if let Self::CommandComplete {
            num_packets: _,
            opcode: _,
            data,
        } = self
        {
            let status = data.as_slice()[0];
            if status != 0 {
                return Err(Error::Failed(status));
            }
        }

        Ok(self)
    }

    /// Reads and decodes an event and assumes the packet type (0x04) is already read.
    pub fn read(connector: &dyn HciConnection) -> Self {
        let event = Event::read(connector);

        match event.code {
            EVENT_COMMAND_COMPLETE => {
                let data = event.data.as_slice();
                let num_packets = data[0];
                let opcode = ((data[2] as u16) << 8) + data[1] as u16;
                let data = event.data.subdata_from(3);
                Self::CommandComplete {
                    num_packets,
                    opcode,
                    data,
                }
            }
            EVENT_DISCONNECTION_COMPLETE => {
                let data = event.data.as_slice();
                let status = data[0];
                let handle = ((data[2] as u16) << 8) + data[1] as u16;
                let reason = data[3];
                let status = ErrorCode::from_u8(status);
                let reason = ErrorCode::from_u8(reason);
                Self::DisconnectComplete {
                    handle,
                    status,
                    reason,
                }
            }
            EVENT_NUMBER_OF_COMPLETED_PACKETS => {
                let data = event.data.as_slice();
                let num_handles = data[0];
                let connection_handle = ((data[2] as u16) << 8) + data[1] as u16;
                let completed_packet = ((data[4] as u16) << 8) + data[3] as u16;
                Self::NumberOfCompletedPackets {
                    number_of_connection_handles: num_handles,
                    connection_handles: connection_handle,
                    completed_packets: completed_packet,
                }
            }
            _ => {
                log::warn!(
                    "Ignoring unknown event {:02x} data = {:02x?}",
                    event.code,
                    event.data.as_slice()
                );
                Self::Unknown
            }
        }
    }

    #[cfg(feature = "async")]
    /// Reads and decodes an event and assumes the packet type (0x04) is already read.
    pub async fn async_read<T>(connector: &mut T) -> Self
    where
        T: embedded_io::asynch::Read,
    {
        let event = Event::async_read(connector).await;

        match event.code {
            EVENT_COMMAND_COMPLETE => {
                let data = event.data.as_slice();
                let num_packets = data[0];
                let opcode = ((data[2] as u16) << 8) + data[1] as u16;
                let data = event.data.subdata_from(3);
                Self::CommandComplete {
                    num_packets,
                    opcode,
                    data,
                }
            }
            EVENT_DISCONNECTION_COMPLETE => {
                let data = event.data.as_slice();
                let status = data[0];
                let handle = ((data[2] as u16) << 8) + data[1] as u16;
                let reason = data[3];
                let status = ErrorCode::from_u8(status);
                let reason = ErrorCode::from_u8(reason);
                Self::DisconnectComplete {
                    handle,
                    status,
                    reason,
                }
            }
            EVENT_NUMBER_OF_COMPLETED_PACKETS => {
                let data = event.data.as_slice();
                let num_handles = data[0];
                let connection_handle = ((data[2] as u16) << 8) + data[1] as u16;
                let completed_packet = ((data[4] as u16) << 8) + data[3] as u16;
                Self::NumberOfCompletedPackets {
                    number_of_connection_handles: num_handles,
                    connection_handles: connection_handle,
                    completed_packets: completed_packet,
                }
            }
            _ => {
                log::warn!(
                    "Ignoring unknown event {:02x} data = {:02x?}",
                    event.code,
                    event.data.as_slice()
                );
                Self::Unknown
            }
        }
    }
}

impl Event {
    fn read(connector: &dyn HciConnection) -> Self {
        let code = connector.read().unwrap() as u8;
        let len = connector.read().unwrap() as usize;
        let data = Data::read(connector, len);
        Self { code, data }
    }

    #[cfg(feature = "async")]
    async fn async_read<T>(connector: &mut T) -> Self
    where
        T: embedded_io::asynch::Read,
    {
        let mut buffer = [0u8];
        let _code_len = connector.read(&mut buffer).await.unwrap();
        let code = buffer[0];

        let _len_len = connector.read(&mut buffer).await.unwrap();
        let len = buffer[0] as usize;

        let data = Data::async_read(connector, len).await;
        Self { code, data }
    }
}
