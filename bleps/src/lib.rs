#![no_std]

use log::*;
use types::ACLDataPacket;
use core::cell::RefCell;

use command::{
    opcode, Command, INFORMATIONAL_OGF, LONG_TERM_KEY_REQUEST_REPLY_OCF, READ_BD_ADDR_OCF,
    SET_ADVERTISE_ENABLE_OCF, SET_ADVERTISING_DATA_OCF, SET_EVENT_MASK_OCF, SET_SCAN_RSP_DATA_OCF,
};
use command::{CONTROLLER_OGF, LE_OGF, RESET_OCF, SET_ADVERTISING_PARAMETERS_OCF};
pub use types::{Data, EventPacket};

pub mod acl;
pub mod ad_structure;
pub mod att;
pub mod buffer;
pub mod command;
pub mod event;
pub mod l2cap;

pub mod types;

pub mod attribute;
pub mod attribute_server;

#[cfg(feature = "sync")]
pub use embedded_io::{Read, Write};
#[cfg(feature = "async")]
pub use embedded_io_async::{Read, Write};
#[cfg(feature = "async")]
pub mod async_attribute_server;

#[cfg(feature = "macros")]
pub use bleps_macros::gatt;

#[cfg(all(feature = "sync", feature = "async"))]
compile_error!("sync and async are conflict!, choose one");

const TIMEOUT_MILLIS: u64 = 1000;

#[derive(Debug)]
pub enum Error {
    Timeout,
    Failed(u8),
}

#[cfg(feature = "defmt")]
impl defmt::Format for Error {
    fn format(&self, fmt: defmt::Formatter) {
        match self {
            Error::Timeout => {
                defmt::write!(fmt, "Timeout")
            }
            Error::Failed(value) => {
                defmt::write!(fmt, "Failed({})", value)
            }
        }
    }
}

#[derive(Debug)]
pub enum PollResult {
    Event(EventPacket),
    AsyncData(ACLDataPacket),
}

#[derive(Debug, Clone, Copy)]
pub enum AdvertisingType {
    AdvInd = 0x00,
    AdvDirectInd = 0x01,
    AdvScanInd = 0x02,
    AdvNonConnInd = 0x03,
    AdvDirectIndLowDuty = 0x04,
}

#[derive(Debug, Clone, Copy)]
pub enum OwnAddressType {
    Public = 0x00,
    Random = 0x01,
    ResolvablePrivateAddress = 0x02,
    ResolvablePrivateAddressFromIRK = 0x03,
}

#[derive(Debug, Clone, Copy)]
pub enum PeerAddressType {
    Public = 0x00,
    Random = 0x01,
}

#[derive(Debug, Clone, Copy)]
pub enum AdvertisingChannelMapBits {
    Channel37 = 0b001,
    Channel38 = 0b010,
    Channel39 = 0b100,
}

#[derive(Debug, Clone, Copy)]
pub enum AdvertisingFilterPolicy {
    All = 0x00,
    FilteredScanAllConnect = 0x01,
    AllScanFilteredConnect = 0x02,
    Filtered = 0x03,
}

#[derive(Debug, Clone, Copy)]
pub struct AdvertisingParameters {
    pub advertising_interval_min: u16,
    pub advertising_interval_max: u16,
    pub advertising_type: AdvertisingType,
    pub own_address_type: OwnAddressType,
    pub peer_address_type: PeerAddressType,
    pub peer_address: [u8; 6],
    pub advertising_channel_map: u8,
    pub filter_policy: AdvertisingFilterPolicy,
}

const PACKET_TYPE_COMMAND: u8 = 0x01;
const PACKET_TYPE_ASYNC_DATA: u8 = 0x02;
const PACKET_TYPE_EVENT: u8 = 0x04;

pub struct Ble<T, F> {
    pub hci: RefCell<T>,
    pub get_millis: F,
}

impl<T, F> Ble<T, F>
    where T: Read + Write,
          F: Fn()->u64
    {

    pub fn new(hci: T, get_millis: F) -> Self {
        Self {
            hci: RefCell::new(hci),
            get_millis,
        }
    }

    fn millis(&self) -> u64 {
        (self.get_millis)()
    }

    pub fn init(&mut self) -> Result<(), Error>
    where
        Self: Sized,
    {
        self.cmd_reset()?;
        self.cmd_set_event_mask([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff])?;
        Ok(())
    }

    pub fn cmd_reset(&mut self) -> Result<EventPacket, Error>
    where
        Self: Sized,
    {
        self.write_bytes(Command::Reset.encode().as_slice());
        self.wait_for_command_complete(CONTROLLER_OGF, RESET_OCF)?
            .check_cmd_completed()
    }

    pub fn cmd_set_event_mask(&mut self, events: [u8; 8]) -> Result<EventPacket, Error>
    where
        Self: Sized,
    {
        self.write_bytes(Command::SetEventMask { events }.encode().as_slice());
        self.wait_for_command_complete(CONTROLLER_OGF, SET_EVENT_MASK_OCF)?
            .check_cmd_completed()
    }

    pub fn cmd_set_le_advertising_parameters(&mut self) -> Result<EventPacket, Error>
    where
        Self: Sized,
    {
        self.write_bytes(Command::LeSetAdvertisingParameters.encode().as_slice());
        self.wait_for_command_complete(LE_OGF, SET_ADVERTISING_PARAMETERS_OCF)?
            .check_cmd_completed()
    }

    pub fn cmd_set_le_advertising_parameters_custom(
        &mut self,
        params: &AdvertisingParameters,
    ) -> Result<EventPacket, Error>
    where
        Self: Sized,
    {
        self.write_bytes(
            Command::LeSetAdvertisingParametersCustom(params)
                .encode()
                .as_slice(),
        );
        self.wait_for_command_complete(LE_OGF, SET_ADVERTISING_PARAMETERS_OCF)?
            .check_cmd_completed()
    }

    pub fn cmd_set_le_advertising_data(&mut self, data: Data) -> Result<EventPacket, Error>
    where
        Self: Sized,
    {
        self.write_bytes(Command::LeSetAdvertisingData { data }.encode().as_slice());
        self.wait_for_command_complete(LE_OGF, SET_ADVERTISING_DATA_OCF)?
            .check_cmd_completed()
    }

    pub fn cmd_set_le_scan_rsp_data(&mut self, data: Data) -> Result<EventPacket, Error>
    where
        Self: Sized,
    {
        self.write_bytes(Command::LeSetScanRspData { data }.encode().as_slice());
        self.wait_for_command_complete(LE_OGF, SET_SCAN_RSP_DATA_OCF)?
            .check_cmd_completed()
    }

    pub fn cmd_set_le_advertise_enable(&mut self, enable: bool) -> Result<EventPacket, Error>
    where
        Self: Sized,
    {
        self.write_bytes(Command::LeSetAdvertiseEnable(enable).encode().as_slice());
        self.wait_for_command_complete(LE_OGF, SET_ADVERTISE_ENABLE_OCF)?
            .check_cmd_completed()
    }

    pub fn cmd_long_term_key_request_reply(
        &mut self,
        handle: u16,
        ltk: u128,
    ) -> Result<EventPacket, Error>
    where
        Self: Sized,
    {
        trace!("before, key = {:x}, hanlde = {:x}", ltk, handle);
        self.write_bytes(
            Command::LeLongTermKeyRequestReply { handle, ltk }
                .encode()
                .as_slice(),
        );
        trace!("done writing command");
        let res = self
            .wait_for_command_complete(LE_OGF, LONG_TERM_KEY_REQUEST_REPLY_OCF)?
            .check_cmd_completed();
        trace!("got completion event");

        res
    }

    pub fn cmd_read_br_addr(&mut self) -> Result<[u8; 6], Error>
    where
        Self: Sized,
    {
        self.write_bytes(Command::ReadBrAddr.encode().as_slice());
        let res = self
            .wait_for_command_complete(INFORMATIONAL_OGF, READ_BD_ADDR_OCF)?
            .check_cmd_completed()?;
        match res {
            EventPacket::CommandComplete {
                num_hci_command_packets: _,
                command_opcode: _,
                return_parameters: data,
                ..
            } => Ok(data.as_slice()[1..][..6].try_into().unwrap()),
            _ => Err(Error::Failed(0)),
        }
    }

    fn wait_for_command_complete(&mut self, ogf: u8, ocf: u16) -> Result<EventPacket, Error>
    where
        Self: Sized,
    {
        let timeout_at = self.millis() + TIMEOUT_MILLIS;
        loop {
            let res = self.poll();
            if res.is_some() {
                debug!("polled while waiting {:?}", res);
            }

            match res {
                Some(PollResult::Event(event)) => match event {
                    EventPacket::CommandComplete {
                        command_opcode: code,
                        ..
                    } if code == opcode(ogf, ocf) => {
                        return Ok(event);
                    }
                    _ => (),
                },
                _ => (),
            }

            if self.millis() > timeout_at {
                return Err(Error::Timeout);
            }
        }
    }

    pub fn poll(&mut self) -> Option<PollResult>
    where
        Self: Sized,
    {
        // poll & process input
        let packet_type = {
            let mut buffer = [0u8];
            let l = self.hci.borrow_mut().read(&mut buffer).unwrap();
            if l == 0 {
                None
            } else {
                Some(buffer[0])
            }
        };

        match packet_type {
            Some(packet_type) => match packet_type {
                PACKET_TYPE_COMMAND => {}
                PACKET_TYPE_ASYNC_DATA => {
                    let acl_packet = ACLDataPacket::read(&mut *self.hci.borrow_mut());
                    return Some(PollResult::AsyncData(acl_packet));
                }
                PACKET_TYPE_EVENT => {
                    let event = EventPacket::read(&mut *self.hci.borrow_mut());
                    return Some(PollResult::Event(event));
                }
                _ => {
                    // this is a serious error
                    panic!("Unknown packet type {}", packet_type);
                }
            },
            None => {}
        }

        None
    }

    fn write_bytes(&mut self, bytes: &[u8]) {
        self.hci.borrow_mut().write(bytes).unwrap();
    }
}

#[cfg(feature = "async")]
pub mod asynch {
    use super::*;

    impl<T, F> Ble<T, F>
    where
        T: Read + Write,
        F: Fn() -> u64,
    {
        pub fn new(hci: T, get_millis: fn() -> u64) -> Self {
            Self {
                hci: RefCell::new(hci),
                get_millis,
            }
        }

        fn millis(&self) -> u64 {
            (self.get_millis)()
        }

        pub async fn init(&mut self) -> Result<EventPacket, Error>
        where
            Self: Sized,
        {
            let res = self.cmd_reset().await?;
            self.cmd_set_event_mask([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff])
                .await?;
            Ok(res)
        }

        pub async fn cmd_reset(&mut self) -> Result<EventPacket, Error>
        where
            Self: Sized,
        {
            self.write_bytes(Command::Reset.encode().as_slice()).await;
            self.wait_for_command_complete(CONTROLLER_OGF, RESET_OCF)
                .await?
                .check_cmd_completed()
        }

        pub async fn cmd_set_event_mask(&mut self, events: [u8; 8]) -> Result<EventPacket, Error>
        where
            Self: Sized,
        {
            self.write_bytes(Command::SetEventMask { events }.encode().as_slice())
                .await;
            self.wait_for_command_complete(CONTROLLER_OGF, SET_EVENT_MASK_OCF)
                .await?
                .check_cmd_completed()
        }

        pub async fn cmd_set_le_advertising_parameters(&mut self) -> Result<EventPacket, Error>
        where
            Self: Sized,
        {
            self.write_bytes(Command::LeSetAdvertisingParameters.encode().as_slice())
                .await;
            self.wait_for_command_complete(LE_OGF, SET_ADVERTISING_PARAMETERS_OCF)
                .await?
                .check_cmd_completed()
        }

        pub async fn cmd_set_le_advertising_parameters_custom(
            &mut self,
            params: &AdvertisingParameters,
        ) -> Result<EventPacket, Error>
        where
            Self: Sized,
        {
            self.write_bytes(
                Command::LeSetAdvertisingParametersCustom(params)
                    .encode()
                    .as_slice(),
            )
            .await;
            self.wait_for_command_complete(LE_OGF, SET_ADVERTISING_PARAMETERS_OCF)
                .await?
                .check_cmd_completed()
        }

        pub async fn cmd_set_le_advertising_data(
            &mut self,
            data: Data,
        ) -> Result<EventPacket, Error>
        where
            Self: Sized,
        {
            self.write_bytes(Command::LeSetAdvertisingData { data }.encode().as_slice())
                .await;
            self.wait_for_command_complete(LE_OGF, SET_ADVERTISING_DATA_OCF)
                .await?
                .check_cmd_completed()
        }

        pub async fn cmd_set_le_advertise_enable(
            &mut self,
            enable: bool,
        ) -> Result<EventPacket, Error>
        where
            Self: Sized,
        {
            self.write_bytes(Command::LeSetAdvertiseEnable(enable).encode().as_slice())
                .await;
            self.wait_for_command_complete(LE_OGF, SET_ADVERTISE_ENABLE_OCF)
                .await?
                .check_cmd_completed()
        }

        pub async fn cmd_long_term_key_request_reply(
            &mut self,
            handle: u16,
            ltk: u128,
        ) -> Result<EventPacket, Error>
        where
            Self: Sized,
        {
            trace!("before, key = {:x}, handle = {:x}", ltk, handle);
            self.write_bytes(
                Command::LeLongTermKeyRequestReply { handle, ltk }
                    .encode()
                    .as_slice(),
            )
            .await;
            trace!("done writing command");
            let res = self
                .wait_for_command_complete(LE_OGF, LONG_TERM_KEY_REQUEST_REPLY_OCF)
                .await?
                .check_cmd_completed();
            trace!("got completion event");

            res
        }

        pub async fn cmd_read_br_addr(&mut self) -> Result<[u8; 6], Error>
        where
            Self: Sized,
        {
            self.write_bytes(Command::ReadBrAddr.encode().as_slice())
                .await;
            let res = self
                .wait_for_command_complete(INFORMATIONAL_OGF, READ_BD_ADDR_OCF)
                .await?
                .check_cmd_completed()?;
            match res {
                EventPacket::CommandComplete {
                    num_hci_command_packets: _,
                    command_opcode: _,
                    return_parameters,
                    ..
                } => Ok(return_parameters.as_slice()[1..][..6].try_into().unwrap()),
                _ => Err(Error::Failed(0)),
            }
        }

        pub(crate) async fn wait_for_command_complete(
            &mut self,
            ogf: u8,
            ocf: u16,
        ) -> Result<EventPacket, Error>
        where
            Self: Sized,
        {
            let timeout_at = self.millis() + TIMEOUT_MILLIS;
            loop {
                let res = self.poll().await;

                match res {
                    Some(PollResult::Event(event)) => match event {
                        EventPacket::CommandComplete {
                            command_opcode: code,
                            ..
                        } if code == opcode(ogf, ocf) => {
                            return Ok(event);
                        }
                        _ => (),
                    },
                    _ => (),
                }

                if self.millis() > timeout_at {
                    return Err(Error::Timeout);
                }
            }
        }

        pub async fn poll(&mut self) -> Option<PollResult>
        where
            Self: Sized,
        {
            // poll & process input
            let packet_type = {
                let mut buffer = [0u8];
                let l = self.hci.borrow_mut().read(&mut buffer).await.unwrap();
                if l == 0 {
                    None
                } else {
                    Some(buffer[0])
                }
            };

            match packet_type {
                Some(packet_type) => match packet_type {
                    PACKET_TYPE_COMMAND => {}
                    PACKET_TYPE_ASYNC_DATA => {
                        let mut acl_packet =
                            AclPacket::async_read(&mut *self.hci.borrow_mut()).await;

                        let wanted =
                            u16::from_le_bytes(acl_packet.data.as_slice()[..2].try_into().unwrap())
                                as usize;

                        // somewhat dirty way to handle re-assembling fragmented packets
                        loop {
                            debug!("Wanted = {}, actual = {}", wanted, acl_packet.data.len());

                            if wanted == acl_packet.data.len() - 4 {
                                break;
                            }

                            debug!("Need more!");
                            let mut buffer = [0u8; 1];
                            (&mut *self.hci.borrow_mut())
                                .read(&mut buffer)
                                .await
                                .unwrap();
                            if buffer[0] != PACKET_TYPE_ASYNC_DATA {
                                error!("Expected async data");
                            }

                            let next_acl_packet =
                                AclPacket::async_read(&mut *self.hci.borrow_mut()).await;
                            acl_packet.data.append(next_acl_packet.data.as_slice());
                        }

                        return Some(PollResult::AsyncData(acl_packet));
                    }
                    PACKET_TYPE_EVENT => {
                        let event = EventPacket::async_read(&mut *self.hci.borrow_mut()).await;
                        return Some(PollResult::Event(event));
                    }
                    _ => {
                        // this is an serious error
                        panic!("Unknown packet type {}", packet_type);
                    }
                },
                None => {}
            }

            None
        }

        pub(crate) async fn write_bytes(&mut self, bytes: &[u8]) {
            self.hci.borrow_mut().write(bytes).await.unwrap();
        }
    }

    impl Data {
        pub(crate) async fn async_read<T>(mut connector: T, len: usize) -> Self
        where
            T: embedded_io_async::Read,
        {
            let mut idx = 0;
            let mut data = [0u8; 256];
            loop {
                let l = connector.read(&mut data[idx..][..len]).await.unwrap();
                idx += l;

                if idx >= len {
                    break;
                }

                // TODO timeout?
            }

            let mut data = Self::new(&data);
            data.len = len;
            data
        }
    }
}
