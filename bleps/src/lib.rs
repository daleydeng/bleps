#![no_std]

#[macro_use]
extern crate alloc;

use heapless::{Vec, String};

#[cfg(not(feature = "defmt"))]
use log::{debug, trace};
#[cfg(feature = "defmt")]
use defmt::{panic, debug, trace};

#[cfg(all(feature = "log", feature = "defmt"))]
compile_error!("log and defmt can't have both!");

use maybe_async::maybe_async;
use thiserror_no_std::Error;
use types::{encode, ACLDataPacket, AdvertisingFilterPolicy, AdvertisingParameters, AdvertisingType, CommandPacket, ControllerError, HCIPacket, OwnAddressType, PeerAddressType, CMD_LE_ADV_DATA_MAX_SIZE};
use core::cell::RefCell;

use command::{
    opcode, INFORMATIONAL_OGF, LONG_TERM_KEY_REQUEST_REPLY_OCF, READ_BD_ADDR_OCF,
    SET_ADVERTISE_ENABLE_OCF, SET_ADVERTISING_DATA_OCF, SET_EVENT_MASK_OCF, SET_SCAN_RSP_DATA_OCF,
};
use command::{CONTROLLER_OGF, LE_OGF, RESET_OCF, SET_ADVERTISING_PARAMETERS_OCF};
pub use types::{Data, EventPacket};

pub mod ad_structure;
pub mod att;
pub mod buffer;
pub mod command;
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

#[derive(Error, Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum BleError {
    #[error("Timeout")]
    Timeout,
    #[error("Controller Error: {}", .0)]
    CtrlErr(#[from] ControllerError),
    #[error("Unknown Error")]
    Unknown(String<64>),
}

#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum PollResult {
    Event(EventPacket),
    AsyncData(ACLDataPacket),
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
}

#[maybe_async]
impl<T, F> Ble<T, F>
where T: Read + Write,
        F: Fn()->u64
{
    pub async fn init(&mut self) -> Result<(), BleError>
    where
        Self: Sized,
    {
        self.cmd_reset().await?;
        self.cmd_set_event_mask(0xffff_ffff_ffff_ffffu64).await?;
        Ok(())
    }

    pub async fn cmd_reset(&mut self) -> Result<EventPacket, BleError>
    where
        Self: Sized,
    {
        let cmd = HCIPacket::Command(CommandPacket::Reset{});
        self.write_bytes(cmd.encode().as_slice()).await;
        self.wait_for_command_complete(CONTROLLER_OGF, RESET_OCF).await
    }

    pub async fn cmd_set_event_mask(&mut self, event_mask: u64) -> Result<EventPacket, BleError>
    where
        Self: Sized,
    {
        let cmd = HCIPacket::Command(CommandPacket::SetEventMask { event_mask });
        self.write_bytes(cmd.encode().as_slice()).await;
        self.wait_for_command_complete(CONTROLLER_OGF, SET_EVENT_MASK_OCF).await
    }

    pub async fn cmd_set_le_advertising_parameters(&mut self) -> Result<EventPacket, BleError>
    where
        Self: Sized,
    {
        let params = AdvertisingParameters::default();
        let cmd = HCIPacket::Command(CommandPacket::LeSetAdvertisingParameters {
            params
        });
        self.write_bytes(cmd.encode().as_slice()).await;
        self.wait_for_command_complete(LE_OGF, SET_ADVERTISING_PARAMETERS_OCF).await
    }

    pub async fn cmd_set_le_advertising_parameters_custom(
        &mut self,
        params: &AdvertisingParameters,
    ) -> Result<EventPacket, BleError>
    where
        Self: Sized,
    {
        let cmd = HCIPacket::Command(CommandPacket::LeSetAdvertisingParameters {
            params: *params,
        });
        self.write_bytes(cmd.encode().as_slice()).await;
        self.wait_for_command_complete(LE_OGF, SET_ADVERTISING_PARAMETERS_OCF).await
    }

    pub async fn cmd_set_le_advertising_data(&mut self, data: Data) -> Result<EventPacket, BleError>
    where
        Self: Sized,
    {
        let data = Vec::from_slice(data.as_slice()).expect(
            &format!("data size({}) > limit({})", data.len(), CMD_LE_ADV_DATA_MAX_SIZE));
        let cmd = HCIPacket::Command(CommandPacket::LeSetAdvertisingData {
            data
        });
        self.write_bytes(cmd.encode().as_slice()).await;
        self.wait_for_command_complete(LE_OGF, SET_ADVERTISING_DATA_OCF).await
    }

    pub async fn cmd_set_le_scan_rsp_data(&mut self, data: Data) -> Result<EventPacket, BleError>
    where
        Self: Sized,
    {
        let cmd = HCIPacket::Command(CommandPacket::LeSetScanRspData {
            data: Vec::from_slice(data.as_slice()).unwrap(),
        });
        self.write_bytes(cmd.encode().as_slice()).await;
        self.wait_for_command_complete(LE_OGF, SET_SCAN_RSP_DATA_OCF).await
    }

    pub async fn cmd_set_le_advertise_enable(&mut self, enable: bool) -> Result<EventPacket, BleError>
    where
        Self: Sized,
    {
        let cmd = HCIPacket::Command(CommandPacket::LeSetAdvertiseEnable { enable });
        self.write_bytes(cmd.encode().as_slice()).await;
        self.wait_for_command_complete(LE_OGF, SET_ADVERTISE_ENABLE_OCF).await
    }

    pub async fn cmd_long_term_key_request_reply(
        &mut self,
        handle: u16,
        ltk: u128,
    ) -> Result<EventPacket, BleError>
    where
        Self: Sized,
    {
        trace!("before, key = {:x}, hanlde = {:x}", ltk, handle);
        let cmd = HCIPacket::Command(CommandPacket::LeLongTermKeyRequestReply {
            connection_handle: handle,
            ltk
        });
        self.write_bytes(cmd.encode().as_slice()).await;
        trace!("done writing command");
        let res = self
            .wait_for_command_complete(LE_OGF, LONG_TERM_KEY_REQUEST_REPLY_OCF).await?;
        trace!("got completion event");

        Ok(res)
    }

    pub async fn cmd_read_br_addr(&mut self) -> Result<[u8; 6], BleError>
    where
        Self: Sized,
    {
        let cmd = HCIPacket::Command(CommandPacket::ReadBdAddr {});
        self.write_bytes(cmd.encode().as_slice()).await;
        let res = self
            .wait_for_command_complete(INFORMATIONAL_OGF, READ_BD_ADDR_OCF).await?;

        match res {
            EventPacket::CommandComplete {
                num_hci_command_packets: _,
                command_opcode: _,
                return_parameters: data,
                ..
            } => Ok(data.as_slice()[1..][..6].try_into().unwrap()),
            val => Err(BleError::Unknown(
                format!("EventType is not Command Complete {:?}", val).as_str().try_into().unwrap()
            )),
        }
    }

    async fn wait_for_command_complete(&mut self, ogf: u8, ocf: u16) -> Result<EventPacket, BleError>
    where
        Self: Sized,
    {
        let timeout_at = self.millis() + TIMEOUT_MILLIS;
        loop {
            let res = self.poll().await;
            if res.is_some() {
                debug!("polled while waiting {:?}", res);
            }

            match res {
                Some(PollResult::Event(ref event)) => match event {
                    EventPacket::CommandComplete {
                        command_opcode,
                        return_parameters,
                        ..
                    } => {
                        if command_opcode == &opcode(ogf, ocf) {
                            let status = return_parameters[0];
                            if status == 0 {
                                return Ok(event.clone());
                            }
                            return match status.try_into() {
                                Ok(e) => Err(BleError::CtrlErr(e)),
                                Err(_) => Err(BleError::Unknown(
                                    format!("Opcode({}) unknown Status({})", command_opcode, status)
                                    .as_str().try_into().unwrap()
                                )),
                            };
                        } else {
                            return Err(BleError::Unknown(
                                format!("unknown Opcode({})", command_opcode)
                                .as_str().try_into().unwrap()));
                        }
                    }
                    _ => (),
                },
                _ => (),
            }

            if self.millis() > timeout_at {
                return Err(BleError::Timeout);
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
                    let acl_packet = ACLDataPacket::read(&mut *self.hci.borrow_mut()).await;
                    return Some(PollResult::AsyncData(acl_packet));
                }
                PACKET_TYPE_EVENT => {
                    let event = EventPacket::read(&mut *self.hci.borrow_mut()).await;
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

    async fn write_bytes(&mut self, bytes: &[u8]) {
        self.hci.borrow_mut().write(bytes).await.unwrap();
    }
}
