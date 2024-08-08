use binrw::io::Cursor;
use binrw::{BinRead, BinWrite};

use crate::Read;
use crate::types::{ACLBoundaryFlag, ACLBroadcastFlag, ACLDataPacket, ACLDataPacketHeader, ACLPacketBuffer, ACLPayloadBuffer, ACL_PKT_HEADER_SIZE, ACL_PKT_MAX_SIZE};

impl ACLDataPacket {
    pub fn new(handle: u16, pb: ACLBoundaryFlag, bc: ACLBroadcastFlag, payload: &[u8]) -> Self {
        Self {
            header: ACLDataPacketHeader::new()
                .with_handle(handle)
                .with_packet_boundary_flag(pb)
                .with_broadcast_flag(bc),
            len: payload.len() as u16,
            data: ACLPayloadBuffer::from_slice(payload).unwrap(),
        }
    }

    pub fn encode(&self) -> ACLPacketBuffer {
        let mut buf = [0u8; ACL_PKT_MAX_SIZE];
        let mut writer = Cursor::new(&mut buf[..]);
        self.write(&mut writer).unwrap();
        let len = writer.position() as usize;
        ACLPacketBuffer::from_slice(&buf[..len]).unwrap()
    }

    #[maybe_async::maybe_async]
    pub fn read<T: Read>(connector: &mut T) -> Self {
        let mut buffer = [0u8; ACL_PKT_MAX_SIZE];
        let l = connector.read(&mut buffer[..4]).await.unwrap();
        assert_eq!(l, ACL_PKT_HEADER_SIZE);
        let len = u16::from_le_bytes(buffer[2..4].try_into().unwrap()) as usize;
        assert!(len <= 27);
        let tot_len = len + 4;
        let l = connector.read(&mut buffer[4..tot_len]).await.unwrap();
        assert_eq!(l, len);
        <Self as BinRead>::read(&mut Cursor::new(&buffer[..tot_len])).unwrap()
    }
}
