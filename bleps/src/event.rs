extern crate alloc;
use crate::types::{ControllerError, EventPacket, EVT_PKT_PAYLOAD_MAX_SIZE};
use crate::{BleError, Read};
use binrw::io::Cursor;
use binrw::BinRead;

impl EventPacket {
    #[maybe_async::maybe_async]
    pub async fn read<T: Read>(connector: &mut T) -> Self {
        let mut buffer = [0u8; EVT_PKT_PAYLOAD_MAX_SIZE];
        let l = connector.read(&mut buffer[..2]).await.unwrap();
        assert_eq!(l, 2);
        let len = buffer[1] as usize;

        let l = connector.read(&mut buffer[2..len+2]).await.unwrap();
        assert_eq!(l, len);

        <Self as BinRead>::read(&mut Cursor::new(&buffer[..len+2])).unwrap()
    }
}
