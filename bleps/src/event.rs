extern crate alloc;
use crate::types::{EventPacket, EVENT_PKT_PAYLOAD_MAX_SIZE};
use crate::{Error, Read};
use binrw::io::Cursor;
use binrw::BinRead;

impl EventPacket {
    pub fn check_cmd_completed(self) -> Result<Self, Error> {
        if let Self::CommandComplete {return_parameters, .. } = &self {
            let status = return_parameters[0];
            if status != 0 {
                return Err(Error::Failed(status));
            }
        }
        Ok(self)
    }

    #[maybe_async::maybe_async]
    pub async fn read<T: Read>(connector: &mut T) -> Self {
        let mut buffer = [0u8; EVENT_PKT_PAYLOAD_MAX_SIZE];
        let l = connector.read(&mut buffer[..2]).await.unwrap();
        assert_eq!(l, 2);
        let len = buffer[1] as usize;

        let l = connector.read(&mut buffer[2..len+2]).await.unwrap();
        assert_eq!(l, len);

        <Self as BinRead>::read(&mut Cursor::new(&buffer[..len+2])).unwrap()
    }
}
