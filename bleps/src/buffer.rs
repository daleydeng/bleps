use crate::Data;

impl Data {
    pub fn new(bytes: &[u8]) -> Data {
        let n = bytes.len();
        let mut data = [0u8; 256];
        data[..n].copy_from_slice(bytes);
        Data { data, len: n }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data[0..self.len]
    }

    pub fn as_slice_mut(&mut self) -> &mut [u8] {
        &mut self.data[self.len..]
    }

    pub fn set_len(&mut self, new_len: usize) {
        self.len = if new_len > self.data.len() {
            self.data.len()
        } else {
            new_len
        };
    }

    pub fn set(&mut self, index: usize, byte: u8) {
        self.data[index] = byte;
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn append_len(&mut self, extra_len: usize) {
        self.set_len(self.len + extra_len);
    }

    pub fn limit_len(&mut self, max_len: usize) {
        if self.len > max_len {
            self.len = max_len;
        }
    }

    pub fn subdata_from(&self, from: usize) -> Data {
        let mut data = [0u8; 256];
        let new_len = self.len - from;
        data[..new_len].copy_from_slice(&self.data[from..self.len]);
        Data { data, len: new_len }
    }

    pub fn append(&mut self, bytes: &[u8]) {
        self.data[self.len..(self.len + bytes.len())].copy_from_slice(bytes);
        self.len += bytes.len();
    }

    pub fn append_value<T: Sized + 'static>(&mut self, value: T) {
        let slice = unsafe {
            core::slice::from_raw_parts(&value as *const _ as *const _, core::mem::size_of::<T>())
        };

        #[cfg(target_endian = "little")]
        self.append(slice);

        #[cfg(target_endian = "big")]
        {
            let top = slice.len() - 1;
            for (index, byte) in slice.iter().enumerate() {
                self.set(top - index, *byte);
            }
            self.append_len(slice.len());
        }
    }
}
