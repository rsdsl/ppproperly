use crate::Result;

use std::io::Read;

pub trait Deserialize {
    fn deserialize<R: Read>(&mut self, r: R) -> Result<()>;
}
