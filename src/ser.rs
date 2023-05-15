use crate::Result;

use std::io::Write;

pub trait Serialize {
    fn serialize<W: Write>(&self, w: &mut W) -> Result<()>;
}
