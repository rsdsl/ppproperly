use bitfield::bitfield;

bitfield! {
    /// Version and type of a PPPoE header combined in a single octet.
    pub struct VerType(u8);
    impl Debug;

    u8;

    pub ver, set_ver: 7, 4;
    pub ty, set_ty: 3, 0;
}

impl Default for VerType {
    fn default() -> Self {
        Self(0x11)
    }
}
