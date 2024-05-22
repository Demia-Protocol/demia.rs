#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
/// Tag used in data payload to identify block
pub struct TagId(Vec<u8>);

impl ToString for TagId {
    fn to_string(&self) -> String {
        prefix_hex::encode(self.0.clone())
    }
}

impl From<Vec<u8>> for TagId {
    fn from(bytes: Vec<u8>) -> Self {
        TagId(bytes)
    }
}
