use anyhow::Result;
use bincode::{
    config::{BigEndian, WithOtherEndian},
    DefaultOptions, Options,
};
use rand::Rng;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Default)]
pub struct DNSHeader {
    pub id: u16,
    pub flags: u16,
    pub num_questions: u16,
    pub num_answers: u16,
    pub num_authorities: u16,
    pub num_additionals: u16,
}

#[derive(Serialize, Deserialize)]
pub struct DNSQuestion {
    pub name: Vec<u8>,
    pub kind: u16,
    pub class: u16,
}

#[repr(u16)]
pub enum RecordType {
    A = 1,
}

#[repr(u16)]
pub enum Class {
    In = 1,
}

pub fn build_query(domain_name: &str, record_type: RecordType) -> Result<Vec<u8>> {
    let name = encode_dns_name(domain_name)?;
    let id = {
        let mut rng = rand::thread_rng();
        rng.gen_range(0..=65535)
    };
    let recursion_desired = 1 << 8;
    let header = DNSHeader {
        id,
        flags: recursion_desired,
        ..Default::default()
    };
    let question = DNSQuestion {
        name,
        kind: record_type as u16,
        class: Class::In as u16,
    };

    let config = DefaultOptions::new().with_big_endian();

    let mut bytes = header_to_bytes(header, config)?;
    bytes.extend_from_slice(&question_to_bytes(question, config)?);

    Ok(bytes)
}

fn header_to_bytes(
    header: DNSHeader,
    config: WithOtherEndian<DefaultOptions, BigEndian>,
) -> Result<Vec<u8>> {
    config.serialize(&header).map_err(|e| anyhow::anyhow!(e))
}

fn question_to_bytes(
    question: DNSQuestion,
    config: WithOtherEndian<DefaultOptions, BigEndian>,
) -> Result<Vec<u8>> {
    config.serialize(&question).map_err(|e| anyhow::anyhow!(e))
}

fn encode_dns_name(name: &str) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    for label in name.split('.') {
        bytes.push(label.len() as u8);
        bytes.extend_from_slice(label.as_bytes());
    }
    bytes.push(0);
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use crate::{build_query, encode_dns_name, RecordType};

    #[test]
    fn test_encode_dns_name() {
        let encoded = encode_dns_name("google.com").unwrap();
        assert_eq!(encoded[0], 6);
    }

    #[test]
    fn test_build_query() {
        let query = build_query("www.example.com", RecordType::A).unwrap();
        println!("{:x?}", query);
    }
}
