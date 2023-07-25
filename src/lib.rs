use std::io::{BufRead, Cursor, Read};

use anyhow::Result;
use deku::prelude::*;
use rand::Rng;

pub mod consts {
    pub const DNS_BUF_SIZE: usize = 1024;
    pub const HEADER_SIZE: usize = 12;
}

#[derive(Debug, Default, DekuWrite)]
#[deku(endian = "big")]
pub struct DNSHeader {
    pub id: u16,
    pub flags: u16,
    pub num_questions: u16,
    pub num_answers: u16,
    pub num_authorities: u16,
    pub num_additionals: u16,
}

impl TryFrom<&[u8]> for DNSHeader {
    type Error = anyhow::Error;

    fn try_from(buf: &[u8]) -> Result<Self> {
        Ok(DNSHeader {
            id: u16::from_be_bytes(buf[0..2].try_into()?),
            flags: u16::from_be_bytes(buf[2..4].try_into()?),
            num_questions: u16::from_be_bytes(buf[4..6].try_into()?),
            num_answers: u16::from_be_bytes(buf[6..8].try_into()?),
            num_authorities: u16::from_be_bytes(buf[8..10].try_into()?),
            num_additionals: u16::from_be_bytes(buf[10..12].try_into()?),
        })
    }
}

pub fn parse_header(reader: &mut Cursor<&[u8; consts::DNS_BUF_SIZE]>) -> Result<DNSHeader> {
    let header = &mut [0; consts::HEADER_SIZE];
    reader.read_exact(header)?;
    let header: &[u8] = header;
    DNSHeader::try_from(header)
}

#[derive(Debug, Default, DekuWrite)]
#[deku(endian = "big")]
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

    let mut bytes = header_to_bytes(header)?;
    bytes.extend_from_slice(&question_to_bytes(question)?);

    Ok(bytes)
}

fn header_to_bytes(header: DNSHeader) -> Result<Vec<u8>> {
    header.to_bytes().map_err(|e| anyhow::anyhow!(e))
}

fn question_to_bytes(question: DNSQuestion) -> Result<Vec<u8>> {
    question.to_bytes().map_err(|e| anyhow::anyhow!(e))
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
    use std::{
        io::Cursor,
        net::{Ipv4Addr, UdpSocket},
    };

    use crate::{
        build_query, consts, encode_dns_name, header_to_bytes, parse_header, DNSHeader, RecordType,
    };
    use deku::prelude::*;

    #[test]
    fn test_header() {
        let target = DNSHeader {
            id: 0x1314,
            flags: 000000000,
            num_questions: 1,
            num_answers: 0,
            num_authorities: 0,
            num_additionals: 0,
        };
        let target = header_to_bytes(target).unwrap();

        let another = DNSHeader {
            id: 0x1314,
            flags: 000000000,
            num_questions: 1,
            num_answers: 0,
            num_authorities: 0,
            num_additionals: 0,
        };
        let another = another.to_bytes();

        println!("target  = {:02x?}", target);
        println!("another = {:02x?}", another);
    }

    #[test]
    fn test_encode_dns_name() {
        let encoded = encode_dns_name("google.com").unwrap();
        assert_eq!(encoded[0], 6);
    }

    #[test]
    fn test_build_query() {
        let query = build_query("www.example.com", RecordType::A).unwrap();
        println!("query = {:02x?}", query);
    }

    #[test]
    fn send_udp_request_to_google_dns_server_and_get_the_response() {
        let query = build_query("www.example.com", RecordType::A).unwrap();

        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();

        // Send our query to 8.8.8.8, port 53. Port 53 is the DNS port.
        socket.send_to(&query, ("8.8.8.8", 53)).unwrap();

        // Read the response. UDP DNS responses are usually less than 512 bytes
        // (see https://www.netmeister.org/blog/dns-size.html for MUCH more on that)
        // so reading 1024 bytes is enough
        let mut response = [0; consts::DNS_BUF_SIZE];
        let (_, _) = socket.recv_from(&mut response).unwrap();

        // Process the response as needed
        println!("Response: {:x?}", &response);

        let mut cur = Cursor::new(&response);
        println!("{:?}", parse_header(&mut cur));
        println!("{:?}", cur.position());
    }
}
