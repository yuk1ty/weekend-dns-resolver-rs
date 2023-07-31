use std::{
    io::{Cursor, Read},
    net::{Ipv4Addr, UdpSocket},
};

use anyhow::Result;
use deku::prelude::*;
use num_enum::TryFromPrimitive;
use rand::Rng;

pub mod consts {
    pub const DNS_BUF_SIZE: usize = 1024;
    pub const HEADER_SIZE: usize = 12;
    pub const QUESTION_DATA_SIZE: usize = 4;
}

pub fn lookup_domain(domain_name: &str) -> Result<Ipv4Addr> {
    let query = build_query(domain_name, RecordType::A)?;

    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
    socket.send_to(&query, ("8.8.8.8", 53)).unwrap();

    let mut response = [0; consts::DNS_BUF_SIZE];
    let (_, _) = socket.recv_from(&mut response).unwrap();

    let packet = parse_dns_packet(&response)?;
    let [octet1, octet2, octet3, octet4, ..] = packet.answers[0].data[0..4] else { return Err(anyhow::anyhow!("data is not correct format!")); };

    Ok(Ipv4Addr::new(octet1, octet2, octet3, octet4))
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

fn parse_header<const SIZE: usize>(reader: &mut Cursor<&[u8; SIZE]>) -> Result<DNSHeader> {
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

impl TryFrom<(Vec<u8>, &[u8])> for DNSQuestion {
    type Error = anyhow::Error;

    fn try_from((name, data): (Vec<u8>, &[u8])) -> std::result::Result<Self, Self::Error> {
        Ok(DNSQuestion {
            name,
            kind: u16::from_be_bytes(data[0..2].try_into()?),
            class: u16::from_be_bytes(data[2..4].try_into()?),
        })
    }
}

fn parse_question<const SIZE: usize>(reader: &mut Cursor<&[u8; SIZE]>) -> Result<DNSQuestion> {
    let name = decode_name(reader)?;
    let data = &mut [0; consts::QUESTION_DATA_SIZE];
    reader.read_exact(data)?;
    let data: &[u8] = data;
    DNSQuestion::try_from((name.into(), data))
}

fn decode_name<const SIZE: usize>(reader: &mut Cursor<&[u8; SIZE]>) -> Result<String> {
    let mut cursor = reader.position();
    let mut parts = Vec::new();
    let mut length = reader.get_ref()[cursor as usize];

    while length != 0 {
        if (length & 0b1100_0000) != 0 {
            parts.push(decode_compressed_name(reader)?);
            cursor += 2;
            reader.set_position(cursor);
            return Ok(parts.join("."));
        } else {
            let (start, end) = ((cursor + 1) as usize, (cursor + length as u64 + 1) as usize);
            parts.push(String::from_utf8(reader.get_ref()[start..end].to_vec())?);
            cursor += length as u64 + 1;
            length = reader.get_ref()[cursor as usize];
        }
    }

    cursor += 1;
    reader.set_position(cursor);
    Ok(parts.join("."))
}

fn decode_compressed_name<const SIZE: usize>(reader: &mut Cursor<&[u8; SIZE]>) -> Result<String> {
    let curr_pos = reader.position() as usize;
    let curr = reader.get_ref()[curr_pos] & 0b0011_1111;
    let next = reader.get_ref()[curr_pos + 1];
    let cursor = u16::from_be_bytes([curr, next]);
    reader.set_position(cursor as u64);
    decode_name(reader)
}

#[derive(Debug, TryFromPrimitive)]
#[repr(u16)]
pub enum RecordType {
    A = 1,
}

#[derive(Debug, TryFromPrimitive)]
#[repr(u16)]
pub enum Class {
    In = 1,
}

fn build_query(domain_name: &str, record_type: RecordType) -> Result<Vec<u8>> {
    let name = encode_dns_name(domain_name)?;
    let id = {
        let mut rng = rand::thread_rng();
        rng.gen_range(0..=65535)
    };
    let recursion_desired = 1 << 8;
    let header = DNSHeader {
        id,
        flags: recursion_desired,
        num_questions: 1,
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

#[derive(Debug)]
pub struct DNSRecord {
    name: Vec<u8>,
    kind: RecordType,
    class: Class,
    ttl: u32,
    data: Vec<u8>,
}

fn parse_record<const SIZE: usize>(reader: &mut Cursor<&[u8; SIZE]>) -> Result<DNSRecord> {
    let name = decode_name(reader)?;
    let data = &mut [0; 10];
    reader.read_exact(data)?;
    let kind = u16::from_be_bytes(data[0..2].try_into()?);
    let class = u16::from_be_bytes(data[2..4].try_into()?);
    let ttl = u32::from_be_bytes(data[4..8].try_into()?);
    let data_len = u16::from_be_bytes(data[8..10].try_into()?);
    let mut data = vec![0; data_len as usize];
    reader.read_exact(&mut data)?;
    Ok(DNSRecord {
        name: name.into(),
        kind: RecordType::try_from(kind)?,
        class: Class::try_from(class)?,
        ttl,
        data,
    })
}

#[derive(Debug)]
pub struct DNSPacket {
    pub header: DNSHeader,
    pub questions: Vec<DNSQuestion>,
    pub answers: Vec<DNSRecord>,
    pub authorities: Vec<DNSRecord>,
    pub additionals: Vec<DNSRecord>,
}

fn parse_dns_packet<const SIZE: usize>(data: &[u8; SIZE]) -> Result<DNSPacket> {
    let mut reader = Cursor::new(data);
    let header = parse_header(&mut reader)?;
    let questions = (0..header.num_questions)
        .map(|_| parse_question(&mut reader))
        .collect::<Result<Vec<_>>>()?;
    let answers = (0..header.num_answers)
        .map(|_| parse_record(&mut reader))
        .collect::<Result<Vec<_>>>()?;
    let authorities = (0..header.num_authorities)
        .map(|_| parse_record(&mut reader))
        .collect::<Result<Vec<_>>>()?;
    let additionals = (0..header.num_additionals)
        .map(|_| parse_record(&mut reader))
        .collect::<Result<Vec<_>>>()?;
    Ok(DNSPacket {
        header,
        questions,
        answers,
        authorities,
        additionals,
    })
}

#[cfg(test)]
mod tests {
    use std::{
        io::Cursor,
        net::{Ipv4Addr, UdpSocket},
    };

    use crate::{
        build_query, consts, encode_dns_name, header_to_bytes, parse_dns_packet, parse_header,
        parse_question, parse_record, DNSHeader, RecordType,
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

        let r = parse_dns_packet(&response);
        println!("{:?}", r);

        let data = &r.unwrap().answers[0].data;
        assert_eq!(data.len(), 4);
        assert_eq!(data[0], 93);
        assert_eq!(data[1], 184);
        assert_eq!(data[2], 216);
        assert_eq!(data[3], 34);
    }

    #[test]
    fn test_decode_name() {
        let mut buf = [0; consts::DNS_BUF_SIZE];
        buf[0] = 3;
        buf[1] = 'w' as u8;
        buf[2] = 'w' as u8;
        buf[3] = 'w' as u8;
        buf[4] = 7;
        buf[5] = 'e' as u8;
        buf[6] = 'x' as u8;
        buf[7] = 'a' as u8;
        buf[8] = 'm' as u8;
        buf[9] = 'p' as u8;
        buf[10] = 'l' as u8;
        buf[11] = 'e' as u8;
        buf[12] = 3;
        buf[13] = 'c' as u8;
        buf[14] = 'o' as u8;
        buf[15] = 'm' as u8;
        buf[16] = 0;

        let mut cur = Cursor::new(&buf);
        let name = super::decode_name(&mut cur);
        assert_eq!(name.unwrap(), "www.example.com");
        assert_eq!(cur.position(), 17);
    }
}
