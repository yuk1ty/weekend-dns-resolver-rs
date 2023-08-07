use weekend_dns_resolver::{lookup_domain, send_query, RecordType};

fn main() {
    // println!("example.com: {:?}", lookup_domain("example.com"));
    // println!("recurse.com: {:?}", lookup_domain("recurse.com"));
    // println!("metafilter.com: {:?}", lookup_domain("metafilter.com"));
    println!(
        "send rq: {:?}",
        send_query("198.41.0.4".parse().unwrap(), "google.com", RecordType::A)
    );
    println!(
        "send rq: {:?}",
        send_query("192.12.94.30".parse().unwrap(), "google.com", RecordType::A)
    );
    println!(
        "send rq: {:?}",
        send_query(
            "216.239.32.10".parse().unwrap(),
            "google.com",
            RecordType::A
        )
    );
}
