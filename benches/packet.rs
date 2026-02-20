//! Benchmarks for packet construction.

use criterion::{Criterion, criterion_group, criterion_main};
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use pnet::util::MacAddr;
use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bluebox::network::{BufferPool, PacketBuilder, PacketInfo};

fn create_test_response() -> Message {
    let mut msg = Message::new();
    msg.set_id(1234)
        .set_message_type(MessageType::Response)
        .set_op_code(OpCode::Query)
        .set_response_code(ResponseCode::NoError);
    msg
}

fn create_ipv4_packet_info() -> PacketInfo {
    PacketInfo {
        source_mac: MacAddr::new(0x11, 0x22, 0x33, 0x44, 0x55, 0x66),
        dest_mac: MacAddr::new(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff),
        source_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
        dest_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        source_port: 12345,
        dest_port: 53,
    }
}

fn create_ipv6_packet_info() -> PacketInfo {
    PacketInfo {
        source_mac: MacAddr::new(0x11, 0x22, 0x33, 0x44, 0x55, 0x66),
        dest_mac: MacAddr::new(0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff),
        source_ip: IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
        dest_ip: IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2)),
        source_port: 12345,
        dest_port: 53,
    }
}

fn bench_packet_building(c: &mut Criterion) {
    let mut group = c.benchmark_group("packet_building");

    let pool = BufferPool::new(64);
    let builder = PacketBuilder::new(pool);
    let response = create_test_response();

    let ipv4_info = create_ipv4_packet_info();
    group.bench_function("ipv4_response", |b| {
        b.iter(|| builder.build_response(black_box(&response), black_box(&ipv4_info)));
    });

    let ipv6_info = create_ipv6_packet_info();
    group.bench_function("ipv6_response", |b| {
        b.iter(|| builder.build_response(black_box(&response), black_box(&ipv6_info)));
    });

    group.finish();
}

fn bench_buffer_pool(c: &mut Criterion) {
    let mut group = c.benchmark_group("buffer_pool");

    let pool = BufferPool::new(64);

    group.bench_function("get_and_drop", |b| {
        b.iter(|| {
            let buf = pool.get();
            drop(black_box(buf));
        });
    });

    group.bench_function("get_zeroed_512", |b| {
        b.iter(|| {
            let buf = pool.get_zeroed(512);
            drop(black_box(buf));
        });
    });

    group.finish();
}

criterion_group!(benches, bench_packet_building, bench_buffer_pool);
criterion_main!(benches);
