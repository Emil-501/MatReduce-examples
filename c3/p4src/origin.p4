#include <core.p4>
#include <v1model.p4>

struct meta_t {
    bit<8>  packet_category;
    bit<32> nhop_ipv4;
    bit<16> tcp_length;
}

header ethernet_t {
    bit<48> dst_addr;
    bit<48> src_addr;
    bit<16> ether_type;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> total_len;
    bit<16> identification;
    bit<3>  flags;
    bit<13> frag_offset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> checksum;
    bit<32> src_addr;
    bit<32> dst_addr;
}

header tcp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4>  data_offset;
    bit<4>  res;
    bit<8>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

struct metadata {
    @name(".meta") 
    meta_t meta;
}

struct headers {
    @name(".ethernet") 
    ethernet_t ethernet;
    @name(".ipv4") 
    ipv4_t     ipv4;
    @name(".tcp") 
    tcp_t      tcp;
}

parser ParserImpl(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".parse_ethernet") state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            16w0x800: parse_ipv4;
            default: accept;
        }
    }
    @name(".parse_ipv4") state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            8w6: parse_tcp;
            default: accept;
        }
    }
    @name(".parse_tcp") state parse_tcp {
        packet.extract(hdr.tcp);
        meta.meta.tcp_length = hdr.ipv4.total_len - 16w20;
        transition accept;
    }
    @name(".start") state start {
        meta.meta.packet_category = 8w3;
        transition parse_ethernet;
    }
}

control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    action handle_forward(bit<48> smac) {
        hdr.ethernet.src_addr = smac;
    }
    action handle_fake() {
        mark_to_drop();
    }
    action handle_denied() {
        mark_to_drop();
    }
    action handle_unknown() {
        mark_to_drop();
    }
    table send_frame {
        actions = {
            handle_forward;
            handle_fake;
            handle_denied;
            handle_unknown;
        }
        key = {
            meta.meta.packet_category    : exact;
            standard_metadata.egress_port: ternary;
        }
        size = 256;
    }
    apply {
        send_frame.apply();
    }
}

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    action set_dmac(bit<48> dmac) {
        meta.meta.packet_category = 8w0;
        hdr.ethernet.dst_addr = dmac;
    }
    action set_nhop(bit<32> nhop_ipv4, bit<9> port) {
        meta.meta.nhop_ipv4 = nhop_ipv4;
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl + 8w255;
    }
    action nop() {
        ;
    }
    action sg_mark() {
        meta.meta.packet_category = 8w1;
    }
    action acl_mark() {
        meta.meta.packet_category = 8w2;
    }
    action nat_int_to_ext(bit<32> src_addr, bit<16> port_span) {
        hdr.ipv4.src_addr = src_addr;
        hdr.tcp.src_port = hdr.tcp.src_port + port_span;
    }
    action nat_ext_to_int(bit<32> dst_addr, bit<16> port_span) {
        hdr.ipv4.dst_addr = dst_addr;
        hdr.tcp.dst_port = hdr.tcp.dst_port - port_span;
    }
    table forward {
        actions = {
            set_dmac;
        }
        key = {
            meta.meta.nhop_ipv4: exact;
        }
        size = 512;
    }
    table ipv4_lpm {
        actions = {
            set_nhop;
        }
        key = {
            hdr.ipv4.dst_addr: lpm;
        }
        size = 1024;
    }
    table ipv4_sg {
        actions = {
            nop;
            sg_mark;
        }
        key = {
            hdr.ethernet.src_addr: exact;
            hdr.ipv4.src_addr    : exact;
        }
    }
    table ipv4_tcp_acl {
        actions = {
            nop;
            acl_mark;
        }
        key = {
            standard_metadata.ingress_port: exact;
            hdr.ipv4.src_addr             : ternary;
            hdr.ipv4.dst_addr             : ternary;
            hdr.tcp.src_port              : ternary;
            hdr.tcp.dst_port              : ternary;
            hdr.tcp.flags                 : ternary;
        }
    }
    table nat {
        actions = {
            nat_int_to_ext;
            nat_ext_to_int;
        }
        key = {
            hdr.ipv4.src_addr: ternary;
            hdr.ipv4.dst_addr: ternary;
            hdr.tcp.src_port : ternary;
            hdr.tcp.dst_port : ternary;
        }
        size = 128;
    }
    apply {
        if (hdr.ipv4.isValid()) {
            if (ipv4_sg.apply().hit) {
                //if (hdr.tcp.isValid()) {
                    if (ipv4_tcp_acl.apply().hit) {
                        nat.apply();
                        if (hdr.ipv4.ttl > 8w0) {
                            ipv4_lpm.apply();
                            forward.apply();
                        }
                    }
                //}
            }
        }
    }
}

control DeparserImpl(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
    }
}

control verifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
        verify_checksum(true, { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv, hdr.ipv4.total_len, hdr.ipv4.identification, hdr.ipv4.flags, hdr.ipv4.frag_offset, hdr.ipv4.ttl, hdr.ipv4.protocol, hdr.ipv4.src_addr, hdr.ipv4.dst_addr }, hdr.ipv4.checksum, HashAlgorithm.csum16);
        verify_checksum_with_payload(hdr.tcp.isValid(), { hdr.ipv4.src_addr, hdr.ipv4.dst_addr, 8w0, hdr.ipv4.protocol, meta.meta.tcp_length, hdr.tcp.src_port, hdr.tcp.dst_port, hdr.tcp.seq_no, hdr.tcp.ack_no, hdr.tcp.data_offset, hdr.tcp.res, hdr.tcp.flags, hdr.tcp.window, hdr.tcp.urgent_ptr }, hdr.tcp.checksum, HashAlgorithm.csum16);
    }
}

control computeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(true, { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv, hdr.ipv4.total_len, hdr.ipv4.identification, hdr.ipv4.flags, hdr.ipv4.frag_offset, hdr.ipv4.ttl, hdr.ipv4.protocol, hdr.ipv4.src_addr, hdr.ipv4.dst_addr }, hdr.ipv4.checksum, HashAlgorithm.csum16);
        update_checksum_with_payload(hdr.tcp.isValid(), { hdr.ipv4.src_addr, hdr.ipv4.dst_addr, 8w0, hdr.ipv4.protocol, meta.meta.tcp_length, hdr.tcp.src_port, hdr.tcp.dst_port, hdr.tcp.seq_no, hdr.tcp.ack_no, hdr.tcp.data_offset, hdr.tcp.res, hdr.tcp.flags, hdr.tcp.window, hdr.tcp.urgent_ptr }, hdr.tcp.checksum, HashAlgorithm.csum16);
    }
}

V1Switch(ParserImpl(), verifyChecksum(), ingress(), egress(), computeChecksum(), DeparserImpl()) main;

