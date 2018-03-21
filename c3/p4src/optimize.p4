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
    action nop() { }
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

    // the two tables cannot be optimized since they have match dependencies
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

    bit<32> src_addr_tmp=32w0;
    bit<32> dst_addr_tmp=32w0;
    bit<16> port_span_tmp=16w0;
    bit<32> aid = 32w0;
    bit<32> did = 32w0;
    action _drop() {
        mark_to_drop();
    }
    action composed_a(inout bit<32> a, inout bit<32> d, bit<32> a1, bit<32> d1, bit<32> src_addr, bit<32> dst_addr, bit<16> port_span) {
        a = a1; // target action id
        d = d1; // target default action
        src_addr_tmp = src_addr;
        dst_addr_tmp = dst_addr;
        port_span_tmp = port_span;
    }
    table composed_t {
        actions = {
            composed_a(aid, did); _drop;
        }
        key = {
            standard_metadata.ingress_port: ternary; // used for ipv4_tcp_acl
            hdr.ethernet.src_addr         : ternary; // used for ipv4_sg
            hdr.ipv4.src_addr             : ternary; // used for ipv4_sg, ipv4_tcp_acl, nat
            hdr.ipv4.dst_addr             : ternary; // used for ipv4_tcp_acl, nat
            hdr.tcp.src_port              : ternary; // used for ipv4_tcp_acl, nat
            hdr.tcp.dst_port              : ternary; // used for ipv4_tcp_acl, nat
            hdr.tcp.flags                 : ternary; // used for ipv4_tcp_acl
        }
    }

    // table1: ipv4_sg
    // action1: nop; 
    // action2: sg_mark;

    // table2: ipv4_tcp_acl
    // action3: nop;
    // action4: acl_mark;
    
    // table3: nat
    // action5: nat_int_to_ext;
    // action6: nat_ext_to_int.

    apply {
        composed_t.apply();

        // table1
        bool ipv4_sg_hit = false;
        if (((aid>>0)&32w1) == 32w1) { 
            nop();
            if (((did>>0)&32w1) != 32w1) {
                ipv4_sg_hit = true;
            }
        } else if (((aid>>1)&32w1) == 32w1) { 
            sg_mark();
            if (((did>>1)&32w1) != 32w1) {
                ipv4_sg_hit = true;
            }
        }

        // table2
        bool ipv4_tcp_acl_hit = false;
        if (ipv4_sg_hit) {
            if (((aid>>2)&32w1) == 32w1) { 
                nop();
                if (((did>>2)&32w1) != 32w1) {
                    ipv4_tcp_acl_hit = true;
                }
            } else if (((aid>>3)&32w1) == 32w1) { 
                acl_mark();
                if (((did>>3)&32w1) != 32w1) {
                    ipv4_tcp_acl_hit = true;
                }
            }
        }

        // table3
        if (ipv4_sg_hit && ipv4_tcp_acl_hit) {
            if (((aid>>4)&32w1) == 32w1) { 
                nat_int_to_ext(src_addr_tmp, port_span_tmp);
            } else if (((aid>>5)&32w1) == 32w1) { 
                nat_ext_to_int(dst_addr_tmp, port_span_tmp);
            }
            if (hdr.ipv4.ttl > 8w0) {
                ipv4_lpm.apply();
                forward.apply();
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

