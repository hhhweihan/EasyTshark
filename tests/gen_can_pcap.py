#!/usr/bin/env python3
# 生成一份纯字节拼装的 CAN 测试 pcap（DLT 227 / SocketCAN），不依赖 scapy、
# 不需要真实 CAN 总线或硬件。字节布局与 tests/test_native_engine.cpp 里
# NativeParserTest 用到的 canSocketcanFrame/canFdSocketcanFrame 等 helper 完全一致，
# 用于手工验证"CAN会话"分组与 UDS-over-CAN / ISO-TP 重组这几个解析特性。
#
# 注意：这份 pcap 只有在被自研引擎（NativeAnalyzer）解析时才会识别出 can_id 和
# CAN/UDS 协议名——tshark 转发路径（PacketParser.cpp）完全没有 CAN 相关逻辑。
# 若本机装了 tshark，AnalysisSession 默认会优先用 tshark 后端，此时载入这份 pcap
# 不会出现"CAN会话"。要强制走自研引擎，在 GUI/Web 的"tshark 路径"里填一个不存在
# 的路径（如 /nonexistent）再载入即可。

import struct
import sys

PCAP_MAGIC = 0xa1b2c3d4
LINKTYPE_SOCKETCAN = 227


def le32(x):
    return struct.pack('<I', x)


def le16(x):
    return struct.pack('<H', x)


def global_header(link_type):
    return (le32(PCAP_MAGIC) + le16(2) + le16(4) +
            le32(0) + le32(0) + le32(65535) + le32(link_type))


def record(ts_sec, frame):
    return le32(ts_sec) + le32(0) + le32(len(frame)) + le32(len(frame)) + frame


def can_classic_frame(can_id, data):
    dlc = len(data)
    return le32(can_id) + bytes([dlc, 0, 0, 0]) + bytes(data)


def can_fd_frame(can_id, flags, data):
    length = len(data)
    return le32(can_id) + bytes([flags, length, 0, 0]) + bytes(data)


def isotp_first_frame(payload):
    head = bytes([0x10, len(payload)])
    return head + bytes(payload[:6])


def isotp_consecutive_frame(payload, seq):
    head = bytes([0x20 | (seq & 0x0F)])
    body = bytes(payload[6:])
    frame = head + body
    return frame + bytes([0xAA] * (8 - len(frame)))


def build_frames():
    frames = []

    # 两条普通 CAN 会话（不同 CAN ID，无 UDS 特征）
    frames.append(can_classic_frame(0x100, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]))
    frames.append(can_classic_frame(0x200, [0xDE, 0xAD, 0xBE, 0xEF]))

    # ISO-TP 单帧 UDS：CAN 0x123，PCI=0x02（长度2），SID=0x3E（TesterPresent）
    frames.append(can_classic_frame(0x123, [0x02, 0x3E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]))

    # ISO-TP 多帧 UDS：CAN 0x7E8，First Frame + Consecutive Frame，
    # 负载是 ReadDataByIdentifier 正响应 62 F1 90 + "ABCDEFG"
    payload = [0x62, 0xF1, 0x90, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47]
    frames.append(can_classic_frame(0x7E8, isotp_first_frame(payload)))
    frames.append(can_classic_frame(0x7E8, isotp_consecutive_frame(payload, 1)))

    # CAN FD：flags=0x80 仅 FDF → "CAN FD"
    frames.append(can_fd_frame(0x1FED, 0x80, list(range(16))))

    # CAN FD：flags=0x83 = FDF+BRS+ESI → "CAN FD BRS ESI"
    frames.append(can_fd_frame(0x1FEE, 0x83, list(range(32))))

    return frames


def main():
    out_path = sys.argv[1] if len(sys.argv) > 1 else 'data/pcaps/can_demo.pcap'
    frames = build_frames()
    with open(out_path, 'wb') as f:
        f.write(global_header(LINKTYPE_SOCKETCAN))
        for i, frame in enumerate(frames, start=1):
            f.write(record(i, frame))
    print('生成 %s：%d 个 CAN 帧（DLT 227）' % (out_path, len(frames)))


if __name__ == '__main__':
    main()
