import importlib.util
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('pppoe_capture', Path(__file__).parents[1] / 'scripts/pppoe_test.py')
engine = importlib.util.module_from_spec(spec)
spec.loader.exec_module(engine)


def fixture():
    """Synthetic Ethernet control/auth/data frames, with and without a VLAN."""
    rows = []
    for tagged in (False, True):
        for protocol, codes, accepted in ((0xc021, (1, 5), True), (0x8021, (1, 3), True),
                                          (0x8057, (1,), True), (0xc023, (1,), False),
                                          (0xc023, (2, 3), True), (0xc223, (1, 2), False),
                                          (0xc223, (3, 4), True), (0x0021, (0x45,), False),
                                          (0x0057, (0x60,), False)):
            for code in codes:
                packet = struct.pack('!HBBH', protocol, code, 1, 4)
                payload = struct.pack('!BBHH', 0x11, 0, 1, len(packet)) + packet
                ethernet = bytes.fromhex('020000000002020000000001')
                ethernet += struct.pack('!HHH', 0x8100, 123, 0x8864) if tagged else struct.pack('!H', 0x8864)
                rows.append((ethernet + payload, accepted))
        ethernet = bytes.fromhex('ffffffffffff020000000001')
        ethernet += struct.pack('!HHH', 0x8100, 123, 0x8863) if tagged else struct.pack('!H', 0x8863)
        rows.append((ethernet + struct.pack('!BBHH', 0x11, 9, 0, 0), True))
    # A foreign subscriber's discovery must not be captured even though broadcast.
    rows.append((bytes.fromhex('ffffffffffff0200000000998863110900000000'), False))
    return rows


def verify_filter(packet_filter, directory):
    source, selected = directory / 'synthetic.pcap', directory / 'selected.pcap'
    rows = fixture()
    with source.open('wb') as stream:
        stream.write(struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 2048, 1))
        for index, (packet, _) in enumerate(rows):
            stream.write(struct.pack('<IIII', index + 1, 0, len(packet), len(packet)))
            stream.write(packet)
    subprocess.run(['tcpdump', '-n', '-r', str(source), '-w', str(selected), packet_filter],
                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=10)
    data = selected.read_bytes()
    endian = '<' if data[:4] == bytes.fromhex('d4c3b2a1') else '>'
    offset, actual = 24, []
    while offset < len(data):
        timestamp, _, length, _ = struct.unpack_from(endian + 'IIII', data, offset)
        actual.append(timestamp - 1)
        offset += 16 + length
    expected = [i for i, (_, accepted) in enumerate(rows) if accepted]
    return actual, expected


class CaptureFilterTest(unittest.TestCase):
    def test_invalid_mac_cannot_broaden_capture(self):
        with self.assertRaises(ValueError):
            engine.control_filter('02:00:00:00:00:01 or ether')

    @unittest.skipUnless(shutil.which('tcpdump'), 'tcpdump is needed for offline BPF verification')
    def test_real_bpf_excludes_credentials_data_and_other_subscribers(self):
        with tempfile.TemporaryDirectory() as temp:
            actual, expected = verify_filter(engine.control_filter('02:00:00:00:00:01'), Path(temp))
            self.assertEqual(actual, expected)


if __name__ == '__main__':
    unittest.main()
