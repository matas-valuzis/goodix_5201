import pyshark
import struct

SENSOR_WIDTH = 88
SENSOR_HEIGHT = 108

# saves unpacked values as pgm file
def save_pgm(unpacked_values, suffix="image"):
    fout = open('%s.pgm' % suffix, 'w+')
    fout.write('P2\n')
    width = SENSOR_HEIGHT
    height = SENSOR_WIDTH
    fout.write("%d %d\n" % (width, height))

    # 16bpp data, but only 12bit actual value
    fout.write("4095\n")

    for value in unpacked_values:
        fout.write("%d\n" % value)

    fout.close()

def rolling_key_gen(seed):
    var1 = seed >> 1 ^ seed
    var2 = seed >> 0x10
    var3 = ((((((((seed >> 0xf & 0x2000 | seed & 0x1000000) >> 1 | seed & 0x20000) >> 2 | seed & 0x1000) >> 3 | (seed >> 7 ^ seed) & 0x80000) >> 1 | (seed >> 0xf ^ seed) & 0x4000) >> 2 | seed & 0x2000) >> 1 | (seed >> 0xe ^ seed) & 0x200) >> 1 | var1 & 0x40 | seed & 0x20) >> 1
    var4 = var3 | ((seed >> 0x14) ^ seed * 2) & 4 | seed & 1
    next_seed = (var1 >> 0x1e ^ seed >> 10 & 0xff ^ seed & 0xff) << 0x1f | seed >> 1
    key = ((var3 >> 8) | (var2 >> 8 ^ ((seed << 3) >> 8)) & 0x40 | (var2 >> 1 ^ seed) & 8 | (((seed << 6) >> 8) ^ ((seed >> 7) >> 8)) & 1 | (((seed & 0x100) << 7) >> 8)) + var4 * 0x100
    return (key, next_seed & 0xffffffff)

def decrypt_data(data_bytes):
    decrypted = b''
    size = len(data_bytes)
    seed = 0x12345678 # starting seed
    for i in range(0, size, 2):
        (key, seed) = rolling_key_gen(seed)
        word = int.from_bytes(data_bytes[i:i+2], 'little')
        dec_word = (word ^ key) & 0xffff # just xor 16bit words with key
        decrypted += dec_word.to_bytes(2, byteorder='little')
    return decrypted

def unpack_data_to_16bit(data):
    # 6 bytes are needed to represent 4 16-bit values
    assert (len(data) % 6) == 0
    out = []
    for i in range(0, len(data), 6):
        chunk = data[i:i+6]
        o1 = ((chunk[0] & 0xf) << 8) + chunk[1] 
        o2 = (chunk[3] << 4) + (chunk[0] >> 4)
        o3 = ((chunk[5] & 0xf) << 8) + chunk[2] 
        o4 = (chunk[4] << 4) + (chunk[5] >> 4)
        out += [o1, o2, o3, o4]
    return out

# always static
def image_checksum_lookup_table():
    map_bytes = b''
    for i in range(0, 256):
        var1 = i << 0x18
        var2 = 0
        for j in range(0, 8):
            if var2 ^ var1 > 2147483647:
                var2 = (var2 * 2 ^ 0x4c11db7) & 0xffffffff
            else:
                var2 = (var2 * 2) & 0xffffffff
            var1 = var1 * 2 & 0xffffffff
        map_bytes += var2.to_bytes(4, 'little')
    return map_bytes

def get_image_checksum(data_bytes):
    return data_bytes[-2] * 0x1000000 +  data_bytes[-1] * 0x10000 + data_bytes[-4] * 0x100 + data_bytes[-3]

def calc_image_checksum(data_bytes):
    sum = 0xffffffff
    cks_map = image_checksum_lookup_table()
    for byte in data_bytes[:-4]: # last 4 bytes is real image checksum
        i = ((sum >> 24) ^ byte) * 4
        sum = (struct.unpack("<L", cks_map[i:i+4])[0] ^ sum << 8) & 0xffffffff
    return sum

def save_bytes(data_bytes, file="bytes"):
    fout = open("%s.bin" % file, "wb")
    fout.write(data_bytes)
    fout.close()

def images_from_wireshark(pcap_file, image_dir = "images"):
    for frame in pyshark.FileCapture(pcap_file, display_filter='goodix.image_data'):
        image_bytes = bytearray.fromhex(frame.goodix.image_data.raw_value)
        dec = decrypt_data(image_bytes)
        unpacked = unpack_data_to_16bit(dec)
        save_pgm(unpacked, "%s/%s" % (image_dir, str(frame.number)))

def main():
    # fin = open("print_data.bin", "rb")
    # image_data = fin.read()
    # fin.close()
    # print ("Calculated checksum: %x" % calc_image_checksum(image_data))
    # print ("Real checksum: %x" % get_image_checksum(image_data))
    # save_pgm(unpack_data_to_16bit(decrypt_data(image_data[:-4])), 'print_image')
    # print ("print_image.pgm image created")
    images_from_wireshark("wireshark/windows_setup.pcapng")

main()
