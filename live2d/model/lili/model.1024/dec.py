# coding=utf-8
from __future__ import print_function
import sys
import struct


def save(data, file):
    f = open(file, 'wb')
    f.write(data)
    f.close()


def decrypt(data):
    if data[:8] != "gemtrade":
        print("[x] Not valid file.")

    len_data = len(data)

    magic = struct.unpack("<I", data[16:20])[0]
    magic_2 = struct.unpack("<I", data[20:24])[0]
    magic_3 = struct.unpack("<I", data[24:28])[0]
    magic_4 = (magic_3 + magic_2) >> 1
    magic_5 = (magic_2 - magic_3) >> 1
    left_len = len_data - 28
    to_xor = magic - magic_4 % magic_5
    decode_buf = bytearray(data[28:])

    counter = 0
    while True:
        # xor begin
        for i in range(4):
            decode_buf[counter +
                       i] = (decode_buf[counter + i] ^ (to_xor >> 8 * i)) & 0xff
        # xor end
        counter += 4
        v21 = left_len - counter
        to_xor -= 1
        if left_len <= counter or v21 <= 3:
            break
        if magic_4 <= counter and magic_4 < v21:
            counter += magic_5
            if left_len < counter or magic_4 > left_len - counter:
                counter = left_len - magic_4

    return str(decode_buf)


def main():
    infile = sys.argv[1]
    f = open(infile, 'rb')
    data = f.read()
    f.close()
    data = decrypt(data)
    save(data, infile)  # + ".png")


if __name__ == '__main__':
    main()
