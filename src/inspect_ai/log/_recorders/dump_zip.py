from io import BufferedReader
from inspect_ai.log._recorders.eval_async_zip import LocalFileHeader, CDFH, EOCD64Locator, EOCD64, EOCD

import argparse

def dump_hex(data: bytes):
    hex_data = data.hex()
    for i in range(0, len(hex_data), 32):
        print(hex_data[i:i+32])

def dump_eocd(eocd: EOCD):
    print("=== End of Central Directory Record ===")
    print(f"Signature      {eocd.signature}")
    print(f"Disk Number    {eocd.disk_number}")
    print(f"Disk Start     {eocd.disk_start}")
    print(f"Entries disk   {eocd.entries_this_disk}")
    print(f"Entries total  {eocd.entries_total}")
    print(f"Size           {eocd.size}")
    print(f"Offset         {eocd.offset}")
    print(f"Comment size   {eocd.comment_size}")
    print()

def dump_cd(header: CDFH):
    print("=== Central Directory File Header ===")
    print(f"Signature           {header.signature}")
    print(f"Create version      {header.create_version}")
    print(f"Create system       {header.create_system}")
    print(f"Extract version     {header.extract_version}")
    print(f"Extract system      {header.extract_system}")
    print(f"Flat bits           {header.flat_bits}")
    print(f"Compress type       {header.compress_type}")
    print(f"Time                {header.time}")
    print(f"Date                {header.date}")
    print(f"CRC                 {header.crc}")
    print(f"Compressed size     {header.compressed_size}")
    print(f"Uncompressed size   {header.uncompressed_size}")
    print(f"Filename length     {header.filename_length}")
    print(f"Extra field len     {header.extra_field_length}")
    print(f"Comment length      {header.comment_length}")
    print(f"Disk number start   {header.disk_number_start}")
    print(f"Internal file attr  {header.internal_file_attributes}")
    print(f"External file attr  {header.external_file_attributes}")
    print(f"Local header offset {header.local_header_offset}")

def dump_lfh(header: LocalFileHeader):
    print("=== Local File Header ===")
    print(f"Signature           {header.signature}")
    print(f"Extract version     {header.extract_version}")
    print(f"Extract system      {header.extract_system}")
    print(f"Flag bits           {header.general_purpose_flag_bits}")
    print(f"Compression method  {header.compression_method}")
    print(f"Time                {header.last_mod_time}")
    print(f"Date                {header.last_mod_date}")
    print(f"CRC                 {header.crc}")
    print(f"Compressed size     {header.compressed_size}")
    print(f"Uncompressed size   {header.uncompressed_size}")
    print(f"Filename length     {header.filename_length}")
    print(f"Extra field length  {header.extra_field_length}")

def read_and_dump(f: BufferedReader, length: int) -> bytes:
    offset = f.tell()
    print(f"Offset {offset}")
    data = f.read(length)

    if len(data) != length:
        raise EOFError(f"Expected {length} bytes, got {len(data)}")
    
    f.seek(max(0, offset - 32))
    pre_data = f.read(32)
    f.seek(offset + length)
    post_data = f.read(32)

    f.seek(offset + length)

    dump_hex(pre_data)
    print('---')
    dump_hex(data)
    print('---')
    dump_hex(post_data)
    return data

def dump_zip_main():
    parser = argparse.ArgumentParser(description='Dump zip file')
    parser.add_argument('input', type=str, help='Input zip file')
    args = parser.parse_args()

    with open(args.input, 'rb') as f:
        f.seek(-EOCD.SIZE, 2)
        eocd_data = read_and_dump(f, EOCD.SIZE)
        eocd = EOCD.from_bytes(eocd_data)
        dump_eocd(eocd)

        f.seek(eocd.offset)
        for i in range(eocd.entries_total):
            print(f"Entry {i}")
            header_data = read_and_dump(f, CDFH.SIZE)
            header = CDFH.from_bytes(header_data)
            dump_cd(header)
            filename = f.read(header.filename_length)
            offset_next = f.tell()
            print(f"Filename: {filename}")
            print()
            assert header.extra_field_length == 0
            assert header.comment_length == 0

            f.seek(header.local_header_offset)
            lfh_data = read_and_dump(f, LocalFileHeader.SIZE)
            lfh = LocalFileHeader.from_bytes(lfh_data)
            dump_lfh(lfh)
            filename = f.read(header.filename_length)
            print(f"Filename: {filename}")
            print()

            f.seek(offset_next)


if __name__ == "__main__":
    dump_zip_main()
