from __future__ import annotations
from dataclasses import dataclass
import os
import struct
import sys
import time
import anyio
import zlib

DEFAULT_VERSION = 20
ZIP_DEFLATED = 8

class AsyncZip:
    _file: anyio.AsyncFile | None
    _dirbuffer: bytearray | None
    _dircount: int | None

    def __init__(self, file: anyio.AsyncFile):
        self._file = file

    async def init(self):
        await self._file.seek(0, 2)
        if await self._file.tell() == 0:  # empty file
            self._dirbuffer = bytearray()
            self._dircount = 0
        else:
            self._dirbuffer, self._dircount = await _read_and_truncate_directory(self._file)

    async def aclose(self):
        if self._file is None:
            return
        
        # Write the central directory
        offset = await self._file.tell()
        await self._file.write(self._dirbuffer)
        # Write the end of central directory record
        cfdh = EOCD.new_with_defaults(
            count=self._dircount,
            size=len(self._dirbuffer),
            offset=offset
        )
        await self._file.write(cfdh.to_bytes())

        await self._file.flush()
        # await self._file.aclose()   # don't close because someone else might be using the file again
        self._file = None

    async def add_file(self, filename: str, data: bytes, compresslevel: int):
        # Compress the data
        compressed_data = zlib.compress(data, level=compresslevel, wbits=-15)

        # Calculate the CRC32 checksum
        crc = zlib.crc32(data)

        # Get file offset
        offset = await self._file.tell()

        # Store the local file header in the buffer
        cdfh = CDFH.new_with_defaults(
            crc=crc,
            compressed_size=len(compressed_data),
            uncompressed_size=len(data),
            filename=filename,
            local_header_offset=offset,
        )
        self._dirbuffer.extend(cdfh.to_bytes())
        self._dirbuffer.extend(filename.encode('utf-8'))
        self._dircount += 1

        # Compute and write the local file header
        lhf = cdfh.to_local()
        await self._file.write(lhf.to_bytes())
        # Write the filename
        await self._file.write(filename.encode('utf-8'))
        # No extra field
        # Write the compressed data to the file
        await self._file.write(compressed_data)

@dataclass
class LocalFileHeader:
    signature: bytes
    extract_version: int
    extract_system: int
    general_purpose_flag_bits: int
    compression_method: int
    last_mod_time: int
    last_mod_date: int
    crc: int
    compressed_size: int
    uncompressed_size: int
    filename_length: int
    extra_field_length: int

    STRUCT = "<4s2B4HL2L2H"
    MAGIC = b"PK\003\004"
    SIZE = struct.calcsize(STRUCT)

    def to_bytes(self) -> bytes:
        return struct.pack(self.STRUCT, self.signature, self.extract_version,
                           self.extract_system, self.general_purpose_flag_bits,
                           self.compression_method, self.last_mod_time,
                           self.last_mod_date, self.crc, self.compressed_size,
                           self.uncompressed_size, self.filename_length,
                           self.extra_field_length)

@dataclass
class CDFH:
    signature: bytes
    create_version: int
    create_system: int
    extract_version: int
    extract_system: int
    flat_bits: int
    compress_type: int
    time: int
    date: int
    crc: int
    compressed_size: int
    uncompressed_size: int
    filename_length: int
    extra_field_length: int
    comment_length: int
    disk_number_start: int
    internal_file_attributes: int
    external_file_attributes: int
    local_header_offset: int

    STRUCT = "<4s4B4HL2L5H2L"
    MAGIC = b"PK\001\002"
    SIZE = struct.calcsize(STRUCT)

    def to_local(self):
        return LocalFileHeader(
            signature=LocalFileHeader.MAGIC,
            extract_version=self.extract_version,
            extract_system=self.extract_system,
            general_purpose_flag_bits=self.flat_bits,
            compression_method=self.compress_type,
            last_mod_time=self.time,
            last_mod_date=self.date,
            crc=self.crc,
            compressed_size=self.compressed_size,
            uncompressed_size=self.uncompressed_size,
            filename_length=self.filename_length,
            extra_field_length=self.extra_field_length
        )

    @classmethod
    def new_with_defaults(cls, crc:int, compressed_size: int, uncompressed_size: int, filename:str, local_header_offset: int) -> CDFH:
        dt = time.localtime()
        dosdate = (dt[0] - 1980) << 9 | dt[1] << 5 | dt[2]
        dostime = dt[3] << 11 | dt[4] << 5 | (dt[5] // 2)
        return cls(
            signature=cls.MAGIC,
            create_version=DEFAULT_VERSION,
            create_system=0 if sys.platform == "win32" else 3,
            extract_version=DEFAULT_VERSION,
            extract_system=0,
            flat_bits=0,
            compress_type=ZIP_DEFLATED,
            time=dostime,
            date=dosdate,
            crc=crc,
            compressed_size=compressed_size,
            uncompressed_size=uncompressed_size,
            filename_length=len(filename),
            extra_field_length=0,
            comment_length=0,
            disk_number_start=0,
            internal_file_attributes=0,
            external_file_attributes=0,
            local_header_offset=local_header_offset
        )

    def to_bytes(self) -> bytes:
        return struct.pack(self.STRUCT, self.signature, self.create_version,
                           self.create_system, self.extract_version,
                           self.extract_system, self.flat_bits,
                           self.compress_type, self.time, self.date,
                           self.crc, self.compressed_size,
                           self.uncompressed_size, self.filename_length,
                           self.extra_field_length, self.comment_length,
                           self.disk_number_start, self.internal_file_attributes,
                           self.external_file_attributes,
                           self.local_header_offset)

@dataclass
class EOCD:
    signature: bytes
    disk_number: int
    disk_start: int
    entries_this_disk: int
    entries_total: int
    size: int
    offset: int
    comment_size: int

    STRUCT = b"<4s4H2LH"
    MAGIC = b"PK\005\006"
    SIZE = struct.calcsize(STRUCT)

    @classmethod
    def from_bytes(cls, data: bytes):
        if len(data) != cls.SIZE:
            raise ValueError("Invalid EOCD size")
        return cls(*struct.unpack(cls.STRUCT, data))
    
    def to_bytes(self) -> bytes:
        return struct.pack(self.STRUCT, self.signature, self.disk_number,
                           self.disk_start, self.entries_this_disk,
                           self.entries_total, self.size, self.offset,
                           self.comment_size)

    @classmethod
    def new_with_defaults(cls, count: int, size: int, offset: int) -> EOCD:
        return cls(
            signature=cls.MAGIC,
            disk_number=0,
            disk_start=0,
            entries_this_disk=count,
            entries_total=count,
            size=size,
            offset=offset,
            comment_size=0
        )

async def _read_and_truncate_directory(file: anyio.AsyncFile) -> tuple[bytearray, int]:
    # This function should read the directory from the file and truncate it.
    endrec = await _read_endrec(file)
    
    # Read the central directory
    await file.seek(endrec.offset)
    data = await file.read(endrec.size)
    if len(data) != endrec.size:
        raise ValueError("Did not successfully read entire central directory")
    
    # Position file to the start of the central directory and truncate
    await file.seek(endrec.offset)
    await file.truncate()

    return bytearray(data), endrec.entries_total

# TODO: zip64
async def _read_endrec(file: anyio.AsyncFile) -> EOCD:
    # jump to the start of the end of the central directory
    await file.seek(-EOCD.SIZE, 2)
    data = await file.read(EOCD.SIZE)
    if len(data) != EOCD.SIZE:
        raise ValueError("Zip file too small to contain end of central directory")
    if data[0:4] != EOCD.MAGIC:
        raise ValueError("End of central directory magic number not found, might contain comment")
    if data[-2:] != b"\x00\x00":
        raise ValueError("End of central directory comment length not set to 0")
    
    endrec = EOCD.from_bytes(data)
    if endrec.disk_number != 0 or endrec.disk_start != 0 or endrec.entries_this_disk != endrec.entries_total:
        raise ValueError("Zip file is split across multiple disks, not supported")
    
    return endrec

async def test_main():
    if os.path.exists("test.zip"):
        os.remove("test.zip")

    print("Creating test.zip")
    async with await anyio.open_file("test.zip", 'wb') as f:
        zip_file = AsyncZip(f)
        await zip_file.init()
        try:
            await zip_file.add_file("test.txt", b"Hello, world!", compresslevel=6)
            await zip_file.add_file("test2.txt", b"Another file", compresslevel=6)
        finally:
            await zip_file.aclose()

    print("Adding more files to test.zip")
    async with await anyio.open_file("test.zip", 'r+b') as f:
        zip_file = AsyncZip(f)
        await zip_file.init()
        try:
            await zip_file.add_file("test3.txt", b"Third file", compresslevel=6)
        finally:
            await zip_file.aclose()

if __name__ == "__main__":
    anyio.run(test_main)
