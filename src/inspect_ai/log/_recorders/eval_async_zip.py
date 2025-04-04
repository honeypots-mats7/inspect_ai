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
    _64: bool | None
    _closing: bool

    def __init__(self, file: anyio.AsyncFile):
        self._file = file
        self._closing = False

    async def init(self):
        assert not self._closing
        await self._file.seek(0, 2)
        if await self._file.tell() == 0:  # empty file
            self._dirbuffer = bytearray()
            self._dircount = 0
            self._64 = False
        else:
            self._dirbuffer, self._dircount, self._64 = await _read_and_truncate_directory(self._file)

    async def aclose(self):
        self._closing = True
        if self._file is None:
            return
        
        # Write the central directory
        offset = await self._file.tell()
        await self._file.write(self._dirbuffer)

        self._64 |= offset + len(self._dirbuffer) + EOCD.SIZE > 0x7FFFFFFF

        if self._64:
            # Write the zip64 end of central directory record
            eocd64 = EOCD64.new_with_defaults(
                count=self._dircount,
                size=len(self._dirbuffer),
                offset=offset
            )
            await self._file.write(eocd64.to_bytes())

            # Write the zip64 end of central directory locator
            locator = EOCD64Locator.new_with_defaults(relative_offset=offset + len(self._dirbuffer))
            await self._file.write(locator.to_bytes())
            eocd = EOCD.new_for_zip64()
        else:
            # Some sanity checks - we should have already set the _64 flag if any of these are broken
            assert self._dircount <= 0xFFFF
            assert len(self._dirbuffer) <= 0x7FFFFFFF
            assert offset <= 0x7FFFFFFF

            eocd = EOCD.new_with_defaults(
                count=self._dircount,
                size=len(self._dirbuffer),
                offset=offset
            )
        # Write the end of central directory record
        await self._file.write(eocd.to_bytes())

        await self._file.flush()
        # await self._file.aclose()   # don't close because someone else might be using the file again
        self._file = None

    async def add_file(self, filename: str, data: bytes, compresslevel: int):
        assert not self._closing

        # Compress the data
        compressed_data = zlib.compress(data, level=compresslevel, wbits=-15)

        # Calculate the CRC32 checksum
        crc = zlib.crc32(data)

        # Get file offset
        offset = await self._file.tell()

        cd_extras = []
        cd_extra_struct = '<HH'
        cd_extra_length = 4
        local_extras = []
        local_extra_struct = '<HH'
        local_extra_length = 4
        uncompressed_size = len(data)
        compressed_size = len(compressed_data)
        if uncompressed_size > 0x7FFFFFFF or compressed_size > 0x7FFFFFFF:
            # Use ZIP64 extra field
            self._64 = True
            cd_extra_struct += 'QQ'
            cd_extras += [uncompressed_size, compressed_size]
            cd_extra_length += 16
            local_extra_struct += 'QQ'
            local_extras += [uncompressed_size, compressed_size]
            local_extra_length += 16
            uncompressed_size_field = 0xFFFFFFFF
            compressed_size_field = 0xFFFFFFFF
        else:
            uncompressed_size_field = uncompressed_size
            compressed_size_field = compressed_size

        if offset > 0x7FFFFFFF:
            # Use ZIP64 extra field
            self._64 = True
            cd_extra_struct += 'Q'
            cd_extras.append(offset)
            cd_extra_length += 8
            # offset does not appear in the local file header
            offset_field = 0xFFFFFFFF
        else:
            offset_field = offset

        if len(cd_extras) > 0:
            cd_extra_field = struct.pack(cd_extra_struct, 1, cd_extra_length-4, *cd_extras)
        else:
            cd_extra_field = b""
            cd_extra_length = 0
        assert cd_extra_length == len(cd_extra_field)

        if len(local_extras) > 0:
            local_extra_field = struct.pack(local_extra_struct, 1, local_extra_length-4, *local_extras)
        else:
            local_extra_field = b""
            local_extra_length = 0
        assert local_extra_length == len(local_extra_field)

        # Store the local file header in the buffer
        dt = time.localtime()
        filename_bytes = filename.encode('utf-8')
        cdfh = CDFH.new_with_defaults(
            dt=dt,
            crc=crc,
            compressed_size=compressed_size_field,
            uncompressed_size=uncompressed_size_field,
            filename_length=len(filename_bytes),
            extra_field_length=cd_extra_length,
            local_header_offset=offset_field,
        )

        # Compute and write the local file header
        lhf = LocalFileHeader.new_with_defaults(
            dt=dt,
            crc=crc,
            compressed_size=compressed_size_field,
            uncompressed_size=uncompressed_size_field,
            filename_length=len(filename_bytes),
            extra_field_length=local_extra_length,
        )
        # Do this in this order in case an exception (Ctrl+C) is thrown in the middle
        # (in this case, it should be safe writing some extra garbage to the file that isn't
        # recorded in the central directory)

        # Write the local file header
        await self._file.write(lhf.to_bytes())
        # Write the filename
        await self._file.write(filename_bytes)
        await self._file.write(local_extra_field)
        # Write the compressed data to the file
        await self._file.write(compressed_data)

        self._64 |= self._dircount > 0xFFFF or len(self._dirbuffer) > 0x7FFFFFFF
        self._64 |= offset + LocalFileHeader.SIZE + len(filename_bytes) + local_extra_length + len(compressed_data) > 0x7FFFFFFF
        self._dirbuffer.extend(cdfh.to_bytes())
        self._dirbuffer.extend(filename_bytes)
        self._dirbuffer.extend(cd_extra_field)
        self._dircount += 1

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

    @classmethod
    def new_with_defaults(cls,
                          dt: tuple,
                          crc:int,
                          compressed_size: int,
                          uncompressed_size: int,
                          filename_length: int,
                          extra_field_length: int) -> LocalFileHeader:
        dosdate = (dt[0] - 1980) << 9 | dt[1] << 5 | dt[2]
        dostime = dt[3] << 11 | dt[4] << 5 | (dt[5] // 2)
        return cls(
            signature=cls.MAGIC,
            extract_version=DEFAULT_VERSION,
            extract_system=0,
            general_purpose_flag_bits=0,
            compression_method=ZIP_DEFLATED,
            last_mod_time=dostime,
            last_mod_date=dosdate,
            crc=crc,
            compressed_size=compressed_size,
            uncompressed_size=uncompressed_size,
            filename_length=filename_length,
            extra_field_length=extra_field_length
        )
    
    @classmethod
    def from_bytes(cls, data: bytes) -> LocalFileHeader:
        if len(data) != cls.SIZE:
            raise ValueError("Invalid Local File Header size")
        return cls(*struct.unpack(cls.STRUCT, data))

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

    @classmethod
    def new_with_defaults(cls,
                          dt: tuple,
                          crc:int,
                          compressed_size: int,
                          uncompressed_size: int,
                          filename_length: int,
                          extra_field_length: int,
                          local_header_offset: int) -> CDFH:
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
            filename_length=filename_length,
            extra_field_length=extra_field_length,
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
    
    @classmethod
    def from_bytes(cls, data: bytes) -> CDFH:
        if len(data) != cls.SIZE:
            raise ValueError("Invalid CDFH size")
        return cls(*struct.unpack(cls.STRUCT, data))

@dataclass
class EOCD64Locator:
    signature: bytes
    disk_number: int
    relative_offset: int
    disks: int

    STRUCT = b"<4sLQL"
    MAGIC = b"PK\006\007"
    SIZE = struct.calcsize(STRUCT)

    @classmethod
    def from_bytes(cls, data: bytes):
        if len(data) != cls.SIZE:
            raise ValueError("Invalid EOCD locator size")
        return cls(*struct.unpack(cls.STRUCT, data))
    
    def to_bytes(self) -> bytes:
        return struct.pack(self.STRUCT, self.signature, self.disk_number,
                           self.relative_offset, self.disks)

    @classmethod
    def new_with_defaults(cls, relative_offset: int) -> EOCD64Locator:
        return cls(
            signature=cls.MAGIC,
            disk_number=0,
            relative_offset=relative_offset,
            disks=1
        )

@dataclass
class EOCD64:
    signature: bytes
    size_minus_12: int
    version_made_by: int
    version_needed: int
    disk_number: int
    disk_start: int
    entries_this_disk: int
    entries_total: int
    size: int
    offset: int

    STRUCT = b"<4sQ2H2L4Q"
    MAGIC = b"PK\006\006"
    SIZE = struct.calcsize(STRUCT)

    @classmethod
    def from_bytes(cls, data: bytes):
        if len(data) != cls.SIZE:
            raise ValueError("Invalid EOCD64 size")
        return cls(*struct.unpack(cls.STRUCT, data))
    
    def to_bytes(self) -> bytes:
        return struct.pack(self.STRUCT, self.signature, self.size_minus_12,
                           self.version_made_by, self.version_needed,
                           self.disk_number, self.disk_start,
                           self.entries_this_disk, self.entries_total,
                           self.size, self.offset)
    
    @classmethod
    def new_with_defaults(cls, count: int, size: int, offset: int) -> EOCD64:
        return cls(
            signature=cls.MAGIC,
            size_minus_12=cls.SIZE - 12,
            version_made_by=DEFAULT_VERSION,
            version_needed=DEFAULT_VERSION,
            disk_number=0,
            disk_start=0,
            entries_this_disk=count,
            entries_total=count,
            size=size,
            offset=offset
        )

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
    
    def is_zip64(self) -> bool:
        return (self.disk_number == 0xFFFF and self.disk_start == 0xFFFF and
               self.entries_this_disk == 0xFFFF and self.entries_total == 0xFFFF and
               self.size == 0xFFFFFFFF and self.offset == 0xFFFFFFFF)

    @classmethod
    def new_for_zip64(cls) -> EOCD:
        return cls(
            signature=cls.MAGIC,
            disk_number=0xFFFF,
            disk_start=0xFFFF,
            entries_this_disk=0xFFFF,
            entries_total=0xFFFF,
            size=0xFFFFFFFF,
            offset=0xFFFFFFFF,
            comment_size=0
        )

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

async def _read_and_truncate_directory(file: anyio.AsyncFile) -> tuple[bytearray, int, bool]:
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

    return bytearray(data), endrec.entries_total, isinstance(endrec, EOCD64)

async def _read_endrec(file: anyio.AsyncFile) -> EOCD | EOCD64:
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
    if endrec.is_zip64():
        # End of Central Directory 64 Locator
        await file.seek(-EOCD.SIZE - EOCD64Locator.SIZE, 2)
        data = await file.read(EOCD64Locator.SIZE)
        if len(data) != EOCD64Locator.SIZE:
            raise ValueError("Zip file too small to contain zip64 end of central directory locator")
        if data[0:4] != EOCD64Locator.MAGIC:
            raise ValueError("Zip64 end of central directory locator magic number not found")

        # Read the EOCD64 locator
        locator = EOCD64Locator.from_bytes(data)
        if locator.disk_number != 0 or locator.disks != 1:
            raise ValueError("Zip file is split across multiple disks, not supported")
        
        # End of Central Directory 64
        await file.seek(locator.relative_offset)
        data = await file.read(EOCD64.SIZE)
        if len(data) != EOCD64.SIZE:
            raise ValueError("Zip file too small to contain zip64 end of central directory")
        if data[0:4] != EOCD64.MAGIC:
            raise ValueError("Zip64 end of central directory magic number not found")
        endrec = EOCD64.from_bytes(data)
        if endrec.size_minus_12 != EOCD64.SIZE - 12:
            raise ValueError("Unexpected size of zip64 end of central directory - extensible data sector not supported")

    if endrec.disk_number != 0 or endrec.disk_start != 0:
        raise ValueError("Zip file is split across multiple disks, not supported")
    if endrec.entries_this_disk != endrec.entries_total:
        raise ValueError("Zip file is split across multiple disks, not supported")
    
    return endrec

async def test_main():
    def random_bytes(n: int) -> bytes:
        return os.urandom(n)

    if os.path.exists("test.zip"):
        os.remove("test.zip")

    print("Creating test.zip")
    async with await anyio.open_file("test.zip", 'wb') as f:
        zip_file = AsyncZip(f)
        await zip_file.init()
        try:
            await zip_file.add_file("test.txt", random_bytes(0x80000000), compresslevel=6)
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
