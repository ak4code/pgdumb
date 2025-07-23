import struct
import io
import datetime
import sys
from enum import Enum
from typing import List, Tuple, Optional, BinaryIO
import gzip
import zlib

K_VERS_1_12 = (1, 12, 0)  # PostgreSQL 9.0 - add separate BLOB entries
K_VERS_1_13 = (1, 13, 0)  # PostgreSQL 11 - change search_path behavior
K_VERS_1_14 = (1, 14, 0)  # PostgreSQL 12 - add tableam
K_VERS_1_15 = (1, 15, 0)  # PostgreSQL 16 - add compression_algorithm in header
K_VERS_1_16 = (1, 16, 0)  # PostgreSQL 17 - BLOB METADATA entries and multiple BLOBS, relkind
K_OFFSET_POS_SET = 2  # Entry has data and an offset


class PgDumbError(Exception):
    pass


class CompressionMethod(Enum):
    NONE = "none"
    GZIP = "gzip"
    ZLIB = "zlib"
    LZ4 = "lz4"

    def __str__(self):
        return self.value


class TocEntry:
    def __init__(self, dump_id: int, section: str, desc: str, tag: str, offset: int):
        self.dump_id = dump_id
        self.section = section
        self.desc = desc
        self.tag = tag
        self.offset = offset


class ReadConfig:
    def __init__(self):
        self.int_size: int = 4
        self.offset_size: int = 8

    def read_byte(self, f: BinaryIO) -> int:
        """Читает один байт из потока."""
        try:
            return struct.unpack('B', f.read(1))[0]
        except struct.error:
            raise PgDumbError("Unexpected EOF while reading byte")

    def read_int(self, f: BinaryIO) -> int:
        """Читает целое число с учетом знака."""
        sign = self.read_byte(f)
        value = 0
        for _ in range(self.int_size):
            bv = self.read_byte(f)
            value |= bv << (_ * 8)
        return -value if sign else value

    def read_string(self, f: BinaryIO) -> str:
        """Читает строку с длиной, закодированную в UTF-8."""
        length = self.read_int(f)
        if length <= 0:
            return ""
        data = f.read(length)
        if len(data) != length:
            raise PgDumbError("Unexpected EOF while reading string")
        return data.decode('utf-8')

    def read_data(self, f: BinaryIO, offset: int) -> BinaryIO:
        """Читает блок данных по смещению."""
        f.seek(offset)
        block_type = f.read(1)
        if not block_type:
            raise PgDumbError("Unexpected EOF while reading block type")

        dump_id = self.read_int(f)
        if block_type != b'\x01':  # BLK_DATA
            raise PgDumbError(f"Expected BLK_DATA, got {block_type!r}")

        size = self.read_int(f)
        data = f.read(size)
        if len(data) != size:
            raise PgDumbError("Unexpected EOF while reading data block")

        return io.BytesIO(data)

    def write_int(self, value: int) -> bytes:
        is_negative = value < 0
        value = abs(value)
        out = bytearray()
        out.append(1 if is_negative else 0)
        for i in range(self.int_size):
            out.append((value >> (i * 8)) & 0xFF)
        return bytes(out)


class PgDumb:
    def __init__(
        self, version: Tuple[int, int, int], compression_method: CompressionMethod,
        create_date: datetime.datetime, database_name: str,
        server_version: str, pgdump_version: str, toc_entries: List[TocEntry]
    ):
        self.version = version
        self.compression_method = compression_method
        self.create_date = create_date
        self.database_name = database_name
        self.server_version = server_version
        self.pgdump_version = pgdump_version
        self.toc_entries = toc_entries
        self.io_config = ReadConfig()

    def __str__(self) -> str:
        return f"version={self.version[0]}.{self.version[1]}.{self.version[2]} compression={self.compression_method}"

    @classmethod
    def parse(cls, f: BinaryIO) -> 'PgDumb':
        """Читает и парсит заголовок архива из потока."""
        # Читаем магическую строку
        magic = f.read(5)
        if magic != b'PGDMP':
            raise PgDumbError("File does not start with PGDMP")

        io_config = ReadConfig()

        version = (
            io_config.read_byte(f),
            io_config.read_byte(f),
            io_config.read_byte(f)
        )

        if version < K_VERS_1_12 or version > K_VERS_1_16:
            raise PgDumbError(f"Unsupported version: {version[0]}.{version[1]}.{version[2]}")

        io_config.int_size = io_config.read_byte(f)
        io_config.offset_size = io_config.read_byte(f)

        format_byte = io_config.read_byte(f)
        if format_byte != 1:  # 1 = archCustom
            raise PgDumbError("File format must be 1 (custom)")

        if version >= K_VERS_1_15:
            compression_byte = io_config.read_byte(f)
            compression_map = {0: CompressionMethod.NONE, 1: CompressionMethod.GZIP, 2: CompressionMethod.LZ4,
                3: CompressionMethod.ZLIB}
            compression_method = compression_map.get(compression_byte, None)
            if compression_method is None:
                raise PgDumbError("Invalid compression method")
        else:
            compression = io_config.read_int(f)
            if compression == -1:
                compression_method = CompressionMethod.ZLIB
            elif compression == 0:
                compression_method = CompressionMethod.NONE
            elif 1 <= compression <= 9:
                compression_method = CompressionMethod.GZIP
            else:
                raise PgDumbError("Invalid compression method")

        created_sec = io_config.read_int(f)
        created_min = io_config.read_int(f)
        created_hour = io_config.read_int(f)
        created_mday = io_config.read_int(f)
        created_mon = io_config.read_int(f)
        created_year = io_config.read_int(f)
        _created_isdst = io_config.read_int(f)

        try:
            create_date = datetime.datetime(
                year=created_year + 1900,
                month=created_mon + 1,
                day=created_mday,
                hour=created_hour,
                minute=created_min,
                second=created_sec
            )
        except ValueError:
            raise PgDumbError("Invalid creation date")

        database_name = io_config.read_string(f)
        server_version = io_config.read_string(f)
        pgdump_version = io_config.read_string(f)

        toc_entries = read_toc(f, io_config, version)

        return cls(
            version=version,
            compression_method=compression_method,
            create_date=create_date,
            database_name=database_name,
            server_version=server_version,
            pgdump_version=pgdump_version,
            toc_entries=toc_entries
        )

    def find_toc_entry(self, section: str, desc: str, tag: str) -> Optional[TocEntry]:
        """Находит запись в оглавлении по секции, описанию и тегу."""
        for entry in self.toc_entries:
            print(entry.section, entry.desc, entry.tag)
            if entry.section == section and entry.desc == desc and entry.tag == tag:
                return entry
        return None

    def read_data(self, f: BinaryIO, entry: TocEntry) -> BinaryIO:
        """Читает данные для записи ToC, обрабатывая сжатие."""
        reader = self.io_config.read_data(f, entry.offset)
        if self.compression_method == CompressionMethod.NONE:
            return reader
        elif self.compression_method == CompressionMethod.GZIP:
            return gzip.GzipFile(fileobj=reader, mode='rb')
        elif self.compression_method == CompressionMethod.ZLIB:
            return io.BytesIO(zlib.decompress(reader.read()))
        else:
            raise PgDumbError(f"Compression method {self.compression_method} not supported")


def read_toc(f: BinaryIO, io_config: ReadConfig, version: Tuple[int, int, int]) -> List[TocEntry]:
    """Упрощённая реализация чтения ToC (заглушка, так как оригинал не предоставлен)."""
    num_entries = io_config.read_int(f)
    toc_entries = []
    for _ in range(num_entries):
        dump_id = io_config.read_int(f)
        had_dumper = bool(io_config.read_int(f))
        table_oid = io_config.read_string(f)
        oid = io_config.read_string(f)
        tag = io_config.read_string(f)
        desc = io_config.read_string(f)
        section_idx = io_config.read_int(f)
        section = ["SECTION_PRE_DATA", "SECTION_DATA", "SECTION_POST_DATA", "SECTION_NONE"][
            section_idx - 1] if 1 <= section_idx <= 4 else "SECTION_NONE"
        io_config.read_string(f)  # defn
        io_config.read_string(f)  # drop_stmt
        io_config.read_string(f)  # copy_stmt
        io_config.read_string(f)  # namespace
        io_config.read_string(f)  # tablespace
        if version >= K_VERS_1_14:
            io_config.read_string(f)  # tableam
        io_config.read_string(f)  # owner
        io_config.read_string(f)  # with_oids
        # Читаем зависимости
        dependencies = []
        while True:
            dep = io_config.read_string(f)
            if not dep:
                break
            dependencies.append(int(dep))
        data_state = io_config.read_byte(f)
        offset = 0
        for _ in range(io_config.offset_size):
            bv = io_config.read_byte(f)
            offset |= bv << (_ * 8)
        if data_state == K_OFFSET_POS_SET:  # K_OFFSET_POS_SET
            toc_entries.append(TocEntry(dump_id, section, desc, tag, offset))
    return toc_entries


def modify_data_block(data: bytes) -> bytes:
    lines = data.decode('utf-8')
    lines = lines.replace('row', 'xxxx')
    return lines.encode('utf-8')


def main():
    # Прочитать весь дамп из stdin
    raw = sys.stdin.buffer.read()
    dump_io = io.BytesIO(raw)

    dump = PgDumb.parse(dump_io)

    # Копия дампа для модификации
    output = io.BytesIO()
    output.write(raw[:dump.toc_entries[0].offset])  # записываем заголовок и TOC

    for entry in dump.toc_entries:
        if entry.desc == 'TABLE DATA':
            data = dump.read_data(dump_io, entry).read()
            new_data = modify_data_block(data)

            # Сжатие данных обратно
            if dump.compression_method == CompressionMethod.NONE:
                compressed = new_data
            elif dump.compression_method == CompressionMethod.GZIP:
                buf = io.BytesIO()
                with gzip.GzipFile(fileobj=buf, mode='wb') as gz:
                    gz.write(new_data)
                compressed = buf.getvalue()
            elif dump.compression_method == CompressionMethod.ZLIB:
                compressed = zlib.compress(new_data)
            else:
                raise NotImplementedError(f"Unsupported compression: {dump.compression_method}")

            # Сборка BLK_DATA
            output.write(b'\x01')  # BLK_DATA
            output.write(dump.io_config.write_int(entry.dump_id))
            output.write(dump.io_config.write_int(len(compressed)))
            output.write(compressed)
        else:
            # Просто копируем другие блоки
            data = dump.read_data(dump_io, entry).read()
            output.write(b'\x01')
            output.write(dump.io_config.write_int(entry.dump_id))
            output.write(dump.io_config.write_int(len(data)))
            output.write(data)

    sys.stdout.buffer.write(output.getvalue())


if __name__ == "__main__":
    main()
