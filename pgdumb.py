import logging
import struct
import io
import datetime
import sys
from enum import Enum
from typing import Optional, BinaryIO
import gzip
import zlib

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)

logger = logging.getLogger(__name__)

K_VERS_1_12 = (1, 12, 0)  # PostgreSQL 9.0 - add separate BLOB entries
K_VERS_1_13 = (1, 13, 0)  # PostgreSQL 11 - change search_path behavior
K_VERS_1_14 = (1, 14, 0)  # PostgreSQL 12 - add tableam
K_VERS_1_15 = (1, 15, 0)  # PostgreSQL 16 - add compression_algorithm in header
K_VERS_1_16 = (1, 16, 0)  # PostgreSQL 17 - BLOB METADATA entries and multiple BLOBS, relkind
K_OFFSET_POS_SET = 2  # Entry has data and an offset
BLK_DATA = b'\x01'

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
    def __init__(self, dump_id: int, section: str, desc: str, tag: str, offset: int, defn: Optional[str] = None):
        self.dump_id = dump_id
        self.section = section
        self.desc = desc
        self.tag = tag
        self.offset = offset
        self.defn = defn

class StreamHandler:
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
        if block_type != BLK_DATA:
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
        self,
        version: tuple[int, int, int],
        compression_method: CompressionMethod,
        create_date: datetime.datetime,
        database_name: str,
        server_version: str,
        pgdump_version: str,
        toc_entries: list[TocEntry],
        comment_lines: list[str],
    ):
        self.version = version
        self.compression_method = compression_method
        self.create_date = create_date
        self.database_name = database_name
        self.server_version = server_version
        self.pgdump_version = pgdump_version
        self.toc_entries = toc_entries
        self.io_config = StreamHandler()
        self.comment_lines = []

    def __str__(self) -> str:
        return f"version={self.version[0]}.{self.version[1]}.{self.version[2]} compression={self.compression_method}"

    @classmethod
    def parse(cls, buffer: BinaryIO) -> 'PgDumb':
        """Читает и парсит заголовок архива из потока."""
        # Читаем магическую строку
        magic = buffer.read(5)
        if magic != b'PGDMP':
            raise PgDumbError("File does not start with PGDMP")

        stream_handler = StreamHandler()

        version = (
            stream_handler.read_byte(buffer),
            stream_handler.read_byte(buffer),
            stream_handler.read_byte(buffer)
        )

        if version < K_VERS_1_12 or version > K_VERS_1_16:
            raise PgDumbError(f"Unsupported version: {version[0]}.{version[1]}.{version[2]}")

        stream_handler.int_size = stream_handler.read_byte(buffer)
        stream_handler.offset_size = stream_handler.read_byte(buffer)

        format_byte = stream_handler.read_byte(buffer)
        if format_byte != 1:  # 1 = archCustom
            raise PgDumbError("File format must be 1 (custom)")

        if version >= K_VERS_1_15:
            compression_byte = stream_handler.read_byte(buffer)
            compression_map = {0: CompressionMethod.NONE, 1: CompressionMethod.GZIP, 2: CompressionMethod.LZ4,
                3: CompressionMethod.ZLIB}
            compression_method = compression_map.get(compression_byte, None)
            if compression_method is None:
                raise PgDumbError("Invalid compression method")
        else:
            compression = stream_handler.read_int(buffer)
            if compression == -1:
                compression_method = CompressionMethod.ZLIB
            elif compression == 0:
                compression_method = CompressionMethod.NONE
            elif 1 <= compression <= 9:
                compression_method = CompressionMethod.GZIP
            else:
                raise PgDumbError("Invalid compression method")

        created_sec = stream_handler.read_int(buffer)
        created_min = stream_handler.read_int(buffer)
        created_hour = stream_handler.read_int(buffer)
        created_mday = stream_handler.read_int(buffer)
        created_mon = stream_handler.read_int(buffer)
        created_year = stream_handler.read_int(buffer)
        _created_isdst = stream_handler.read_int(buffer)

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

        database_name = stream_handler.read_string(buffer)
        server_version = stream_handler.read_string(buffer)
        pgdump_version = stream_handler.read_string(buffer)

        toc_entries, comment_lines = read_toc(buffer, stream_handler, version)

        return cls(
            version=version,
            compression_method=compression_method,
            create_date=create_date,
            database_name=database_name,
            server_version=server_version,
            pgdump_version=pgdump_version,
            toc_entries=toc_entries,
            comment_lines=comment_lines,
        )

    def find_toc_entry(self, section: str, desc: str, tag: str) -> Optional[TocEntry]:
        """Находит запись в оглавлении по секции, описанию и тегу."""
        for entry in self.toc_entries:
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
            data = reader.read()
            logger.info(data)
            return io.BytesIO(zlib.decompress(data))
        else:
            raise PgDumbError(f"Compression method {self.compression_method} not supported")


def read_toc(
    buffer: BinaryIO,
    stream_handler: StreamHandler,
    version: tuple[int, int, int],
) -> tuple[list[TocEntry], list[str]]:
    """Упрощённая реализация чтения ToC (заглушка, так как оригинал не предоставлен)."""
    num_entries = stream_handler.read_int(buffer)
    toc_entries = []
    comment_lines = []
    for _ in range(num_entries):
        dump_id = stream_handler.read_int(buffer)
        had_dumper = bool(stream_handler.read_int(buffer))
        table_oid = stream_handler.read_string(buffer)
        oid = stream_handler.read_string(buffer)
        tag = stream_handler.read_string(buffer)
        desc = stream_handler.read_string(buffer)
        section_idx = stream_handler.read_int(buffer)
        section = ["SECTION_PRE_DATA", "SECTION_DATA", "SECTION_POST_DATA", "SECTION_NONE"][
            section_idx - 1] if 1 <= section_idx <= 4 else "SECTION_NONE"
        defn = stream_handler.read_string(buffer)
        drop_stmt = stream_handler.read_string(buffer)
        copy_stmt = stream_handler.read_string(buffer)
        namespace = stream_handler.read_string(buffer)
        tablespace = stream_handler.read_string(buffer)
        if version >= K_VERS_1_14:
            tableam = stream_handler.read_string(buffer)
        owner = stream_handler.read_string(buffer)
        with_oids = stream_handler.read_string(buffer)
        # Читаем зависимости
        dependencies = []
        while True:
            dep = stream_handler.read_string(buffer)
            if not dep:
                break
            dependencies.append(int(dep))
        data_state = stream_handler.read_byte(buffer)
        offset = 0
        for _ in range(stream_handler.offset_size):
            bv = stream_handler.read_byte(buffer)
            offset |= bv << (_ * 8)
        if section == 'SECTION_PRE_DATA' and desc.startswith('COMMENT') and tag.startswith('COLUMN'):
            comment_lines.append(defn)
        if data_state == K_OFFSET_POS_SET:  # K_OFFSET_POS_SET
            toc_entries.append(TocEntry(dump_id, section, desc, tag, offset, defn))
    return toc_entries, comment_lines


def modify_data_block(data: bytes) -> bytes:
    lines = data.decode('utf-8')
    lines = lines.replace('example.com', 'rambler.ru')
    return lines.encode('utf-8')


def main():
    # Прочитать весь дамп из stdin
    raw = sys.stdin.buffer.read()
    buffer = io.BytesIO(raw)

    dump = PgDumb.parse(buffer)

    first_entry = min(dump.toc_entries, key=lambda e: e.offset)
    # Копия дампа для модификации
    output = io.BytesIO()
    output.write(raw[:first_entry.offset])  # записываем заголовок и TOC

    for entry in dump.toc_entries:
        if entry.desc == 'TABLE DATA':
            data = dump.read_data(buffer, entry).read()
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
                logger.info(compressed)
            else:
                raise NotImplementedError(f"Unsupported compression: {dump.compression_method}")

            # Сборка BLK_DATA
            output.write(BLK_DATA)
            output.write(dump.io_config.write_int(entry.dump_id))
            output.write(dump.io_config.write_int(len(compressed)))
            output.write(compressed)
        # else:
        #     # Просто копируем другие блоки
        #     data = dump.read_data(buffer, entry).read()
        #     output.write(b'\x01')
        #     output.write(dump.io_config.write_int(entry.dump_id))
        #     output.write(dump.io_config.write_int(len(data)))
        #     output.write(data)
    # logger.info()
    last_entry = max(dump.toc_entries, key=lambda e: e.offset)
    buffer.seek(last_entry.offset)
    _ = buffer.read(1)  # b'\x01'
    _ = dump.io_config.read_int(buffer)  # dump_id
    length = dump.io_config.read_int(buffer)
    buffer.seek(length, io.SEEK_CUR)
    end_position = buffer.tell()
    output.write(raw[end_position:])

    sys.stdout.buffer.write(output.getvalue())


if __name__ == "__main__":
    main()
