import logging
import os
import struct
import io
import datetime
import subprocess
import sys
from dataclasses import dataclass
from enum import Enum
from typing import Optional, BinaryIO, Literal, Union
import zlib

logging.basicConfig(
    level=logging.INFO,
    format='%(levelname)s>> %(message)s',
    handlers=[logging.StreamHandler()]
)

logger = logging.getLogger(__name__)

K_VERS_1_12 = (1, 12, 0)  # PostgreSQL 9.0 - add separate BLOB entries
K_VERS_1_13 = (1, 13, 0)  # PostgreSQL 11 - change search_path behavior
K_VERS_1_14 = (1, 14, 0)  # PostgreSQL 12 - add tableam
K_VERS_1_15 = (1, 15, 0)  # PostgreSQL 16 - add compression_algorithm in header
K_VERS_1_16 = (1, 16, 0)  # PostgreSQL 17 - BLOB METADATA entries and multiple BLOBS, relkind
K_OFFSET_POS_SET = 2  # Entry has data and an offset
K_OFFSET_POS_NOT_SET = 1  # Offset not set is inline stream
BLK_DATA = b'\x01'
BLK_BLOBS = b'\x02'
BLK_END = b'\x04'
ZLIB_IN_SIZE = 4096


class PgDumbError(Exception):
    pass


class CompressionMethod(Enum):
    NONE = "none"
    GZIP = "gzip"
    ZLIB = "zlib"
    LZ4 = "lz4"

    def __str__(self):
        return self.value


CompressionMethodType = Union[
    Literal[
        CompressionMethod.ZLIB,
        CompressionMethod.NONE,
        CompressionMethod.GZIP
    ],
    CompressionMethod,
]


@dataclass
class TocEntry:
    dump_id: int
    section: str
    had_dumper: bool
    tag: Optional[str]
    tablespace: Optional[str]
    namespace: Optional[str]
    tableam: Optional[str]
    owner: Optional[str]
    desc: Optional[str]
    defn: Optional[str]
    drop_stmt: Optional[str]
    copy_stmt: Optional[str]
    with_oids: Optional[str]
    oid: Optional[str]
    table_oid: Optional[str]
    data_state: int
    offset: int


@dataclass
class Header:
    magic: bytes
    version: tuple[int, int, int]
    database_name: str
    server_version: str
    pgdump_version: str
    compression_method: CompressionMethodType
    create_date: datetime.datetime


@dataclass
class Dump:
    header: Header
    toc_entries: list[TocEntry]


class CombinedStream(io.BufferedReader):
    """Объединяет два потока в один последовательный поток."""

    def __init__(self, first_stream, second_stream):
        self.first_stream = first_stream
        self.second_stream = second_stream
        super().__init__(io.BytesIO(b''))  # Инициализация базового класса

    def read(self, size=-1):
        # Сначала читаем из первого потока
        data = self.first_stream.read(size)
        if size == -1 or len(data) < size:
            # Если нужно больше данных, читаем из второго потока
            remaining = size - len(data) if size != -1 else -1
            more_data = self.second_stream.read(remaining)
            data += more_data
        return data


class DumpIO:
    def __init__(self):
        self.int_size: int = 4
        self.offset_size: int = 8

    def read_byte(self, buffer: BinaryIO) -> int:
        """Читает один байт из потока."""
        try:
            return struct.unpack('B', buffer.read(1))[0]
        except struct.error:
            raise PgDumbError("Unexpected EOF while reading byte")

    def read_int(self, buffer: BinaryIO) -> int:
        """Читает целое число с учетом знака."""
        sign = self.read_byte(buffer)
        if sign is None:
            return None
        bs, bv, value = 0, 0, 0
        for _ in range(self.int_size):
            bv = (self.read_byte(buffer) or 0) & 0xFF
            if bv != 0:
                value += (bv << bs)
            bs += 8
        return -value if sign else value

    def read_string(self, buffer: BinaryIO) -> str:
        """Читает строку с длиной, закодированную в UTF-8."""
        length = self.read_int(buffer)
        if length <= 0:
            return ""
        data = buffer.read(length)
        if len(data) != length:
            raise PgDumbError("Unexpected EOF while reading string")
        return data.decode('utf-8')

    def read_data(self, buffer: BinaryIO, offset: int) -> BinaryIO:
        """Читает блок данных по смещению."""
        buffer.seek(offset)
        block_type = buffer.read(1)
        if not block_type:
            raise PgDumbError("Unexpected EOF while reading block type")

        dump_id = self.read_int(buffer)
        if block_type != BLK_DATA:
            raise PgDumbError(f"Expected BLK_DATA, got {block_type!r}")

        size = self.read_int(buffer)
        data = buffer.read(size)
        if len(data) != size:
            raise PgDumbError("Unexpected EOF while reading data block")

        return io.BytesIO(data)

    def read_stream_data(self, buffer: io.BytesIO, stream: BinaryIO, data_len: int) -> bytes:
        data = buffer.read(data_len)
        while len(data) < data_len:
            more = stream.read(data_len - len(data))
            if not more:
                raise PgDumbError("Unexpected EOF in BLK_DATA")
            data += more
        return data

    def write_int(self, value: int) -> bytes:
        is_negative = value < 0
        value = abs(value)
        out = bytearray()
        out.append(1 if is_negative else 0)
        for i in range(self.int_size):
            out.append((value >> (i * 8)) & 0xFF)
        return bytes(out)


def parse_header_and_toc_entries(buffer: BinaryIO, dump_io: DumpIO) -> 'Dump':
    """Читает и парсит заголовок архива из потока."""
    magic = buffer.read(5)
    if magic != b'PGDMP':
        raise PgDumbError("File does not start with PGDMP")

    version = (
        dump_io.read_byte(buffer),
        dump_io.read_byte(buffer),
        dump_io.read_byte(buffer)
    )

    if version < K_VERS_1_12 or version > K_VERS_1_16:
        raise PgDumbError(f"Unsupported version: {version[0]}.{version[1]}.{version[2]}")

    dump_io.int_size = dump_io.read_byte(buffer)
    dump_io.offset_size = dump_io.read_byte(buffer)

    format_byte = dump_io.read_byte(buffer)
    if format_byte != 1:  # 1 = archCustom
        raise PgDumbError("File format must be 1 (custom)")

    if version >= K_VERS_1_15:
        compression_byte = dump_io.read_byte(buffer)
        compression_map = {
            0: CompressionMethod.NONE,
            1: CompressionMethod.GZIP,
            2: CompressionMethod.LZ4,
            3: CompressionMethod.ZLIB,
        }
        compression_method = compression_map.get(compression_byte, None)
        if compression_method is None:
            raise PgDumbError("Invalid compression method")
    else:
        compression = dump_io.read_int(buffer)
        if compression == -1:
            compression_method = CompressionMethod.ZLIB
        elif compression == 0:
            compression_method = CompressionMethod.NONE
        elif 1 <= compression <= 9:
            compression_method = CompressionMethod.GZIP
        else:
            raise PgDumbError("Invalid compression method")

    created_sec = dump_io.read_int(buffer)
    created_min = dump_io.read_int(buffer)
    created_hour = dump_io.read_int(buffer)
    created_mday = dump_io.read_int(buffer)
    created_mon = dump_io.read_int(buffer)
    created_year = dump_io.read_int(buffer)
    _created_isdst = dump_io.read_int(buffer)

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

    database_name = dump_io.read_string(buffer)
    server_version = dump_io.read_string(buffer)
    pgdump_version = dump_io.read_string(buffer)

    toc_entries = parse_toc_entries(buffer, dump_io, version)

    return Dump(
        header=Header(
            magic=magic,
            version=version,
            compression_method=compression_method,
            create_date=create_date,
            database_name=database_name,
            server_version=server_version,
            pgdump_version=pgdump_version,
        ),
        toc_entries=toc_entries,
    )


def parse_toc_entries(buffer: BinaryIO, dump_io: DumpIO, version: tuple[int, int, int]) -> list[TocEntry]:
    """Упрощённая реализация чтения ToC."""
    num_entries = dump_io.read_int(buffer)
    toc_entries = []
    for _ in range(num_entries):
        dump_id = dump_io.read_int(buffer)
        had_dumper = bool(dump_io.read_int(buffer))
        table_oid = dump_io.read_string(buffer)
        oid = dump_io.read_string(buffer)
        tag = dump_io.read_string(buffer)
        desc = dump_io.read_string(buffer)
        section_idx = dump_io.read_int(buffer)
        section = [
            "SECTION_PRE_DATA",
            "SECTION_DATA",
            "SECTION_POST_DATA",
            "SECTION_NONE"
        ][section_idx - 1] if 1 <= section_idx <= 4 else "SECTION_NONE"
        defn = dump_io.read_string(buffer)
        drop_stmt = dump_io.read_string(buffer)
        copy_stmt = dump_io.read_string(buffer)
        namespace = dump_io.read_string(buffer)
        tablespace = dump_io.read_string(buffer)
        tableam = None
        if version >= K_VERS_1_14:
            tableam = dump_io.read_string(buffer)
        owner = dump_io.read_string(buffer)
        with_oids = dump_io.read_string(buffer)

        dependencies = []
        while True:
            dep = dump_io.read_string(buffer)
            if not dep:
                break
            dependencies.append(int(dep))
        data_state = dump_io.read_byte(buffer)
        offset = 0
        for _ in range(dump_io.offset_size):
            bv = dump_io.read_byte(buffer)
            offset |= bv << (_ * 8)

        toc_entries.append(
            TocEntry(
                dump_id=dump_id,
                had_dumper=had_dumper,
                tag=tag,
                desc=desc,
                section=section,
                defn=defn,
                copy_stmt=copy_stmt,
                drop_stmt=drop_stmt,
                namespace=namespace,
                tablespace=tablespace,
                tableam=tableam,
                data_state=data_state,
                owner=owner,
                offset=offset,
                with_oids=with_oids,
                table_oid=table_oid,
                oid=oid,
            )
        )
    return toc_entries


def modify_data_block(data: bytes) -> bytes:
    lines = data.decode('utf-8')
    lines = lines.replace('live.com', 'obfuscated.live.com')
    return lines.encode('utf-8')


def parse_dump(stdin: io.BufferedReader, stdout: io.BufferedWriter):
    """Обрабатывает потоковый дамп PostgreSQL с правильным разделением заголовка и данных."""
    dump_io = DumpIO()

    # Этап 1: Чтение ровно столько данных, сколько нужно для заголовка и TOC
    header_data = io.BytesIO()
    dump = None
    while dump is None:
        chunk = stdin.read(4096)
        if not chunk:
            raise PgDumbError("Unexpected EOF while reading header/TOC")
        header_data.write(chunk)
        header_data.seek(0)
        try:
            dump = parse_header_and_toc_entries(header_data, dump_io)
        except PgDumbError:
            header_data.seek(0, io.SEEK_END)

    # Получаем позицию, до которой мы прочитали (конец TOC)
    toc_end_pos = header_data.tell()
    header_data.seek(0)

    # Записываем заголовок и TOC в вывод
    stdout.write(header_data.read(toc_end_pos))
    stdout.flush()

    # Оставшиеся данные (если мы прочитали больше, чем нужно) - это начало данных дампа
    remaining_data = header_data.read()

    # Создаем объединенный поток для обработки данных
    if remaining_data:
        # Если есть остаток, создаем цепочку: остаток + stdin
        data_stream = io.BytesIO(remaining_data)
        data_stream = CombinedStream(data_stream, stdin)
    else:
        # Если остатка нет, используем просто stdin
        data_stream = stdin

    # Обрабатываем блоки данных
    process_data_blocks(data_stream, stdout, dump, dump_io)

    stdout.write(stdin.read())
    stdout.flush()


def process_data_blocks(
    input_stream: Union[io.BufferedReader, CombinedStream],
    output_stream: io.BufferedWriter,
    dump: Dump,
    dump_io: DumpIO
):
    """Обрабатывает блоки данных с учетом сжатия."""
    block_type = input_stream.read(1)
    if block_type == BLK_DATA:
        dump_ids_table_data = {entry.dump_id for entry in dump.toc_entries if entry.desc == "TABLE DATA"}
        buffer = io.BytesIO()
        chunk = b''
        decompressor = zlib.decompressobj()

        dump_id = dump_io.read_int(input_stream)
        if dump_id in dump_ids_table_data:
            while True:
                chunk_size = dump_io.read_int(input_stream)
                if not chunk_size:
                    break
                chunk += input_stream.read(chunk_size)
                buffer.write(decompressor.decompress(chunk))
                chunk = decompressor.unconsumed_tail
                if chunk_size < ZLIB_IN_SIZE:
                    break
            buffer.write(decompressor.flush())
            new_data = modify_data_block(buffer.getvalue())

            new_compressed = zlib.compress(new_data)

            # Запись в stdout
            output_stream.write(BLK_DATA)
            output_stream.write(dump_io.write_int(dump_id))
            output_stream.write(dump_io.write_int(len(new_compressed)))
            output_stream.write(new_compressed)
            output_stream.flush()
    else:
        output_stream.write(block_type)


if __name__ == "__main__":
    env = os.environ.copy()
    env['PGHOST'] = 'localhost'
    env['PGPORT'] = '5432'
    env['PGUSER'] = '<secret>'
    env['PGPASSWORD'] = '<secret>'
    env['PGDATABASE'] = '<secret>'
    process = subprocess.Popen(
        ['pg_dump', '-Fc'],  # можно указать определенную таблицу  '-t', 'auth_user'
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )
    parse_dump(process.stdout, sys.stdout.buffer)
