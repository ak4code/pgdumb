import logging
import os
import struct
import io
import datetime
import subprocess
import sys
import zlib
from abc import ABCMeta, abstractmethod
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import Enum
from typing import BinaryIO, Dict, Iterator, List, Optional, Union

from pg_stage.obfuscator import Obfuscator

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)

logger = logging.getLogger(__name__)

Version = tuple[int, int, int]
DumpId = int
Offset = int


class PostgreSQLVersions:
    """Константы версий PostgreSQL для совместимости формата дампов."""
    V1_12 = (1, 12, 0)
    V1_13 = (1, 13, 0)
    V1_14 = (1, 14, 0)
    V1_15 = (1, 15, 0)
    V1_16 = (1, 16, 0)


class OffsetPosition:
    """Константы позиции смещения."""
    SET = 2
    NOT_SET = 1


class BlockType:
    """Идентификаторы типов блоков."""
    DATA = b'\x01'
    BLOBS = b'\x02'
    END = b'\x04'


class Constants:
    """Общие константы."""
    MAGIC_HEADER = b'PGDMP'
    CUSTOM_FORMAT = 1
    ZLIB_CHUNK_SIZE = 4096
    DEFAULT_BUFFER_SIZE = 8192


class PgDumpError(Exception):
    """Базовое исключение для ошибок обработки дампов PostgreSQL."""
    pass


class CompressionMethod(Enum):
    """Поддерживаемые методы сжатия."""
    NONE = "none"
    GZIP = "gzip"
    ZLIB = "zlib"
    LZ4 = "lz4"

    def __str__(self) -> str:
        return self.value


class SectionType(Enum):
    """Типы секций дампа."""
    PRE_DATA = "SECTION_PRE_DATA"
    DATA = "SECTION_DATA"
    POST_DATA = "SECTION_POST_DATA"
    NONE = "SECTION_NONE"


@dataclass(frozen=True)
class DatabaseConnection:
    """Конфигурация подключения к базе данных."""
    host: str = 'localhost'
    port: str = '5432'
    user: str = ''
    password: str = ''
    database: str = ''

    def to_env_dict(self) -> Dict[str, str]:
        """
        Преобразование в словарь переменных окружения.
        :return: словарь переменных окружения для PostgreSQL
        """
        return {
            'PGHOST': self.host,
            'PGPORT': self.port,
            'PGUSER': self.user,
            'PGPASSWORD': self.password,
            'PGDATABASE': self.database,
        }


@dataclass(frozen=True)
class Header:
    """Информация заголовка файла дампа PostgreSQL."""
    magic: bytes
    version: Version
    database_name: str
    server_version: str
    pgdump_version: str
    compression_method: CompressionMethod
    create_date: datetime.datetime
    int_size: int = 4
    offset_size: int = 8


@dataclass(frozen=True)
class TocEntry:
    """Запись оглавления (Table of Contents)."""
    dump_id: DumpId
    section: SectionType
    had_dumper: bool
    tag: Optional[str] = None
    tablespace: Optional[str] = None
    namespace: Optional[str] = None
    tableam: Optional[str] = None
    owner: Optional[str] = None
    desc: Optional[str] = None
    defn: Optional[str] = None
    drop_stmt: Optional[str] = None
    copy_stmt: Optional[str] = None
    with_oids: Optional[str] = None
    oid: Optional[str] = None
    table_oid: Optional[str] = None
    data_state: int = 0
    offset: Offset = 0
    dependencies: List[DumpId] = field(default_factory=list)


@dataclass(frozen=True)
class Dump:
    """Полная структура файла дампа."""
    header: Header
    toc_entries: List[TocEntry]

    def get_table_data_entries(self) -> Iterator[TocEntry]:
        """
        Получить все записи данных таблиц.
        :return: итератор записей с данными таблиц
        """
        return (entry for entry in self.toc_entries if entry.desc == "TABLE DATA")

    def get_comment_entries(self) -> Iterator[TocEntry]:
        """
        Получить все записи комментариев.
        :return: итератор записей комментариев
        """
        return (entry for entry in self.toc_entries if entry.desc == "COMMENT")

    def get_entry_by_id(self, dump_id: DumpId) -> Optional[TocEntry]:
        """
        Найти запись TOC по ID дампа.
        :param dump_id: идентификатор записи в дампе
        :return: запись TOC или None
        """
        return next((entry for entry in self.toc_entries if entry.dump_id == dump_id), None)


class DataProcessor(metaclass=ABCMeta):
    """Протокол для реализации обработчиков данных."""

    @abstractmethod
    def process(self, data: Union[str, bytes]) -> Union[str, bytes]:
        """
        Обработать данные и вернуть модифицированную версию.
        :param data: исходные данные (строка или байты)
        :return: обработанные данные
        """
        raise NotImplementedError()


class ObfuscatorProcessor(DataProcessor):
    """Процессор обфускации из библиотеки pg_stage."""

    def __init__(self, processor: Obfuscator, encoding: str = 'utf-8'):
        """
        Инициализация процессора обфускации.
        :param processor: экземпляр обфускатора
        :param encoding: кодировка для работы с текстом
        """
        self.encoding = encoding
        self.processor = processor

    def process(self, data: Union[str, bytes]) -> Union[str, bytes]:
        """
        Применить замены текста к данным.
        :param data: исходные данные (строка или байты)
        :return: обработанные данные
        """
        if isinstance(data, str):
            return self.processor._parse_line(line=data)

        try:
            lines = data.decode('utf-8').splitlines()
            processed_lines = [self.processor._parse_line(line=line) for line in lines]
            return '\n'.join(processed_lines).encode(self.encoding)
        except UnicodeDecodeError as e:
            logger.warning(f"Failed to decode data as {self.encoding}: {e}")
            return data


class StreamCombiner:
    """Объединяет несколько потоков в один последовательный поток."""

    def __init__(self, *streams: BinaryIO):
        """
        Инициализация с несколькими потоками.
        :param streams: потоки для объединения
        """
        self.streams = list(streams)
        self.current_index = 0

    def read(self, size: int = -1) -> bytes:
        """
        Чтение данных из потоков последовательно.
        :param size: количество байт для чтения
        :return: прочитанные данные
        """
        if self.current_index >= len(self.streams):
            return b''

        data = self.streams[self.current_index].read(size)

        if size != -1 and len(data) < size and data != b'':
            remaining = size - len(data)
            self.current_index += 1
            more_data = self.read(remaining)
            data += more_data
        elif not data:
            self.current_index += 1
            return self.read(size)

        return data


class DumpIO:
    """Утилиты бинарного I/O для формата дампов PostgreSQL."""

    def __init__(self, int_size: int = 4, offset_size: int = 8):
        """
        Инициализация с размерами типов данных.
        :param int_size: размер целого числа в байтах
        :param offset_size: размер смещения в байтах
        """
        self.int_size = int_size
        self.offset_size = offset_size

    def read_byte(self, stream: BinaryIO) -> int:
        """
        Чтение одного байта.
        :param stream: поток для чтения
        :return: значение байта
        """
        data = stream.read(1)
        if not data:
            raise PgDumpError("Unexpected EOF while reading byte")
        return struct.unpack('B', data)[0]

    def read_int(self, stream: BinaryIO) -> int:
        """
        Чтение знакового целого числа с переменным размером.
        :param stream: поток для чтения
        :return: значение целого числа
        """
        sign = self.read_byte(stream)
        value = 0

        for i in range(self.int_size):
            byte_value = self.read_byte(stream)
            if byte_value != 0:
                value += byte_value << (i * 8)

        return -value if sign else value

    def read_string(self, stream: BinaryIO) -> str:
        """
        Чтение строки UTF-8 с префиксом длины.
        :param stream: поток для чтения
        :return: строка
        """
        length = self.read_int(stream)
        if length <= 0:
            return ""

        data = stream.read(length)
        if len(data) != length:
            raise PgDumpError(f"Expected {length} bytes, got {len(data)}")

        try:
            return data.decode('utf-8')
        except UnicodeDecodeError as e:
            raise PgDumpError(f"Invalid UTF-8 string: {e}")

    def read_offset(self, stream: BinaryIO) -> Offset:
        """
        Чтение значения смещения.
        :param stream: поток для чтения
        :return: значение смещения
        """
        offset = 0
        for i in range(self.offset_size):
            byte_value = self.read_byte(stream)
            offset |= byte_value << (i * 8)
        return offset

    def write_int(self, value: int) -> bytes:
        """
        Запись знакового целого числа.
        :param value: значение для записи
        :return: байты для записи
        """
        is_negative = value < 0
        value = abs(value)

        result = bytearray()
        result.append(1 if is_negative else 0)

        for i in range(self.int_size):
            result.append((value >> (i * 8)) & 0xFF)

        return bytes(result)


class HeaderParser:
    """Парсер заголовков файлов дампов PostgreSQL."""

    def __init__(self, dio: DumpIO):
        """
        Инициализация парсера.
        :param dio: объект для работы с бинарным I/O
        """
        self.dio = dio

    def parse(self, stream: BinaryIO) -> Header:
        """
        Парсинг заголовка файла дампа.
        :param stream: поток для чтения
        :return: объект заголовка
        """
        magic = stream.read(5)
        if magic != Constants.MAGIC_HEADER:
            raise PgDumpError(f"Invalid magic header: {magic!r}")

        version = (
            self.dio.read_byte(stream),
            self.dio.read_byte(stream),
            self.dio.read_byte(stream)
        )

        self._validate_version(version)

        int_size = self.dio.read_byte(stream)
        offset_size = self.dio.read_byte(stream)
        self.dio.int_size = int_size
        self.dio.offset_size = offset_size

        format_byte = self.dio.read_byte(stream)
        if format_byte != Constants.CUSTOM_FORMAT:
            raise PgDumpError(f"Unsupported format: {format_byte}")

        compression_method = self._parse_compression(stream, version)
        create_date = self._parse_date(stream)

        database_name = self.dio.read_string(stream)
        server_version = self.dio.read_string(stream)
        pgdump_version = self.dio.read_string(stream)

        return Header(
            magic=magic,
            version=version,
            database_name=database_name,
            server_version=server_version,
            pgdump_version=pgdump_version,
            compression_method=compression_method,
            create_date=create_date,
            int_size=int_size,
            offset_size=offset_size
        )

    def _validate_version(self, version: Version) -> None:
        """
        Валидация версии формата дампа.
        :param version: версия для проверки
        """
        if version < PostgreSQLVersions.V1_12 or version > PostgreSQLVersions.V1_16:
            version_str = '.'.join(map(str, version))
            raise PgDumpError(f"Unsupported version: {version_str}")

    def _parse_compression(self, stream: BinaryIO, version: Version) -> CompressionMethod:
        """
        Парсинг метода сжатия в зависимости от версии.
        :param stream: поток для чтения
        :param version: версия формата
        :return: метод сжатия
        """
        if version >= PostgreSQLVersions.V1_15:
            compression_byte = self.dio.read_byte(stream)
            compression_map = {
                0: CompressionMethod.NONE,
                1: CompressionMethod.GZIP,
                2: CompressionMethod.LZ4,
                3: CompressionMethod.ZLIB,
            }
            compression_method = compression_map.get(compression_byte)
            if compression_method is None:
                raise PgDumpError(f"Unknown compression method: {compression_byte}")
        else:
            compression = self.dio.read_int(stream)
            if compression == -1:
                compression_method = CompressionMethod.ZLIB
            elif compression == 0:
                compression_method = CompressionMethod.NONE
            elif 1 <= compression <= 9:
                compression_method = CompressionMethod.GZIP
            else:
                raise PgDumpError(f"Invalid compression level: {compression}")

        return compression_method

    def _parse_date(self, stream: BinaryIO) -> datetime.datetime:
        """
        Парсинг даты создания из дампа.
        :param stream: поток для чтения
        :return: дата создания
        """
        sec = self.dio.read_int(stream)
        minute = self.dio.read_int(stream)
        hour = self.dio.read_int(stream)
        day = self.dio.read_int(stream)
        month = self.dio.read_int(stream)
        year = self.dio.read_int(stream)
        _isdst = self.dio.read_int(stream)

        try:
            return datetime.datetime(
                year=year + 1900,
                month=month + 1,
                day=day,
                hour=hour,
                minute=minute,
                second=sec
            )
        except ValueError as e:
            raise PgDumpError(f"Invalid creation date: {e}")


class TocParser:
    """Парсер записей оглавления (Table of Contents)."""

    def __init__(self, dio: DumpIO):
        """
        Инициализация парсера TOC.
        :param dio: объект для работы с бинарным I/O
        """
        self.dio = dio

    def parse(self, stream: BinaryIO, version: Version) -> List[TocEntry]:
        """
        Парсинг всех записей TOC.
        :param stream: поток для чтения
        :param version: версия формата дампа
        :return: список записей TOC
        """
        num_entries = self.dio.read_int(stream)
        return [self._parse_entry(stream, version) for _ in range(num_entries)]

    def _parse_entry(self, stream: BinaryIO, version: Version) -> TocEntry:
        """
        Парсинг одной записи TOC.
        :param stream: поток для чтения
        :param version: версия формата дампа
        :return: запись TOC
        """
        dump_id = self.dio.read_int(stream)
        had_dumper = bool(self.dio.read_int(stream))

        table_oid = self.dio.read_string(stream)
        oid = self.dio.read_string(stream)
        tag = self.dio.read_string(stream)
        desc = self.dio.read_string(stream)

        section_idx = self.dio.read_int(stream)
        section = self._parse_section(section_idx)

        defn = self.dio.read_string(stream)
        drop_stmt = self.dio.read_string(stream)
        copy_stmt = self.dio.read_string(stream)
        namespace = self.dio.read_string(stream)
        tablespace = self.dio.read_string(stream)

        tableam = None
        if version >= PostgreSQLVersions.V1_14:
            tableam = self.dio.read_string(stream)

        owner = self.dio.read_string(stream)
        with_oids = self.dio.read_string(stream)

        dependencies = self._parse_dependencies(stream)

        data_state = self.dio.read_byte(stream)
        offset = self.dio.read_offset(stream)

        return TocEntry(
            dump_id=dump_id,
            had_dumper=had_dumper,
            tag=tag or None,
            desc=desc or None,
            section=section,
            defn=defn or None,
            copy_stmt=copy_stmt or None,
            drop_stmt=drop_stmt or None,
            namespace=namespace or None,
            tablespace=tablespace or None,
            tableam=tableam,
            data_state=data_state,
            owner=owner or None,
            offset=offset,
            with_oids=with_oids or None,
            table_oid=table_oid or None,
            oid=oid or None,
            dependencies=dependencies
        )

    def _parse_section(self, section_idx: int) -> SectionType:
        """
        Парсинг типа секции по индексу.
        :param section_idx: индекс секции
        :return: тип секции
        """
        section_map = {
            1: SectionType.PRE_DATA,
            2: SectionType.DATA,
            3: SectionType.POST_DATA,
            4: SectionType.NONE,
        }
        return section_map.get(section_idx, SectionType.NONE)

    def _parse_dependencies(self, stream: BinaryIO) -> list[DumpId]:
        """
        Парсинг списка зависимостей.
        :param stream: поток для чтения
        :return: список ID зависимостей
        """
        dependencies = []
        while True:
            dep_str = self.dio.read_string(stream)
            if not dep_str:
                break
            try:
                dependencies.append(int(dep_str))
            except ValueError:
                logger.warning(f"Invalid dependency ID: {dep_str}")
        return dependencies


class DataBlockProcessor:
    """Обработчик блоков данных с поддержкой сжатия."""

    def __init__(self, dio: DumpIO, processor: DataProcessor):
        """
        Инициализация процессора блоков данных.
        :param dio: объект для работы с бинарным I/O
        :param processor: процессор данных
        """
        self.dio = dio
        self.processor = processor

    def process_block(
        self,
        input_stream: BinaryIO,
        output_stream: BinaryIO,
        dump_id: DumpId,
        compression: CompressionMethod
    ) -> None:
        """
        Обработка одного блока данных.
        :param input_stream: входной поток
        :param output_stream: выходной поток
        :param dump_id: ID записи дампа
        :param compression: метод сжатия
        """
        if compression == CompressionMethod.ZLIB:
            self._process_compressed_block(input_stream, output_stream, dump_id)
        else:
            self._process_uncompressed_block(input_stream, output_stream, dump_id)

    def _process_compressed_block(
        self,
        input_stream: BinaryIO,
        output_stream: BinaryIO,
        dump_id: DumpId
    ) -> None:
        """
        Обработка сжатого блока данных ZLIB.
        :param input_stream: входной поток
        :param output_stream: выходной поток
        :param dump_id: ID записи дампа
        """
        decompressed_data = io.BytesIO()
        decompressor = zlib.decompressobj()
        remaining_chunk = b''

        while True:
            chunk_size = self.dio.read_int(input_stream)
            if chunk_size == 0:
                break

            chunk_data = input_stream.read(chunk_size)
            if len(chunk_data) != chunk_size:
                raise PgDumpError(f"Expected {chunk_size} bytes, got {len(chunk_data)}")

            remaining_chunk += chunk_data
            try:
                decompressed_chunk = decompressor.decompress(remaining_chunk)
                decompressed_data.write(decompressed_chunk)
                remaining_chunk = decompressor.unconsumed_tail
            except zlib.error as e:
                raise PgDumpError(f"Decompression error: {e}")

            if chunk_size < Constants.ZLIB_CHUNK_SIZE:
                break

        try:
            final_data = decompressor.flush()
            decompressed_data.write(final_data)
        except zlib.error as e:
            raise PgDumpError(f"Final decompression error: {e}")

        original_data = decompressed_data.getvalue()
        processed_data = self.processor.process(original_data)

        compressed_data = zlib.compress(processed_data)
        self._write_data_block(output_stream, dump_id, compressed_data)

    def _process_uncompressed_block(
        self,
        input_stream: BinaryIO,
        output_stream: BinaryIO,
        dump_id: DumpId
    ) -> None:
        """
        Обработка несжатого блока данных.
        :param input_stream: входной поток
        :param output_stream: выходной поток
        :param dump_id: ID записи дампа
        """
        size = self.dio.read_int(input_stream)
        data = input_stream.read(size)

        if len(data) != size:
            raise PgDumpError(f"Expected {size} bytes, got {len(data)}")

        processed_data = self.processor.process(data)
        self._write_data_block(output_stream, dump_id, processed_data)

    def _write_data_block(self, output_stream: BinaryIO, dump_id: DumpId, data: bytes) -> None:
        """
        Запись обработанного блока данных в выходной поток.
        :param output_stream: выходной поток
        :param dump_id: ID записи дампа
        :param data: данные для записи
        """
        output_stream.write(BlockType.DATA)
        output_stream.write(self.dio.write_int(dump_id))
        output_stream.write(self.dio.write_int(len(data)))
        output_stream.write(data)
        output_stream.flush()


class DumpProcessor:
    """Главный процессор дампов PostgreSQL."""

    def __init__(self, data_processor: DataProcessor):
        """
        Инициализация процессора дампов.
        :param data_processor: обработчик данных
        """
        self.data_processor = data_processor
        self.dio = DumpIO()

    def process_stream(self, input_stream: BinaryIO, output_stream: BinaryIO) -> None:
        """
        Обработка дампа из входного потока в выходной поток.
        :param input_stream: входной поток
        :param output_stream: выходной поток
        """
        try:
            dump, combined_stream = self._parse_header_and_toc(input_stream, output_stream)
            self._process_data_blocks(combined_stream, output_stream, dump)
        except Exception as e:
            logger.error(f"Error processing dump: {e}")
            raise

    def _parse_header_and_toc(self, input_stream: BinaryIO, output_stream: BinaryIO) -> tuple[Dump, StreamCombiner]:
        """
        Парсинг заголовка и TOC с записью в выходной поток.
        :param input_stream: входной поток
        :param output_stream: выходной поток
        :return: объект дампа и комбинированный поток
        """
        buffer = io.BytesIO()
        dump = None

        while dump is None:
            chunk = input_stream.read(Constants.DEFAULT_BUFFER_SIZE)
            if not chunk:
                raise PgDumpError("Unexpected EOF while reading header/TOC")

            buffer.write(chunk)
            buffer.seek(0)

            try:
                header_parser = HeaderParser(self.dio)
                header = header_parser.parse(buffer)

                toc_parser = TocParser(self.dio)
                toc_entries = toc_parser.parse(buffer, header.version)

                dump = Dump(header=header, toc_entries=toc_entries)

            except (PgDumpError, struct.error):
                buffer.seek(0, io.SEEK_END)
                continue

        toc_end_pos = buffer.tell()
        buffer.seek(0)
        output_stream.write(buffer.read(toc_end_pos))
        output_stream.flush()

        remaining_data = buffer.read()
        combined_stream = StreamCombiner(io.BytesIO(remaining_data), input_stream)

        return dump, combined_stream

    def _process_data_blocks(
        self,
        input_stream: Union[BinaryIO, StreamCombiner],
        output_stream: BinaryIO,
        dump: Dump
    ) -> None:
        """
        Обработка блоков данных в дампе.
        :param input_stream: входной поток
        :param output_stream: выходной поток
        :param dump: объект дампа
        """
        dump_comments = {entry.defn for entry in dump.get_comment_entries()}
        dump_copy_stmts = {entry.dump_id: entry.copy_stmt for entry in dump.get_table_data_entries()}
        dump_ids = {entry.dump_id for entry in dump.get_table_data_entries()}
        processor = DataBlockProcessor(self.dio, self.data_processor)

        for comment in dump_comments:
            self.data_processor.process(comment)

        while True:
            block_type = input_stream.read(1)
            if not block_type:
                break

            if block_type == BlockType.DATA:
                dump_id = self.dio.read_int(input_stream)

                if dump_id in dump_ids:
                    self.data_processor.process(dump_copy_stmts[dump_id])
                    processor.process_block(
                        input_stream,
                        output_stream,
                        dump_id,
                        dump.header.compression_method
                    )
                else:
                    self._pass_through_block(input_stream, output_stream, block_type, dump_id)
            else:
                output_stream.write(block_type)
                if block_type == BlockType.END:
                    break

    def _pass_through_block(
        self,
        input_stream: BinaryIO,
        output_stream: BinaryIO,
        block_type: bytes,
        dump_id: DumpId
    ) -> None:
        """
        Передача блока без обработки.
        :param input_stream: входной поток
        :param output_stream: выходной поток
        :param block_type: тип блока
        :param dump_id: ID записи дампа
        """
        output_stream.write(block_type)
        output_stream.write(self.dio.write_int(dump_id))

        size = self.dio.read_int(input_stream)
        output_stream.write(self.dio.write_int(size))

        remaining = size
        while remaining > 0:
            chunk_size = min(remaining, Constants.DEFAULT_BUFFER_SIZE)
            chunk = input_stream.read(chunk_size)
            if not chunk:
                break
            output_stream.write(chunk)
            remaining -= len(chunk)

        output_stream.flush()


@contextmanager
def create_pg_dump_process(connection: DatabaseConnection, tables: Optional[List[str]] = None):
    """
    Создание подпроцесса pg_dump с правильным управлением ресурсами.
    :param connection: конфигурация подключения к БД
    :param tables: список таблиц для дампа (опционально)
    :yield: объект подпроцесса
    """
    cmd = ['pg_dump', '-Fc']

    if tables:
        for table in tables:
            cmd.extend(['-t', table])

    env = os.environ.copy()
    env.update(connection.to_env_dict())

    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env
    )

    try:
        yield process
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait()


def main():
    """Точка входа в программу."""
    connection = DatabaseConnection(
        host='localhost',
        port='5432',
        user='secret',
        password='secret',
        database='secret',
    )

    dump_tables = []

    data_processor = ObfuscatorProcessor(
        Obfuscator(locale='ru', delete_tables_by_pattern=[r'\_historical'])
    )
    dump_processor = DumpProcessor(data_processor)

    try:
        with create_pg_dump_process(connection, dump_tables) as process:
            dump_processor.process_stream(process.stdout, sys.stdout.buffer)

            return_code = process.wait()
            if return_code != 0:
                stderr_output = process.stderr.read().decode('utf-8')
                logger.error(f"pg_dump failed with code {return_code}: {stderr_output}")
                sys.exit(return_code)

    except KeyboardInterrupt:
        logger.info("Process interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
