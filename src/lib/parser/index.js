export default function parser(buf) {
    const bytes = new Uint8Array(buf);
    const head = { ptr: 0 };
    const read = n => readNBytesHex(bytes, head, n);
    const atAddr = (shift = 0) => `at 0x${(head.ptr - shift).toString(16)}`;

    const members = [];
    const addMember = (size, name, ptr, memPtr) => {
        const m = { addr: head.ptr - size, len: size, name, ptr, memPtr };
        members.push(m);
        return m;
    };
    const areas = [];
    const addArea = (ptr, len, name) => areas.push({ ptr, len, name });

    // Magic number
    if (read(4) !== "7f454c46") {
        return "Not an ELF file";
    }
    addMember(4, "ELF magic number");
    members.push({ addr: 9, len: 7, name: "Padding (zeros)" });

    let regSize; // 4 (32-bit) or 8 (64-bit)
    switch (read(1)) {
        case "01":
            regSize = 4;
            break;
        case "02":
            regSize = 8;
            break;
        default:
            return "Invalid register size value " + atAddr(1);
    }
    addMember(1, "Register size (" + regSize * 8 + "-bit)");

    let endianness; // "big" / "little"
    switch (read(1)) {
        case "01":
            endianness = "little";
            break;
        case "02":
            endianness = "big";
            break;
        default:
            return "Invalid endianness value " + atAddr(1);
    }
    addMember(1, "Endianness (" + endianness + ")");
    const nextInt = size => readInt(bytes, head, endianness, size);

    if (read(1) !== "01") {
        return "Invalid ELF version, expected 1 " + atAddr(1);
    }
    addMember(1, "ELF version (0x01)");

    if (read(1) !== "00") {
        return "Invalid ABI type, expected 0 " + atAddr(1);
    }
    addMember(1, "ELF ABI type (0x00)");

    if (read(1) !== "00") {
        return "Invalid ABI version, expected 0 " + atAddr(1);
    }
    addMember(1, "ELF ABI version (00)");

    head.ptr = 0x10; // skip over the padding

    const elfHeader = {};

    elfHeader.type = nextInt(2);
    addMember(2, "Type (" + formatElfType(elfHeader.type) + ")");
    elfHeader.arch = nextInt(2);
    addMember(2, "Architecture (" + formatElfArch(elfHeader.arch) + ")");
    elfHeader.ver = nextInt(4);
    addMember(4, "ELF version (0x" + elfHeader.ver.toString(16) + ")");
    elfHeader.entry = nextInt(regSize);
    addMember(regSize, "Entry point", undefined, elfHeader.entry);
    elfHeader.segmentHeadersStart = nextInt(regSize);
    addMember(regSize, "Segment headers start", elfHeader.segmentHeadersStart);
    elfHeader.sectionHeadersStart = nextInt(regSize);
    addMember(regSize, "Section headers start", elfHeader.sectionHeadersStart);
    elfHeader.flags = nextInt(4);
    addMember(4, "ELF flags (0x" + elfHeader.flags.toString(16) + ")");
    elfHeader.headerSize = nextInt(2);
    addMember(2, "ELF header size", elfHeader.headerSize);
    elfHeader.segmentHeaderSize = nextInt(2);
    addMember(2, "Size of each segment header (" + elfHeader.segmentHeaderSize + ")");
    elfHeader.segmentsNum = nextInt(2);
    addMember(2, "Number of segments (" + elfHeader.segmentsNum + ")");
    elfHeader.sectionHeaderSize = nextInt(2);
    addMember(2, "Size of each section header (" + elfHeader.sectionHeaderSize + ")");
    elfHeader.sectionsNum = nextInt(2);
    addMember(2, "Number of sections (" + elfHeader.sectionsNum + ")");
    elfHeader.sectionHeaderStringsIndex = nextInt(2);
    addMember(2, "Section header strings index (" + elfHeader.sectionHeaderStringsIndex + ")",
        elfHeader.sectionHeadersStart + elfHeader.sectionHeaderSize * elfHeader.sectionHeaderStringsIndex
    );

    if (elfHeader.ver !== 1) {
        return "ELF version is " + elfHeader.ver + " when 1 was expected";
    }

    addArea(0, elfHeader.headerSize, "ELF header");

    const shstrtabArrayOffset = findShstrtabArrayOffset(bytes, elfHeader, endianness, regSize);

    const segments = parseSegmentHeaders(regSize, elfHeader, head, nextInt, addMember, addArea);
    const sections = parseSectionHeaders(regSize, elfHeader, head, nextInt, addMember, addArea, bytes, shstrtabArrayOffset);
    const symbols = parseSymbolsTable(regSize, sections, head, nextInt, addMember, addArea, bytes);

    return { members, areas };
}

function findShstrtabArrayOffset(bytes, elfHeader, endianness, regSize) {
    const shstrabSectionOffset = elfHeader.sectionHeadersStart
        + elfHeader.sectionHeaderStringsIndex * elfHeader.sectionHeaderSize;

    if (regSize === 4) { // 32-bit: @+16 (len 4)
        const head = { ptr: offsetOfAddress + 16 };
        return readInt(bytes, head, endianness, 4);
    } else if (regSize === 8) { // 64-bit: @+24 (len 8)
        const head = { ptr: shstrabSectionOffset + 24 };
        return readInt(bytes, head, endianness, 8);
    }
}

function formatElfType(num) {
    return ["None", "Relocatable", "Executable", "Shared object", "Core"][num] ?? "Unknown";
}

function formatElfArch(num) {
    return { 0x03: "x86", 0x08: "MIPS", 0x28: "ARM", 0x3e: "amd64", 0xb7: "ARMv8", 0xf3: "RISC-V" }[num] ?? "Unknown";
}

function formatSegmentType(num) {
    return ["null", "load", "dynamic", "interp", "note", "shlib (invalid)", "program header", "TLS - thread local storage"][num] ?? "unknown";
}

function formatSegmentFlags(num) {
    if (num === 0) return "none";
    const X = 1, W = 2, R = 4;
    const flags = [];
    if (num & X) flags.push("exec");
    if (num & W) flags.push("write");
    if (num & R) flags.push("read");
    if (num & ~(X | W | R)) flags.push("unknown");
    return flags.join("|");
}

// Adaptively parse segment headers (i.e. program section headers)
function parseSegmentHeaders(regSize, elfHeader, head, nextInt, addMember, addArea) {
    const start = elfHeader.segmentHeadersStart;
    const eachSize = elfHeader.segmentHeaderSize;
    const num = elfHeader.segmentsNum;

    for (let i = 0; i < num; i++) {
        addArea(start + i * eachSize, eachSize, "Segment [" + i + "] header");
    }

    let fn;
    if (regSize === 4) fn = parseSegmentHeaders32;
    else if (regSize === 8) fn = parseSegmentHeaders64;

    const segments = fn(
        start,
        eachSize,
        num,
        head,
        nextInt,
        addMember
    );
    segments.forEach((s, i) => {
        if (s.fileOffset !== 0)
            addArea(s.fileOffset, s.fileSize, "Segment [" + i + "]");
    });
    return segments;
}

function parseSegmentHeaders32(start, eachSize, num, head, nextInt, addMember) {
    const nextAddr = () => nextInt(4); // 32-bit
    const segments = [];
    if (eachSize === 0 || num === 0) return segments;

    for (let i = 0; i < num; i++) {
        head.ptr = start + i * eachSize;
        const s = {};

        s.type = nextInt(4);
        addMember(4, `Segment [${i}] type (${s.type}: ${formatSegmentType(s.type)})`);
        s.fileOffset = nextAddr();
        addMember(4, `Segment [${i}] offset in file`, s.fileOffset);
        s.addressVirt = nextAddr();
        addMember(4, `Segment [${i}] (virtual) memory location`, undefined, s.addressVirt);
        s.addressPhys = nextAddr();
        addMember(4, `Segment [${i}] (physical) memory location`, undefined, s.addressPhys);
        s.fileSize = nextAddr();
        addMember(4, `Segment [${i}] size in file (0x${s.fileSize.toString(16)})`);
        s.memorySize = nextAddr();
        addMember(4, `Segment [${i}] size in memory (0x${s.memorySize.toString(16)})`);
        s.flags = nextInt(4);
        addMember(4, `Segment [${i}] flags (0x${s.flags.toString(16)}: ${formatSegmentFlags(s.flags)})`);
        s.align = nextAddr();
        addMember(4, `Segment [${i}] memory alignment (0x${s.align.toString(16)})`);

        segments.push(s);
    }

    return segments;
}

function parseSegmentHeaders64(start, eachSize, num, head, nextInt, addMember) {
    const nextAddr = () => nextInt(8); // 64-bit
    const segments = [];
    if (eachSize === 0 || num === 0) return segments;

    for (let i = 0; i < num; i++) {
        head.ptr = start + i * eachSize;
        const s = {};

        s.type = nextInt(4);
        addMember(4, `Segment [${i}] type (${s.type}: ${formatSegmentType(s.type)})`);
        s.flags = nextInt(4);
        addMember(4, `Segment [${i}] flags (0x${s.flags.toString(16)}: ${formatSegmentFlags(s.flags)})`);
        s.fileOffset = nextAddr();
        addMember(8, `Segment [${i}] offset in file`, s.fileOffset);
        s.addressVirt = nextAddr();
        addMember(8, `Segment [${i}] (virtual) memory location`, undefined, s.addressVirt);
        s.addressPhys = nextAddr();
        addMember(8, `Segment [${i}] (physical) memory location`, undefined, s.addressVirt);
        s.fileSize = nextAddr();
        addMember(8, `Segment [${i}] size in file (0x${s.fileSize.toString(16)})`);
        s.memorySize = nextAddr();
        addMember(8, `Segment [${i}] size in memory (0x${s.memorySize.toString(16)})`);
        s.align = nextAddr();
        addMember(8, `Segment [${i}] memory alignment (0x${s.align.toString(16)})`);

        segments.push(s);
    }

    return segments;
}

function formatSectionType(num) {
    return [
        "null", "progbits", "symbol table", "string table", "rela",
        "hash", "dynamic", "note", "nobits", "rel", "shlib", "dynsym"
    ][num] ?? "unknown";
}

function formatSectionFlags(num) {
    if (num === 0) return "none";
    const W = 1, A = 2, X = 4;
    const flags = [];
    if (num & W) flags.push("write");
    if (num & A) flags.push("alloc");
    if (num & X) flags.push("execinstr");
    if (num & ~(W | A | X)) flags.push("unknown");
    return flags.join("|");
}

// Adaptively parse section headers
function parseSectionHeaders(regSize, elfHeader, head, nextInt, addMember, addArea, buf, shstrtabArrayOffset) {
    const start = elfHeader.sectionHeadersStart;
    const eachSize = elfHeader.sectionHeaderSize;
    const num = elfHeader.sectionsNum;

    for (let i = 0; i < num; i++) {
        addArea(start + i * eachSize, eachSize, "Section [" + i + "] header");
    }

    let fn;
    if (regSize === 4) fn = parseSectionHeaders32;
    else if (regSize === 8) fn = parseSectionHeaders64;

    const sections = fn(
        start,
        eachSize,
        num,
        head,
        nextInt,
        addMember,
        buf,
        shstrtabArrayOffset
    );
    sections.forEach((s, i) => {
        if (s.fileOffset !== 0)
            addArea(s.fileOffset, s.size, `Section [${i}] "${s.nameStr}"`);
    });
    return sections;
}

function parseSectionHeaders32(start, eachSize, num, head, nextInt, addMember, buf, namesStart) {
    const nextAddr = () => nextInt(4); // 32-bit
    const sections = [];
    if (eachSize === 0 || num === 0) return sections;

    for (let i = 0; i < num; i++) {
        head.ptr = start + i * eachSize;
        const s = {};

        s.name = nextInt(4);
        s.nameStr = readStringAt(namesStart + s.name, buf);
        addMember(4, `Section [${i}] name offset (0x${s.name.toString(16)}, "${s.nameStr}")`, namesStart + s.name);
        s.type = nextInt(4);
        addMember(4, `Section [${i}] type (${s.type}: ${formatSectionType(s.type)})`);
        s.flags = nextInt(4);
        addMember(4, `Section [${i}] flags (${s.flags}): ${formatSectionFlags(s.flags)}`);
        s.address = nextAddr();
        addMember(4, `Section [${i}] address`, undefined, s.address);
        s.fileOffset = nextAddr();
        addMember(4, `Section [${i}] offset in file`, s.fileOffset);
        s.size = nextAddr();
        addMember(4, `Section [${i}] size (0x${s.size.toString(16)})`);
        s.link = nextInt(4);
        addMember(4, `Section [${i}] link (0x${s.link.toString(16)})`);
        s.info = nextInt(4);
        addMember(4, `Section [${i}] info (0x${s.info.toString(16)})`);
        s.align = nextAddr();
        addMember(4, `Section [${i}] memory alignment (0x${s.align.toString(16)})`);
        s.entSize = nextAddr();
        addMember(4, `Section [${i}] entry size (0x${s.entSize.toString(16)})`);

        sections.push(s);
    }

    return sections;
}

function parseSectionHeaders64(start, eachSize, num, head, nextInt, addMember, buf, namesStart) {
    const nextAddr = () => nextInt(8); // 64-bit
    const sections = [];
    if (eachSize === 0 || num === 0) return sections;

    for (let i = 0; i < num; i++) {
        head.ptr = start + i * eachSize;
        const s = {};

        s.name = nextInt(4);
        s.nameStr = readStringAt(namesStart + s.name, buf);
        addMember(4, `Section [${i}] name offset (0x${s.name.toString(16)}, "${s.nameStr}")`, namesStart + s.name);
        s.type = nextInt(4);
        addMember(4, `Section [${i}] type (${s.type}: ${formatSectionType(s.type)})`);
        s.flags = nextAddr();
        addMember(8, `Section [${i}] flags (${s.flags}): ${formatSectionFlags(s.flags)}`);
        s.address = nextAddr();
        addMember(8, `Section [${i}] address`, undefined, s.address);
        s.fileOffset = nextAddr();
        addMember(8, `Section [${i}] offset in file`, s.fileOffset);
        s.size = nextAddr();
        addMember(8, `Section [${i}] size (0x${s.size.toString(16)})`);
        s.link = nextInt(4);
        addMember(4, `Section [${i}] link (0x${s.link.toString(16)})`);
        s.info = nextInt(4);
        addMember(4, `Section [${i}] info (0x${s.info.toString(16)})`);
        s.align = nextAddr();
        addMember(8, `Section [${i}] memory alignment (0x${s.align.toString(16)})`);
        s.entSize = nextAddr();
        addMember(8, `Section [${i}] entry size (0x${s.entSize.toString(16)})`);

        sections.push(s);
    }

    return sections;
}

// Adaptively parse symbol table (if any)
function parseSymbolsTable(regSize, sections, head, nextInt, addMember, addArea, buf) {
    const symtabHeader = sections.find(s => s.nameStr === ".symtab");
    if (!symtabHeader) return [];
    const strtabHeader = sections.find(s => s.nameStr === ".strtab");
    if (!strtabHeader) throw new Error("Have .symtab but no .strtab to resolve symbols' names");

    const start = symtabHeader.fileOffset;
    const eachSize = symtabHeader.entSize;
    const num = symtabHeader.size / eachSize;

    let fn;
    if (regSize === 4) fn = parseSymbolsTable32;
    else if (regSize === 8) fn = parseSymbolsTable64;

    const symbols = fn(start, eachSize, num, head, nextInt, addMember, buf, strtabHeader.fileOffset, sections);

    for (let i = 0; i < num; i++) {
        addArea(start + i * eachSize, eachSize, `Symbol [${i}] "${symbols[i].nameStr}"`);
    }

    return symbols;
}

function parseSymbolsTable32(start, eachSize, num, head, nextInt, addMember, buf, namesStart, sections) {
    const symbols = [];
    for (let i = 0; i < num; i++) {
        head.ptr = start + i * eachSize;
        const s = {};

        s.name = nextInt(4);
        s.nameStr = readStringAt(namesStart + s.name, buf);
        addMember(4, `Symbol [${i}] name offset (0x${s.name.toString(16)}, "${s.nameStr}")`, namesStart + s.name);
        s.value = nextInt(4);
        const valueMember = addMember(4, `Symbol [${i}] value (i.e. address) = 0x${s.value.toString(16)}`);
        s.size = nextInt(4);
        addMember(4, `Symbol [${i}] size (0x${s.size.toString(16)})`);
        s.info = nextInt(1);
        addMember(1, `Symbol [${i}] info (i.e. type) (0x${s.info.toString(16)}, ${formatSymbolInfo(s.info)})`);
        s.other = nextInt(1);
        addMember(1, `Symbol [${i}] other (i.e. visibility) (0x${s.other.toString(16)}, ${formatSymbolOther(s.other)})`);
        s.correspondingSection = nextInt(2);
        addMember(2, `Symbol [${i}] corresponding section (${formatSymbolSection(s.correspondingSection)})`);

        symbols.push(s);

        if (s.correspondingSection !== 0 && s.correspondingSection !== 0xfff1 && sections[s.correspondingSection]) {
            valueMember.ptr = sections[s.correspondingSection].fileOffset + s.value;
        }
    }
    return symbols;
}

// todo use sections
function parseSymbolsTable64(start, eachSize, num, head, nextInt, addMember, buf, namesStart, sections) {
    const symbols = [];
    for (let i = 0; i < num; i++) {
        head.ptr = start + i * eachSize;
        const s = {};

        s.name = nextInt(4);
        s.nameStr = readStringAt(namesStart + s.name, buf);
        addMember(4, `Symbol [${i}] name offset (0x${s.name.toString(16)}, "${s.nameStr}")`, namesStart + s.name);
        s.info = nextInt(1);
        addMember(1, `Symbol [${i}] info (i.e. type) (0x${s.info.toString(16)}, ${formatSymbolInfo(s.info)})`);
        s.other = nextInt(1);
        addMember(1, `Symbol [${i}] other (i.e. visibility) (0x${s.other.toString(16)}, ${formatSymbolOther(s.other)})`);
        s.correspondingSection = nextInt(2);
        addMember(2, `Symbol [${i}] corresponding section (${formatSymbolSection(s.correspondingSection)})`);
        s.value = nextInt(8);
        const valueMember = addMember(8, `Symbol [${i}] value (i.e. address) = 0x${s.value.toString(16)}`);
        s.size = nextInt(8);
        addMember(8, `Symbol [${i}] size (0x${s.size.toString(16)})`);

        symbols.push(s);

        if (s.correspondingSection !== 0 && s.correspondingSection !== 0xfff1 && sections[s.correspondingSection]) {
            valueMember.ptr = sections[s.correspondingSection].fileOffset + s.value;
        }
    }
    return symbols;
}

function formatSymbolInfo(num) {
    return ["NOTYPE", "OBJECT", "FUNC", "SECTION", "FILE", "COMMON", "TLS", "NUM"][num] ?? "unknown";
}

function formatSymbolOther(num) { // i.e. symbol visibility
    return ["DEFAULT", "INTERNAL", "HIDDEN", "PROTECTED"][num] ?? "unknown";
}

function formatSymbolSection(num) {
    switch (num) {
        case 0xff1f: return "HIPROC";
        case 0xfff1: return "ABS";
        case 0xfff2: return "COMMON";
        case 0xffff: return "XINDEX";
        case 0xffff: return "HIRESERVE";
    }
    if (num < 0xff00) {
        return `[${num}]`;
    }
    return `reserved index 0x${num.toString(16)}`;
}

// Read a null-terminated string at `addr` in `buf`
function readStringAt(addr, buf) {
    let result = "";
    while (result.length < 256) {
        const c = buf[addr++];
        if (c === 0) break;
        result += String.fromCharCode(c);
    }
    return result;
}

// Read either big-endian or little-endian `size` bytes from `buf` and shift `head`
function readInt(buf, head, endianness, size) {
    if (size !== 1 && size !== 2 && size !== 4 && size !== 8) {
        throw new Error("Expected 1, 2, 4, or 8 as `size` but got " + size);
    }
    if (endianness !== "big" && endianness !== "little") {
        throw new Error("Invalid endianness '" + endianness + "'");
    }

    const bytes = buf.slice(head.ptr, head.ptr + size);
    head.ptr += size;

    let result = 0;
    let place = 1; // 0x1 -> 0x100 -> 0x10000 -> etc

    if (endianness === "little") {
        for (let i = 0; i < size; i++) {
            result += bytes[i] * place;
            place *= 0x100;
        }
    } else if (endianness === "big") {
        for (let i = size - 1; i >= 0; i--) {
            result += bytes[i] * place;
            place *= 0x100;
        }
    }
    return result;
}

// Increment head.ptr by `n` after reading `n` bytes of `buf` as a hexdump
function readNBytesHex(buf, head, n) {
    const str = toHexString(buf, head.ptr, head.ptr + n);
    head.ptr += n;
    return str;
}

// Take bytes `start` to `end` of `buf` (a Uint8Array) and return as plain hexdump
function toHexString(buf, start = 0, end = undefined) {
    return [...buf.slice(start, end)].map(n => n.toString(16).padStart(2, "0")).join("");
}
