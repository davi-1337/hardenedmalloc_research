import gdb


def _ro():
    for s in gdb.lookup_static_symbols("ro"):
        try:
            v = s.value()
            if int(v["slab_region_start"]) != 0:
                return v
        except gdb.error:
            pass
    raise gdb.GdbError("ro not found/initialized: rebuild the .so with -g and run until after the first malloc")


def _f(v, name, default=None):
    try:
        return v[name]
    except gdb.error:
        return default


def _i(v):
    return int(v)


def _popcount(x):
    return bin(x & 0xFFFFFFFFFFFFFFFF).count("1")


def _iter_classes(ro):
    sc = ro["size_class_metadata"]
    n = None
    for s in gdb.lookup_static_symbols("size_classes"):
        try:
            n = s.value().type.range()[1] + 1
            break
        except gdb.error:
            pass
    for arena in range(sc.type.range()[1] + 1):
        base = sc[arena]
        for ci in range(n):
            yield arena, ci, (base + ci).dereference()


def _slab_addr(c, idx):
    return _i(c["class_region_start"]) + idx * _i(c["slab_size"])


def _list_members(c):
    members = {}
    for head, label in (("partial_slabs", "partial"), ("empty_slabs", "empty"),
                        ("free_slabs_head", "free")):
        node = _f(c, head)
        seen = set()
        while node is not None and _i(node) != 0 and _i(node) not in seen:
            seen.add(_i(node))
            members[_i(node)] = label
            node = _f(node.dereference(), "next")
    quar = _f(c, "free_slabs_quarantine")
    if quar is not None:
        for i in range(quar.type.range()[1] + 1):
            node = quar[i]
            if _i(node) != 0:
                members[_i(node)] = "free-quar"
    return members


def _slot_state(meta, slot):
    bucket, bit = divmod(slot, 64)
    qb = _f(meta, "quarantine_bitmap")
    if qb is not None and _i(qb[bucket]) >> bit & 1:
        return "quarantine"
    if _i(meta["bitmap"][bucket]) >> bit & 1:
        return "used"
    return "free"


def _slab_rows(arena, ci, c):
    rows = []
    meta_base = _i(c["slab_info"])
    meta_sz = c["slab_info"].type.target().sizeof
    members = _list_members(c)
    slots = _i(c["slots"])
    for idx in range(_i(c["metadata_count"])):
        meta = (c["slab_info"] + idx).dereference()
        qb = _f(meta, "quarantine_bitmap")
        quar = sum(_popcount(_i(qb[b])) for b in range(4)) if qb is not None else 0
        used = sum(_popcount(_i(meta["bitmap"][b])) for b in range(4)) - quar
        label = members.get(meta_base + idx * meta_sz)
        if label is None:
            label = "full" if used == slots else "guard"
        rows.append((arena, ci, idx, _slab_addr(c, idx), used, quar, slots, label))
    return rows


def _find_class(p):
    ro = _ro()
    if not (_i(ro["slab_region_start"]) <= p < _i(ro["slab_region_end"])):
        return None
    for arena, ci, c in _iter_classes(ro):
        off = p - _i(c["class_region_start"])
        if off < 0:
            continue
        idx = off // _i(c["slab_size"])
        if idx < _i(c["metadata_allocated"]):
            return arena, ci, c, idx
    return None


class HM(gdb.Command):
    def __init__(self):
        super().__init__("hm", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        ro = _ro()
        print("slab region: [%#x, %#x)" % (_i(ro["slab_region_start"]), _i(ro["slab_region_end"])))
        print("%-5s %-6s %-8s %-8s %-6s %-6s %-10s %-10s" %
              ("arena", "class", "size", "slab", "slots", "slabs", "used", "quar"))
        for arena, ci, c in _iter_classes(ro):
            if _i(c["metadata_count"]) == 0:
                continue
            rows = _slab_rows(arena, ci, c)
            print("%-5d %-6d %-8d %#-8x %-6d %-6d %-10d %-10d" %
                  (arena, ci, _i(c["size"]), _i(c["slab_size"]), _i(c["slots"]),
                   len(rows), sum(r[4] for r in rows), sum(r[5] for r in rows)))


class HMSlabs(gdb.Command):
    def __init__(self):
        super().__init__("hm-slabs", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        argv = gdb.string_to_argv(arg)
        want = (int(argv[0]), int(argv[1])) if len(argv) == 2 else None
        print("%-5s %-6s %-6s %-18s %-14s %-7s %-7s %-10s" %
              ("arena", "class", "idx", "slab", "meta", "used", "quar", "list"))
        for arena, ci, c in _iter_classes(_ro()):
            if want and (arena, ci) != want:
                continue
            meta_base = _i(c["slab_info"])
            meta_sz = c["slab_info"].type.target().sizeof
            for r in _slab_rows(arena, ci, c):
                print("%-5d %-6d %-6d %#-18x %#-14x %-7d %-7d %-10s" %
                      (r[0], r[1], r[2], r[3], meta_base + r[2] * meta_sz, r[4], r[5], r[7]))


class HMFind(gdb.Command):
    def __init__(self):
        super().__init__("hm-find", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        p = _i(gdb.parse_and_eval(arg))
        hit = _find_class(p)
        if hit is None:
            for line in _large_rows():
                if line[1] <= p < line[1] + line[2]:
                    print("large allocation: base=%#x size=%#x guard=%#x offset=%#x" %
                          (line[1], line[2], line[3], p - line[1]))
                    return
            print("%#x: not in hardened_malloc heap" % p)
            return
        arena, ci, c, idx = hit
        slab = _slab_addr(c, idx)
        size = _i(c["size"])
        slot = (p - slab) // size
        meta = (c["slab_info"] + idx).dereference()
        state = _slot_state(meta, slot) if slot < _i(c["slots"]) else "slab-tail"
        print("arena=%d class=%d (size=%d) slab=%#x idx=%d slot=%d state=%s offset=%#x" %
              (arena, ci, size, slab, idx, slot, state, p - slab - slot * size))
        cv = _f(meta, "canary_value")
        if cv is not None and state in ("used", "quarantine"):
            addr = slab + slot * size + size - 8
            actual = int.from_bytes(gdb.selected_inferior().read_memory(addr, 8), "little")
            print("canary @%#x: stored=%#x expected=%#x %s" %
                  (addr, actual, _i(cv), "OK" if actual == _i(cv) else "CORRUPTED"))


def _large_rows():
    ra = _ro()["region_allocator"].dereference()
    regions = ra["regions"]
    rows = []
    for i in range(_i(ra["total"])):
        r = (regions + i).dereference()
        if _i(r["p"]) != 0:
            rows.append((i, _i(r["p"]), _i(r["size"]), _i(r["guard_size"])))
    return rows


class HMLarge(gdb.Command):
    def __init__(self):
        super().__init__("hm-large", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        ra = _ro()["region_allocator"].dereference()
        print("region table: total=%d free=%d" % (_i(ra["total"]), _i(ra["free"])))
        print("%-6s %-18s %-12s %-12s" % ("idx", "ptr", "size", "guard"))
        for i, p, size, guard in _large_rows():
            print("%-6d %#-18x %#-12x %#-12x" % (i, p, size, guard))


HM()
HMSlabs()
HMFind()
HMLarge()
print("hardened_malloc: hm, hm-slabs [arena class], hm-find <addr>, hm-large")
