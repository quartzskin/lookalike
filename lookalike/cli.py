import argparse
import json
import sys

from . import __version__
from . import brands as brandlib
from .analyze import check
from .generate import doh_lookup, permutations, resolve_all
from .qr import QRError, decode_png

EXIT_BAD_INPUT = 3
KIND_ORDER = ["homoglyph", "lookalike-sequence", "omission", "transposition", "keyboard-neighbour",
              "bit-flip", "hyphen", "repetition", "other-tld", "dot-inserted", "vowel-swap", "addition"]


class Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        sys.stderr.write("%s: error: %s\n" % (self.prog, message))
        sys.exit(EXIT_BAD_INPUT)


def build_parser():
    p = Parser(prog="lookalike", description="Warn about lookalike links and domains. Nothing is fetched.")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True, parser_class=Parser)

    c = sub.add_parser("check", help="analyze URLs, domains, an HTML snippet or a QR image")
    c.add_argument("targets", nargs="*", help="URL or domain")
    c.add_argument("--qr", metavar="PNG", action="append", default=[], help="decode a QR code from a PNG and check it")
    c.add_argument("--html", metavar="FILE", action="append", default=[], help="check every <a> in an HTML file (- for stdin)")
    c.add_argument("--stdin", action="store_true", help="read one target per line from stdin")
    c.add_argument("--brands", metavar="FILE", help="extra brand/domain list (one per line)")
    c.add_argument("--no-user-brands", action="store_true", help="ignore the per-user brands file")
    c.add_argument("--format", choices=("text", "json"), default="text")

    g = sub.add_parser("generate", help="list lookalike permutations of your own domain")
    g.add_argument("domain")
    g.add_argument("--resolve", action="store_true", help="look names up over DNS-over-HTTPS (sends them to cloudflare-dns.com)")
    g.add_argument("--max-queries", type=int, default=300, help="cap on names resolved (default 300)")
    g.add_argument("--registered-only", action="store_true", help="with --resolve, list only names that resolve")
    g.add_argument("--format", choices=("text", "json"), default="text")

    b = sub.add_parser("brands", help="show or extend your own brand list")
    bs = b.add_subparsers(dest="action", required=True, parser_class=Parser)
    bs.add_parser("list")
    ba = bs.add_parser("add")
    ba.add_argument("domain")

    u = sub.add_parser("gui", help="local web UI on 127.0.0.1")
    u.add_argument("--port", type=int, default=0)
    u.add_argument("--no-open", action="store_true")
    u.add_argument("--browser", metavar="EXE")
    u.add_argument("--brands", metavar="FILE")
    return p


def format_report(r):
    lines = [r["input"]]
    if r.get("link_text") is not None:
        lines.append("  link text: %s" % r["link_text"])
    if r.get("error"):
        lines.append("  error: " + r["error"])
        return "\n".join(lines)
    if r["host_unicode"] and r["host_unicode"] != r["host_ascii"]:
        lines.append("  host: %s  (%s)" % (r["host_unicode"], r["host_ascii"]))
    elif r["host_ascii"]:
        lines.append("  host: " + r["host_ascii"])
    lines.append("  verdict: %s (score %d)" % (r["verdict"], r["score"]))
    for f in sorted(r["findings"], key=lambda f: -f["score"]):
        lines.append("  [%s] %s: %s" % (f["severity"], f["code"], f["message"]))
    shown = [c for c in r["chars"] if c["kind"]]
    for c in shown:
        extra = "looks like %r (%s)" % (c["looks_like"], c["looks_like_name"]) if c["looks_like"] else c["kind"]
        lines.append("    %s %s %s: %s" % (c["char"].encode("unicode_escape").decode() if c["kind"] == "invisible" else c["char"],
                                           c["codepoint"], c["name"], extra))
    if r["verdict"] == "clean":
        lines.append("  no lookalike signals found (this is not a guarantee the site is safe)")
    return "\n".join(lines)


def exit_code(reports, errors):
    worst = max((r["score"] for r in reports), default=0)
    if worst >= 50:
        return 2
    if worst >= 20:
        return 1
    return EXIT_BAD_INPUT if errors else 0


def read_text(path):
    if path == "-":
        return sys.stdin.read()
    with open(path, encoding="utf-8", errors="replace") as f:
        return f.read()


def cmd_check(args):
    try:
        brands = brandlib.load_brands(args.brands, not args.no_user_brands)
    except OSError as e:
        print("lookalike: cannot read brands file: %s" % e, file=sys.stderr)
        return EXIT_BAD_INPUT
    reports, errors = [], []
    jobs = [("target", t) for t in args.targets] + [("qr", q) for q in args.qr] + [("html", h) for h in args.html]
    if args.stdin:
        jobs += [("target", ln) for ln in sys.stdin.read().splitlines() if ln.strip()]
    if not jobs:
        print("lookalike: nothing to check (give a URL, --qr, --html or --stdin)", file=sys.stderr)
        return EXIT_BAD_INPUT
    for kind, value in jobs:
        try:
            if kind == "qr":
                with open(value, "rb") as f:
                    text = decode_png(f.read())
                for r in check(text, brands):
                    r["input"] = "%s -> %s" % (value, r["input"])
                    reports.append(r)
            elif kind == "html":
                reports.extend(check(read_text(value), brands, html=True))
            else:
                reports.extend(check(value, brands))
        except (ValueError, QRError, OSError) as e:
            errors.append({"input": value, "error": str(e)})
    if args.format == "json":
        print(json.dumps({"reports": reports, "errors": errors}, indent=2, ensure_ascii=False))
    else:
        for r in reports:
            print(format_report(r))
            print()
        for e in errors:
            print("%s\n  error: %s\n" % (e["input"], e["error"]))
    return exit_code(reports, errors)


def cmd_generate(args):
    try:
        items = permutations(args.domain)
    except ValueError as e:
        print("lookalike: %s" % e, file=sys.stderr)
        return EXIT_BAD_INPUT
    items.sort(key=lambda it: (KIND_ORDER.index(it["kind"]) if it["kind"] in KIND_ORDER else 99, it["domain"]))
    if args.resolve:
        todo = items[:max(0, args.max_queries)]
        print("resolving %d of %d names via cloudflare-dns.com over HTTPS" % (len(todo), len(items)), file=sys.stderr)
        resolve_all(todo, lookup=doh_lookup)
        items = todo
        if args.registered_only:
            items = [it for it in items if it["addresses"]]
    if args.format == "json":
        print(json.dumps(items, indent=2, ensure_ascii=False))
        return 0
    for it in items:
        name = it["domain"] if it["domain"] == it["ascii"] else "%s  (%s)" % (it["domain"], it["ascii"])
        tail = ""
        if "addresses" in it:
            tail = "  " + (", ".join(it["addresses"]) if it["addresses"] else ("no records" if it["addresses"] == [] else "lookup failed"))
        print("%-20s %s%s" % (it["kind"], name, tail))
    print("%d permutations" % len(items), file=sys.stderr)
    return 0


def cmd_brands(args):
    if args.action == "list":
        print("# user file: %s" % brandlib.user_file())
        for b in brandlib.load_brands():
            print(b)
        return 0
    try:
        path, added = brandlib.add_brand(args.domain)
    except ValueError as e:
        print("lookalike: %s" % e, file=sys.stderr)
        return EXIT_BAD_INPUT
    print(("added %s to %s" if added else "%s already in %s") % (args.domain.lower(), path))
    return 0


def cmd_gui(args):
    from .server import serve
    try:
        brands = brandlib.load_brands(args.brands)
    except OSError as e:
        print("lookalike: cannot read brands file: %s" % e, file=sys.stderr)
        return EXIT_BAD_INPUT
    serve(brands, args.port, args.no_open, args.browser)
    return 0


def main(argv=None):
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    args = build_parser().parse_args(argv)
    return {"check": cmd_check, "generate": cmd_generate, "brands": cmd_brands, "gui": cmd_gui}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
