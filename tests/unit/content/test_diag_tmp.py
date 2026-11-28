import sys

import pytest
from lxml import etree

from mailferret.content.html import _parse


@pytest.mark.skipif(sys.platform != "win32", reason="diagnostic for the Windows runner")
def test_diag_nesting() -> None:
    versions = (etree.LXML_VERSION, etree.LIBXML_VERSION, etree.LIBXML_COMPILED_VERSION)
    lines = [f"lxml, libxml, compiled = {versions}"]
    for n in (100, 200, 254, 255, 256, 257, 300):
        parser = etree.HTMLParser(
            encoding="utf-8",
            recover=True,
            no_network=True,
            huge_tree=False,
            remove_comments=False,
            remove_pis=False,
            collect_ids=False,
        )
        try:
            root = etree.fromstring(("<font>" * n + "tail text").encode(), parser)
        except Exception as exc:
            lines.append(f"n={n} raised {type(exc).__name__}: {exc}")
            continue
        depth, node = 0, root
        while len(node):
            node = node[0]
            depth += 1
        log = [
            (e.type_name, e.domain_name, e.level_name, e.type, e.message) for e in parser.error_log
        ]
        lines.append(f"n={n} depth={depth} tail={node.tail!r} text={node.text!r} log={log}")
        lines.append(f"   parse={_parse('<font>' * n + 'tail text')[1]}")
    raise AssertionError("\n".join(lines))
