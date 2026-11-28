"""BODYSTRUCTURE shapes and malformed-boundary mails for C2, generated at test time."""

from __future__ import annotations

from .generators import _mail

Node = tuple[object, ...]


def text_leaf(size: int = 5, *, charset: bytes = b"utf-8", encoding: bytes = b"7bit") -> Node:
    return (
        b"text",
        b"plain",
        (b"charset", charset),
        None,
        None,
        encoding,
        size,
        1,
        None,
        None,
        None,
    )


def html_leaf(size: int = 5) -> Node:
    return (
        b"text",
        b"html",
        (b"charset", b"utf-8"),
        None,
        None,
        b"7bit",
        size,
        1,
        None,
        None,
        None,
    )


def attachment_leaf(name: bytes = b"a.bin", size: int = 10) -> Node:
    return (
        b"application",
        b"octet-stream",
        None,
        None,
        None,
        b"base64",
        size,
        None,
        (b"attachment", (b"filename", name)),
        None,
    )


def multipart(children: list[object], subtype: bytes = b"mixed") -> Node:
    return (children, subtype, (b"boundary", b"b"), None, None, None)


def deep_bodystructure(depth: int) -> Node:
    node: Node = text_leaf()
    for _ in range(depth):
        node = multipart([node])
    return node


def wide_bodystructure(count: int) -> Node:
    return multipart([text_leaf() for _ in range(count)])


def declared_size_bodystructure(size: int) -> Node:
    return multipart([text_leaf(size), attachment_leaf(size=size)])


def malformed_boundary_mails() -> dict[str, bytes]:
    body = b"--b\r\nContent-Type: text/plain\r\n\r\nx\r\n--b--\r\n"
    return {
        "missing": _mail("multipart/mixed", body),
        "empty": _mail('multipart/mixed; boundary=""', body),
        "overlong": _mail(f'multipart/mixed; boundary="{"b" * 5000}"', body),
        "absent_from_body": _mail('multipart/mixed; boundary="zz"', body),
        "prefix_only": _mail(
            'multipart/mixed; boundary="b"',
            b"--b1\r\nContent-Type: text/plain\r\n\r\nx\r\n--b1--\r\n",
        ),
    }


def lf_only_mail() -> bytes:
    return (
        b"Content-Type: multipart/mixed; boundary=b\n\n"
        b"--b\nContent-Type: text/plain\n\none\n--b\nContent-Type: text/html\n\ntwo\n--b--\n"
    )
