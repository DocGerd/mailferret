"""Hypothesis strategies for the C2 MIME walk: hostile BODYSTRUCTURE values and small limits."""

from __future__ import annotations

from hypothesis import strategies as st

from mailferret.limits import Limits

_scalars = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(-5, 2**40),
    st.binary(max_size=12),
    st.sampled_from([b"text", b"plain", b"html", b"multipart", b"mixed", b"message", b"rfc822"]),
    st.text(max_size=8),
)

_leaf = st.tuples(
    st.sampled_from([b"text", b"image", b"application", b"message", None, 7]),
    st.sampled_from([b"plain", b"html", b"png", b"rfc822", None]),
    st.one_of(st.none(), st.tuples(st.just(b"charset"), st.binary(max_size=8))),
    _scalars,
    _scalars,
    st.sampled_from([b"7bit", b"base64", b"quoted-printable", b"x-weird", None, 3]),
    _scalars,
    st.lists(_scalars, max_size=8).map(tuple),
).map(lambda t: (*t[:7], *t[7]))


def _extend(children: st.SearchStrategy[object]) -> st.SearchStrategy[object]:
    return st.one_of(
        st.lists(children, max_size=5).map(lambda kids: (kids, b"mixed", None, None, None, None)),
        st.lists(children, max_size=4).map(
            lambda kids: (*[k for k in kids if isinstance(k, tuple)], b"mixed", None)
        ),
        st.lists(_scalars, max_size=6).map(tuple),
    )


bodystructures = st.recursive(_leaf, _extend, max_leaves=40)

small_limits = st.builds(
    Limits,
    max_mime_depth=st.integers(1, 4),
    max_mime_parts=st.integers(1, 6),
    max_attachments_listed=st.integers(1, 3),
    max_part_bytes=st.integers(1, 64),
    max_body_chars=st.integers(1, 32),
    max_header_bytes=st.integers(16, 256),
)
