"""Safe PDF fixtures for testing invisible text-layer injection in a document-ingestion flow.

The generated PDF has a visible benign cover line and an invisible, selectable text layer. Whether a
target's PDF parser extracts and obeys that layer is measured by the target adapter and oracle; this
module only builds the artifact and never submits it anywhere by itself.
"""

from __future__ import annotations

from io import BytesIO

from pypdf import PdfWriter
from pypdf.generic import DecodedStreamObject, DictionaryObject, NameObject

MAX_HIDDEN_TEXT_CHARS = 32_768


def _literal(text: str) -> bytes:
    """Encode a PDF literal string in WinAnsi-compatible bytes with PDF delimiters escaped."""
    encoded = text.encode("cp1252", errors="replace")
    return b"(" + encoded.replace(b"\\", b"\\\\").replace(b"(", b"\\(").replace(b")", b"\\)") + b")"


def invisible_text_pdf(payload: str, *, visible_text: str = "Document received for review.") -> bytes:
    """Return a one-page PDF whose text extractor sees ``payload`` but whose page does not render it.

    PDF text rendering mode ``3 Tr`` suppresses glyph rendering while retaining the text in the
    content stream. The hidden layer is ASCII because the bundled standard Helvetica font has no
    dependable Unicode ToUnicode map; reject other characters rather than create a misleading
    fixture. The separate Unicode-tag converter covers invisible Unicode payloads.
    """
    if not isinstance(payload, str) or not payload:
        raise ValueError("payload must be non-empty text")
    if len(payload) > MAX_HIDDEN_TEXT_CHARS:
        raise ValueError(f"payload exceeds the {MAX_HIDDEN_TEXT_CHARS}-character PDF fixture limit")
    if not payload.isascii():
        raise ValueError("the hidden PDF text layer accepts ASCII only; use ascii_smuggler for Unicode text tests")
    writer = PdfWriter()
    page = writer.add_blank_page(width=612, height=792)
    font = DictionaryObject({
        NameObject("/Type"): NameObject("/Font"),
        NameObject("/Subtype"): NameObject("/Type1"),
        NameObject("/BaseFont"): NameObject("/Helvetica"),
        NameObject("/Encoding"): NameObject("/WinAnsiEncoding"),
    })
    font_ref = writer._add_object(font)
    resources = DictionaryObject({NameObject("/Font"): DictionaryObject({NameObject("/F1"): font_ref})})
    page[NameObject("/Resources")] = resources

    commands = (b"BT /F1 12 Tf 0 Tr 72 730 Td " + _literal(visible_text) + b" Tj ET\n"
                b"BT /F1 9 Tf 3 Tr 72 700 Td " + _literal(payload) + b" Tj ET\n")
    stream = DecodedStreamObject()
    stream.set_data(commands)
    page[NameObject("/Contents")] = writer._add_object(stream)

    output = BytesIO()
    writer.write(output)
    return output.getvalue()
