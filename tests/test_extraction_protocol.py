"""Extraction-protocol declaration (AR082 / AC-403).

The analyzer pins ``EXTRACTION_PROTOCOL_VERSION = "2.0"`` explicitly so core's
``declared_extraction_protocol()`` reports "2.0" rather than the SDK default.
Plugins written against protocol 1.0 keep loading indefinitely: core lifts
their ``ScanResult`` into the v2 ``ExtractionResult`` container through
``attackmap.extraction.adapters`` (v1 -> v2 -> v1 round trip is lossless).
"""

from attackmap.extraction.adapters import to_extraction_result, to_scan_result
from attackmap.sdk.analyzer_contracts import declared_extraction_protocol

from attackmap_analyzer_java_spring import EXTRACTION_PROTOCOL_VERSION, JavaSpringAnalyzer


def test_declares_extraction_protocol_2() -> None:
    analyzer = JavaSpringAnalyzer()
    assert EXTRACTION_PROTOCOL_VERSION == "2.0"
    assert analyzer.EXTRACTION_PROTOCOL_VERSION == "2.0"
    assert declared_extraction_protocol(analyzer) == "2.0"


def test_v1_payload_still_loads_via_core_adapter(tmp_path) -> None:
    (tmp_path / "pom.xml").write_text(
        "<project><artifactId>demo</artifactId></project>\n", encoding="utf-8"
    )
    src = tmp_path / "src" / "main" / "java" / "UserController.java"
    src.parent.mkdir(parents=True)
    src.write_text(
        'import org.springframework.web.bind.annotation.*;\n'
        '@RestController\n'
        '@RequestMapping("/api")\n'
        'public class UserController {\n'
        '    @GetMapping("/users")\n'
        '    public Object list() { return null; }\n'
        '}\n',
        encoding="utf-8",
    )
    analyzer = JavaSpringAnalyzer()
    assert analyzer.detect(tmp_path)
    v1 = analyzer.analyze(tmp_path)
    lifted = to_extraction_result(v1)
    assert lifted.source_protocol_version == "1.0"
    round_tripped = to_scan_result(lifted)
    assert round_tripped.model_dump() == v1.model_dump()
