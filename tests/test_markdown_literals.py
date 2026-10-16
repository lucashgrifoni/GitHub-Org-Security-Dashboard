"""User-supplied fields remain visible data in a Markdown renderer."""

from datetime import UTC, datetime
from html.parser import HTMLParser

import pytest
from markdown_it import MarkdownIt

from ghorgsec.comparison import compare_snapshots
from ghorgsec.models import ControlState, OrgSecuritySnapshot, RepositorySecurityControls
from ghorgsec.report import render_markdown_comparison, render_markdown_report
from ghorgsec.serialize import snapshot_to_dict


class RenderedDocument(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.text: list[str] = []
        self.tags: list[str] = []
        self.comments: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags.append(tag)

    def handle_data(self, data: str) -> None:
        self.text.append(data)

    def handle_comment(self, data: str) -> None:
        self.comments.append(data)


@pytest.mark.parametrize(
    "value",
    [
        "<!--hidden-repository-->",
        '<img src="https://example.invalid/pixel">',
        "[replacement](https://example.invalid)",
        "![replacement](https://example.invalid/pixel)",
        "*emphasized* and **strong** and _underscores_",
        "&amp; and &#65;",
        r"backslash\*emphasis* and backslash\|pipe",
        "tick` followed by <img src=x> and `end",
        "``matched`` and `unmatched",
        "pipe|delimiter and 主分支",
        "# forged heading",
        "## forged heading",
        "---",
        "- nested item",
        "+ nested item",
        "1. ordered item",
    ],
)
@pytest.mark.parametrize("field", ["name", "default_branch", "warnings", "organization"])
def test_input_is_visible_without_creating_html_or_markdown(value: str, field: str) -> None:
    repo = RepositorySecurityControls(
        name=value if field == "name" else "api",
        default_branch=value if field == "default_branch" else "main",
        branch_protection=ControlState.ENABLED,
        secret_scanning=ControlState.ENABLED,
        code_scanning=ControlState.ENABLED,
        dependabot_alerts=ControlState.ENABLED,
    )
    snapshot = OrgSecuritySnapshot(
        organization=value if field == "organization" else "example-org",
        generated_at=datetime(2026, 10, 6, tzinfo=UTC),
        collection_mode="fixture_json",
        repositories=(repo,),
        warnings=(value,) if field == "warnings" else (),
    )
    document = RenderedDocument()
    # Raw HTML enabled intentionally: the renderer must escape the data itself.
    renderer = MarkdownIt("commonmark", {"html": True}).enable("table")
    document.feed(renderer.render(render_markdown_report(snapshot)))

    assert value in "".join(document.text)
    assert not ({"a", "img", "em", "strong", "script"} & set(document.tags))
    assert not document.comments
    serialized = snapshot_to_dict(snapshot)
    if field == "warnings":
        assert serialized[field] == [value]
    elif field == "organization":
        assert serialized[field] == value
    else:
        assert serialized["repositories"][0][field] == value


@pytest.mark.parametrize("value", [
    "<!--hidden-repository-->",
    '<img src="https://example.invalid/pixel">',
    "[replacement](https://example.invalid)",
    "tick` followed by <img src=x> and `end",
])
def test_new_sections_render_untrusted_fields_literally(value: str) -> None:
    def snapshot(state: ControlState, day: int) -> OrgSecuritySnapshot:
        return OrgSecuritySnapshot(
            organization=value,
            generated_at=datetime(2026, 10, day, tzinfo=UTC),
            collection_mode="fixture_json",
            repositories=(RepositorySecurityControls(
                name=value,
                branch_protection=state,
                secret_scanning=state,
                code_scanning=state,
                dependabot_alerts=state,
            ),),
            warnings=(value,),
        )

    baseline, current = snapshot(ControlState.DISABLED, 5), snapshot(ControlState.UNKNOWN, 6)
    renderer = MarkdownIt("commonmark", {"html": True}).enable("table")
    for markdown in (
        render_markdown_report(baseline),
        render_markdown_comparison(compare_snapshots(baseline, current)),
    ):
        document = RenderedDocument()
        document.feed(renderer.render(markdown))
        assert value in "".join(document.text)
        assert not ({"a", "img", "em", "strong", "script"} & set(document.tags))
        assert not document.comments
