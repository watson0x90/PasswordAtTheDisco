"""
Tests for the chart save pipeline (visualizations/core.py).

Static PNG export (kaleido) is opt-in and guarded so a kaleido failure/hang
never reaches the HTML report path. These use a mock figure, so they need
neither plotly nor kaleido installed.
"""

from unittest.mock import MagicMock

import pytest

import visualizations.core as vc


@pytest.fixture
def fig():
    f = MagicMock()
    f.to_json.return_value = '{"data": [], "layout": {}}'
    return f


@pytest.fixture(autouse=True)
def _enable_plotly(monkeypatch, tmp_path):
    # Pretend plotly is available and redirect output to a temp dir.
    monkeypatch.setattr(vc, "PLOTLY_AVAILABLE", True)
    monkeypatch.setattr(vc, "html_reports_folder", tmp_path)


class TestSavePlotStaticExport:
    def test_static_disabled_skips_write_image(self, fig):
        result = vc.save_plot(fig, "chart", static=False)
        fig.write_image.assert_not_called()
        assert result["png"] == ""
        assert result["plotly"] == {"data": [], "layout": {}}

    def test_static_enabled_calls_write_image(self, fig):
        result = vc.save_plot(fig, "chart", static=True)
        fig.write_image.assert_called_once()
        assert result["png"].endswith("chart.png")

    def test_static_export_failure_degrades_to_html_only(self, fig):
        # A kaleido error must not crash the pipeline -- png falls back to ''.
        fig.write_image.side_effect = RuntimeError("kaleido boom")
        result = vc.save_plot(fig, "chart", static=True)
        assert result["png"] == ""
        assert result["plotly"] == {"data": [], "layout": {}}

    def test_interactive_outputs_always_produced(self, fig):
        result = vc.save_plot(fig, "chart", static=False)
        fig.write_html.assert_called_once()
        fig.to_json.assert_called_once()
        assert result["html"].endswith("chart.html")

    def test_plotly_unavailable_returns_empty(self, fig, monkeypatch):
        monkeypatch.setattr(vc, "PLOTLY_AVAILABLE", False)
        result = vc.save_plot(fig, "chart")
        assert result == {"png": "", "html": "", "json": "", "plotly": None}
        fig.write_image.assert_not_called()
