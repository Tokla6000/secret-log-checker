from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from textual import work
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Input, OptionList, RichLog, Static


class SecretLogCheckerApp(App):
    CSS = """
    Screen {
        background: #171717;
        color: #e6e6e6;
    }

    #root {
        padding: 2 4;
    }

    #title {
        text-style: bold;
        height: 3;
        margin-bottom: 1;
    }

    #menu {
        height: auto;
        margin-bottom: 2;
    }

    #repo_row {
        display: none;
        margin-bottom: 2;
    }

    #repo_label {
        width: 14;
    }

    #output {
        display: none;
        height: 1fr;
        padding: 1 0 0 0;
    }

    #footer {
        color: #8c8c8c;
        margin-top: 1;
    }
    """

    def compose(self) -> ComposeResult:
        with Vertical(id="root"):
            yield Static("Secret Log Checker Python", id="title")
            yield OptionList(
                "run benchmark suite",
                "analyse external repo",
                "quit",
                id="menu",
            )
            with Horizontal(id="repo_row"):
                yield Static("repo path:", id="repo_label")
                yield Input(placeholder="/path/to/repo", id="repo_path")
            yield RichLog(id="output", highlight=True, wrap=True)
            yield Static("tool by group 1: { oleksandr, tokla, yanlin }", id="footer")

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        selection = event.option_index
        if selection == 0:
            self._hide_repo_input()
            self._start_run([])
            return

        if selection == 1:
            self._show_repo_input()
            return

        if selection == 2:
            self.exit()
            return

    def _start_run(self, args: list[str]) -> None:
        self._set_controls_disabled(True)
        self._clear_output()
        self._write_output("Running analysis...\n")
        self._run_analysis(args)

    @work(thread=True)
    def _run_analysis(self, args: list[str]) -> None:
        script_path = Path(__file__).with_name("run-analysis.py")
        command = [sys.executable, str(script_path), *args]
        result = subprocess.run(command, capture_output=True, text=True)

        output = result.stdout
        if result.stderr:
            output = f"{output}\n{result.stderr}" if output else result.stderr

        if not output:
            output = "(no output)"

        self.call_from_thread(self._finish_run, output, result.returncode)

    def _finish_run(self, output: str, return_code: int) -> None:
        self._write_output(output)
        if return_code != 0:
            self._write_output(f"\nExit code: {return_code}")
        self._set_controls_disabled(False)

    def _clear_output(self) -> None:
        output = self.query_one("#output", RichLog)
        output.clear()

    def _write_output(self, message: str) -> None:
        output = self.query_one("#output", RichLog)
        output.display = True
        for line in message.splitlines() or [""]:
            output.write(line)

    def _set_controls_disabled(self, disabled: bool) -> None:
        self.query_one("#menu", OptionList).disabled = disabled
        self.query_one("#repo_path", Input).disabled = disabled

    def _show_repo_input(self) -> None:
        repo_row = self.query_one("#repo_row", Horizontal)
        repo_row.display = True
        repo_input = self.query_one("#repo_path", Input)
        repo_input.focus()
        self._write_output("Enter a repo path, then press Enter.")

    def _hide_repo_input(self) -> None:
        repo_row = self.query_one("#repo_row", Horizontal)
        repo_row.display = False

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id != "repo_path":
            return
        repo_path = event.value.strip()
        if not repo_path:
            self._write_output("Please enter a repo path.")
            return
        self._hide_repo_input()
        self._start_run(["--repo", repo_path])


if __name__ == "__main__":
    SecretLogCheckerApp().run()
