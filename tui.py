from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

from rich.text import Text
from textual import events, on
from textual.app import App, ComposeResult
from textual.containers import Vertical
from textual.message import Message
from textual.screen import Screen
from textual.widgets import Input, RichLog, Static


ROOT_DIR = Path(__file__).resolve().parent
RUN_ANALYSIS = ROOT_DIR / "run-analysis.py"
TITLE = "Secret Log Checker Python"
FOOTER = "tool by group 1: { oleksandr, tokla, yanlin }"
MAX_PATH_SUGGESTIONS = 5


def path_completion_parts(value: str) -> tuple[str, Path, str]:
    raw_value = value.strip()
    if not raw_value:
        return "", ROOT_DIR, ""

    expanded = Path(raw_value).expanduser()
    if raw_value.endswith(os.sep):
        return raw_value, expanded, ""

    prefix = expanded.name
    base_path = expanded.parent
    base_display = raw_value[: len(raw_value) - len(Path(raw_value).name)]
    return base_display, base_path, prefix


def matching_directories(value: str) -> tuple[str, list[str]]:
    base_display, base_path, prefix = path_completion_parts(value)
    try:
        children = [child for child in base_path.iterdir() if child.is_dir()]
    except OSError:
        return base_display, []

    include_hidden = prefix.startswith(".")
    matches = [
        child.name
        for child in children
        if child.name.startswith(prefix) and (include_hidden or not child.name.startswith("."))
    ]
    matches.sort(key=str.lower)
    return base_display, matches


class TextMenu(Static, can_focus=True):
    """Small text-only menu to match the requested terminal mockup."""

    class Selected(Message):
        def __init__(self, menu: "TextMenu", index: int) -> None:
            self.menu = menu
            self.index = index
            super().__init__()

    def __init__(self, options: list[str], *, id: str | None = None) -> None:
        super().__init__("", id=id)
        self.options = options
        self.selected_index = 0

    def on_mount(self) -> None:
        self.refresh_menu()

    def refresh_menu(self) -> None:
        output = Text()
        for index, option in enumerate(self.options):
            if index > 0:
                output.append("\n\n")
            selected = index == self.selected_index
            output.append("> " if selected else "  ", style="bold white" if selected else "#a8a8a8")
            output.append(option, style="bold white" if selected else "#a8a8a8")
        self.update(output)

    def move_selection(self, amount: int) -> None:
        self.selected_index = (self.selected_index + amount) % len(self.options)
        self.refresh_menu()

    def submit_selection(self) -> None:
        self.post_message(self.Selected(self, self.selected_index))

    def on_key(self, event: events.Key) -> None:
        if event.key == "up":
            self.move_selection(-1)
            event.stop()
        elif event.key == "down":
            self.move_selection(1)
            event.stop()
        elif event.key == "enter":
            self.submit_selection()
            event.stop()

    def on_click(self, event: events.Click) -> None:
        line_number = event.y
        if line_number % 2 != 0:
            return

        index = line_number // 2
        if index >= len(self.options):
            return

        self.selected_index = index
        self.refresh_menu()
        self.submit_selection()


class MainScreen(Screen[None]):
    BINDINGS = [
        ("q", "quit", "Quit"),
    ]

    def compose(self) -> ComposeResult:
        with Vertical(id="root"):
            yield Static(TITLE, id="title")
            yield TextMenu(
                [
                    "run benchmark suite",
                    "analyse external repo",
                    "about",
                    "quit",
                ],
                id="main_menu",
            )
            yield Static(FOOTER, classes="footer")

    def on_mount(self) -> None:
        self.query_one("#main_menu", TextMenu).focus()

    @on(TextMenu.Selected)
    def on_main_menu_selected(self, event: TextMenu.Selected) -> None:
        if event.index == 0:
            self.app.push_screen(OutputScreen([], "run benchmark suite"))
        elif event.index == 1:
            self.app.push_screen(RepoScreen())
        elif event.index == 2:
            self.app.push_screen(AboutScreen())
        elif event.index == 3:
            self.app.exit()

    def action_quit(self) -> None:
        self.app.exit()


class RepoScreen(Screen[None]):
    BINDINGS = [
        ("tab", "complete_path", "Complete path"),
        ("escape", "back", "Back"),
    ]

    def compose(self) -> ComposeResult:
        with Vertical(id="root"):
            yield Static(TITLE, id="title")
            yield Static("repo path:", classes="label")
            yield Input(placeholder="/path/to/repo", id="repo_path")
            yield Static("", id="repo_suggestions")
            yield Static("", id="repo_error")
            yield TextMenu(["run analysis", "go back"], id="repo_menu")
            yield Static(FOOTER, classes="footer")

    def on_mount(self) -> None:
        self.query_one("#repo_path", Input).focus()

    def action_back(self) -> None:
        self.app.pop_screen()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "repo_path":
            self.start_repo_analysis()

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "repo_path":
            self.update_path_suggestions()

    def action_complete_path(self) -> None:
        path_input = self.query_one("#repo_path", Input)
        base_display, matches = matching_directories(path_input.value)
        if not matches:
            self.update_path_suggestions("no matching directories")
            return

        _, _, prefix = path_completion_parts(path_input.value)
        common_prefix = os.path.commonprefix(matches)
        if common_prefix and common_prefix != prefix:
            path_input.value = base_display + common_prefix
            path_input.cursor_position = len(path_input.value)
        elif len(matches) == 1:
            path_input.value = base_display + matches[0] + os.sep
            path_input.cursor_position = len(path_input.value)

        self.update_path_suggestions()

    @on(TextMenu.Selected)
    def on_repo_menu_selected(self, event: TextMenu.Selected) -> None:
        if event.index == 0:
            self.start_repo_analysis()
        elif event.index == 1:
            self.app.pop_screen()

    def start_repo_analysis(self) -> None:
        repo_path = self.query_one("#repo_path", Input).value.strip()
        error = self.query_one("#repo_error", Static)
        if not repo_path:
            error.update("enter a repo path first")
            return
        error.update("")
        self.app.push_screen(OutputScreen(["--repo", repo_path], "analyse external repo"))

    def update_path_suggestions(self, message: str | None = None) -> None:
        suggestions = self.query_one("#repo_suggestions", Static)
        if message is not None:
            suggestions.update(message)
            return

        path_input = self.query_one("#repo_path", Input)
        base_display, matches = matching_directories(path_input.value)
        if not matches:
            suggestions.update("")
            return

        visible_matches = matches[:MAX_PATH_SUGGESTIONS]
        rendered_matches = "  ".join(base_display + match + os.sep for match in visible_matches)
        if len(matches) > MAX_PATH_SUGGESTIONS:
            rendered_matches += f"  (+{len(matches) - MAX_PATH_SUGGESTIONS} more)"
        suggestions.update(rendered_matches)


class AboutScreen(Screen[None]):
    BINDINGS = [
        ("escape", "back", "Back"),
    ]

    def compose(self) -> ComposeResult:
        with Vertical(id="root"):
            yield Static(TITLE, id="title")
            yield Static("A static analysis tool built with Pysa (Pyre) to detect sensitive data leakage into logging statements in Python applications.", id="about_body")
            yield TextMenu(["go back"], id="about_menu")
            yield Static(FOOTER, classes="footer")

    def on_mount(self) -> None:
        self.query_one("#about_menu", TextMenu).focus()

    def action_back(self) -> None:
        self.app.pop_screen()

    @on(TextMenu.Selected)
    def on_about_menu_selected(self, _: TextMenu.Selected) -> None:
        self.app.pop_screen()


class OutputScreen(Screen[None]):
    BINDINGS = [
        ("escape", "back", "Back"),
    ]

    def __init__(self, args: list[str], run_label: str) -> None:
        super().__init__()
        self.args = args
        self.run_label = run_label
        self.process: asyncio.subprocess.Process | None = None

    def compose(self) -> ComposeResult:
        with Vertical(id="root"):
            yield Static(TITLE, id="title")
            yield Static("", id="run_status")
            yield RichLog(id="output", highlight=False, wrap=True, markup=False)
            yield TextMenu(["go back"], id="output_menu")
            yield Static(FOOTER, classes="footer")

    def on_mount(self) -> None:
        self.query_one("#output_menu", TextMenu).focus()
        self.run_worker(self.run_command(), exclusive=True)

    async def run_command(self) -> None:
        status = self.query_one("#run_status", Static)
        output = self.query_one("#output", RichLog)
        display_command = "python run-analysis.py"
        if self.args:
            display_command += " " + " ".join(self.args)

        status.update(f"running {self.run_label}")
        output.write(f"$ {display_command}")
        output.write("")

        try:
            self.process = await asyncio.create_subprocess_exec(
                sys.executable,
                "-u",
                str(RUN_ANALYSIS),
                *self.args,
                cwd=str(ROOT_DIR),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
        except OSError as error:
            status.update("failed to start analysis")
            output.write(str(error))
            return

        assert self.process.stdout is not None
        while True:
            line = await self.process.stdout.readline()
            if not line:
                break
            output.write(line.decode(errors="replace").rstrip("\n"))

        return_code = await self.process.wait()
        self.process = None
        output.write("")
        if return_code == 0:
            status.update("analysis complete")
            output.write("analysis complete")
        else:
            status.update(f"analysis failed with exit code {return_code}")
            output.write(f"analysis failed with exit code {return_code}")

    async def action_back(self) -> None:
        await self.stop_process()
        self.app.pop_screen()

    @on(TextMenu.Selected)
    async def on_output_menu_selected(self, _: TextMenu.Selected) -> None:
        await self.action_back()

    async def on_unmount(self) -> None:
        await self.stop_process()

    async def stop_process(self) -> None:
        if self.process is None or self.process.returncode is not None:
            return

        self.process.terminate()
        try:
            await asyncio.wait_for(self.process.wait(), timeout=2)
        except asyncio.TimeoutError:
            self.process.kill()
            await self.process.wait()
        finally:
            self.process = None


class SecretLogCheckerTUI(App[None]):
    CSS = """
    Screen {
        background: #1b1b1b;
        color: #f2f2f2;
    }

    #root {
        padding: 3 8;
        height: 100%;
    }

    #title {
        height: 3;
        text-style: bold;
        color: #f4f4f4;
    }

    TextMenu {
        height: auto;
        margin-top: 1;
        margin-bottom: 2;
    }

    TextMenu:focus {
        text-style: none;
    }

    .footer {
        color: #7d7d7d;
        margin-top: 1;
    }

    .label {
        color: #bdbdbd;
        margin-top: 1;
    }

    #repo_path {
        background: #1b1b1b;
        color: #f2f2f2;
        border: none;
        width: 70;
        margin-top: 1;
        margin-bottom: 1;
    }

    #repo_error {
        color: #e88c8c;
        height: 1;
    }

    #repo_suggestions {
        color: #7d7d7d;
        height: 1;
        margin-bottom: 1;
    }

    #about_body {
        color: #bdbdbd;
        margin-top: 1;
        margin-bottom: 2;
    }

    #run_status {
        color: #bdbdbd;
        margin-bottom: 1;
    }

    #output {
        height: 1fr;
        min-height: 10;
        background: #1b1b1b;
        color: #d8d8d8;
        border: none;
        padding: 0;
        margin-bottom: 1;
    }
    """

    ENABLE_COMMAND_PALETTE = False

    def on_mount(self) -> None:
        self.push_screen(MainScreen())


if __name__ == "__main__":
    SecretLogCheckerTUI().run()
