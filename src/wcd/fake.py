"""Synthetic fake-desktop backend: the whole driver, no Windows required.

The transaction state machine, envelope engine, lease, and profile schema are
tested against a **scripted window/dialog model** (docs/contract.md section
13) -- this module is that model. It exposes the same action vocabulary as the
in-guest helper (contract section 8): ``context``, ``uia_dump``, ``key``,
``mouse``, ``wait_foreground``. Like the helper, it **never interprets**: the
actions return facts about the scripted surface and inject input into it, and
every input gesture is journaled. Unlike the helper it has no session, no
Windows, and no SendInput -- it is a model, and everything it "does" is a hook
the test scripted.

WHAT IS SCRIPTED
    A :class:`FakeDesktop` holds named :class:`FakeWindow` objects (each a
    title, class, rect, and a fake UIA element tree of :class:`FakeElement`
    nodes), a foreground window, session identity fields, and a ``state`` dict
    standing in for the machine state the GPO observers would really read.
    Elements carry optional ``on_click`` / ``on_key`` hooks receiving the
    desktop; a click on a scripted OK button fires the hook that mutates the
    scripted state -- which is how a full transaction runs end to end:
    lease -> context assert -> navigate -> click OK (commit) -> envelope
    satisfied. Clicking an element also focuses it (the window's
    ``focused_element``), so ``key`` routes text into the field a test clicked.

FAILURES ARE SCRIPTED, NOT SIMULATED SUBTLY
    - **stale focus / context drift**: :meth:`FakeDesktop.set_foreground`,
      or mutating ``desktop``/``user``/``session_id`` mid-flight, surfaces at
      the next context assertion exactly as the contract's named unsupported
      states do -- as mismatches (section 7).
    - **undeclared commit**: script a hook that mutates ``state`` on an
      element whose action the profile never classified as a commit point.
      The surface happily mutates; the transaction machine's
      undeclared-mutation hard stop is what must catch it.
    - **no convergence**: set ``on_observe`` to a hook that changes a
      require-referenced fact on every observation; the oracle never
      stabilizes and :func:`wcd.envelope.converge` reports indeterminate.

    ``wait_foreground`` polls through the injectable clock/sleep, so tests
    control time and never wait.

WHAT THIS BACKEND IS NOT
    No screenshots (the helper's PNG path), no MSAA, no window messages, no
    timing jitter, no input translation -- anything those paths would have
    broken remains untested until the first estate window. It models the
    *logic* the driver depends on, not the platform.
"""

from __future__ import annotations

import hashlib
import re
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from wcd.leases import ForegroundContext, InteractiveContext


class FakeSurfaceError(Exception):
    """An action hit the scripted surface where nothing was there."""


MOUSE_BUTTONS: tuple[str, ...] = ("left", "right", "middle")
MOUSE_ACTIONS: tuple[str, ...] = ("click", "double", "down", "up")


@dataclass(frozen=True)
class FakeRect:
    """A screen rectangle; coordinates are absolute, like the helper's."""

    left: int
    top: int
    right: int
    bottom: int

    @property
    def width(self) -> int:
        return self.right - self.left

    @property
    def height(self) -> int:
        return self.bottom - self.top

    def contains(self, x: int, y: int) -> bool:
        return self.left <= x < self.right and self.top <= y < self.bottom


@dataclass
class FakeElement:
    """One fake UIA element: identity, geometry, patterns, and scripted hooks.

    ``name`` is the scripting name (unique within its window); ``title``,
    ``class_name``, ``automation_id``, ``control_type``, ``rect``, and
    ``patterns`` mirror what ``uia_dump`` reports. ``on_click`` receives the
    desktop when clicked; ``on_key`` receives the desktop and the typed text
    when the element is focused and ``key`` delivers text.
    """

    name: str
    control_type: str
    rect: FakeRect
    title: str | None = None
    class_name: str | None = None
    automation_id: str | None = None
    patterns: tuple[str, ...] = ()
    children: list[FakeElement] = field(default_factory=list)
    on_click: Callable[[FakeDesktop], None] | None = None
    on_key: Callable[[FakeDesktop, str], None] | None = None


@dataclass
class FakeWindow:
    """One scripted window or dialog."""

    name: str
    title: str
    class_name: str
    rect: FakeRect
    pid: int = 0
    hwnd: int = 0
    elements: list[FakeElement] = field(default_factory=list)
    focused_element: str | None = None
    on_key: Callable[[FakeDesktop, str], None] | None = None

    def fingerprint(self) -> str:
        """A digest over title, class, rect, and the whole element tree.

        This is the fake's stand-in for the UIA surface fingerprint the
        context assertion binds to: any scripted change to the window's shape
        changes the fingerprint.
        """
        lines = [self.title, self.class_name, _rect_text(self.rect)]
        for element in self.elements:
            lines.extend(_element_lines(element, 0))
        payload = "\n".join(lines)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _rect_text(rect: FakeRect) -> str:
    return f"{rect.left},{rect.top},{rect.right},{rect.bottom}"


def _element_lines(element: FakeElement, depth: int) -> list[str]:
    line = (
        f"  {depth}|{element.name}|{element.title}|{element.class_name}|"
        f"{element.automation_id}|{element.control_type}|{_rect_text(element.rect)}|"
        f"{','.join(element.patterns)}"
    )
    lines = [line]
    for child in element.children:
        lines.extend(_element_lines(child, depth + 1))
    return lines


# --- Helper-shaped action results ---------------------------------------------


@dataclass(frozen=True)
class FakeForeground:
    """The foreground part of a ``context`` result (helper-shaped)."""

    hwnd: int
    pid: int
    process: str
    title: str
    class_name: str
    rect: FakeRect
    uia_digest: str


@dataclass(frozen=True)
class FakeContext:
    """The ``context`` action result (helper-shaped)."""

    session_id: int
    user: str
    desktop: str | None
    foreground: FakeForeground | None

    def interactive_context(self) -> InteractiveContext:
        """Convert to the lease module's context record for assertions."""
        foreground = self.foreground
        return InteractiveContext(
            session_id=self.session_id,
            user=self.user,
            desktop=self.desktop,
            foreground=None
            if foreground is None
            else ForegroundContext(
                hwnd=foreground.hwnd,
                pid=foreground.pid,
                process=foreground.process,
                fingerprint=foreground.uia_digest,
            ),
        )


@dataclass(frozen=True)
class FakeUiaElement:
    """One flattened element of a ``uia_dump`` result."""

    depth: int
    name: str | None
    class_name: str | None
    automation_id: str | None
    control_type: str
    rect: FakeRect
    patterns: tuple[str, ...]


@dataclass(frozen=True)
class FakeUiaDump:
    """The ``uia_dump`` action result (helper-shaped)."""

    depth: int
    truncated: bool
    element_count: int
    elements: tuple[FakeUiaElement, ...]


@dataclass(frozen=True)
class FakeKeyResult:
    """The ``key`` action result.

    Mirrors the helper's discipline: the typed text never comes back, only its
    length and sha256 (the text is not a secret here, but the model should not
    make secrets pass through it comfortably either).
    """

    dry_run: bool
    text_length: int | None
    text_sha256: str | None
    chords_sent: int | None
    injected_events: int
    would_inject: dict[str, object] | None


@dataclass(frozen=True)
class FakeMouseResult:
    """The ``mouse`` action result (helper-shaped)."""

    dry_run: bool
    x: int
    y: int
    button: str
    mouse_action: str
    hwnd: int | None
    element: str | None
    injected_events: int
    would_inject: dict[str, object] | None


@dataclass(frozen=True)
class FakeWaitResult:
    """The ``wait_foreground`` action result (helper-shaped)."""

    matched: bool
    waited_ms: int
    window: str | None


class FakeDesktop:
    """A scripted desktop exposing the helper's action vocabulary.

    ``clock`` and ``sleep`` are injectable so tests script time (used by
    ``wait_foreground`` and by any oracle polling built on top).
    """

    def __init__(
        self,
        *,
        session_id: int = 1,
        user: str = "lab-user",
        desktop: str = "Default",
        process: str = "mmc.exe",
        process_pid: int = 4242,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.session_id = session_id
        self.user = user
        self.desktop = desktop
        self.process = process
        self.process_pid = process_pid
        self._clock = clock
        self._sleep = sleep
        self.windows: dict[str, FakeWindow] = {}
        self.foreground: str | None = None
        self.state: dict[str, object] = {}
        self.on_observe: Callable[[FakeDesktop], None] | None = None
        self.journal: list[str] = []
        self._next_hwnd = 0x10010

    # -- scripting surface -----------------------------------------------------

    def add_window(self, window: FakeWindow) -> FakeWindow:
        """Register ``window`` and assign it an hwnd (and pid if unset)."""
        if window.name in self.windows:
            raise ValueError(f"window {window.name!r} already exists on this desktop")
        self._next_hwnd += 1
        window.hwnd = self._next_hwnd
        if window.pid == 0:
            window.pid = self.process_pid
        self.windows[window.name] = window
        self.journal.append(f"window added: {window.name}")
        return window

    def close_window(self, name: str) -> None:
        """Remove a window (a scripted dialog closing itself)."""
        if name not in self.windows:
            raise FakeSurfaceError(f"window {name!r} is not open")
        del self.windows[name]
        if self.foreground == name:
            self.foreground = None
        self.journal.append(f"window closed: {name}")

    def set_foreground(self, name: str | None) -> None:
        """Script the foreground window (``None`` = no foreground at all)."""
        if name is not None and name not in self.windows:
            raise FakeSurfaceError(f"cannot foreground unknown window {name!r}")
        self.foreground = name
        self.journal.append(f"foreground set: {name}")

    # -- helper action vocabulary ---------------------------------------------

    def context(self) -> FakeContext:
        """Report session, user, desktop, and the foreground window's facts."""
        window = self._foreground_window()
        foreground = None
        if window is not None:
            foreground = FakeForeground(
                hwnd=window.hwnd,
                pid=window.pid,
                process=self.process,
                title=window.title,
                class_name=window.class_name,
                rect=window.rect,
                uia_digest=window.fingerprint(),
            )
        return FakeContext(
            session_id=self.session_id,
            user=self.user,
            desktop=self.desktop,
            foreground=foreground,
        )

    def interactive_context(self) -> InteractiveContext:
        """The ``context`` facts as the lease module's assertion record."""
        return self.context().interactive_context()

    def uia_dump(self, *, depth: int = 4) -> FakeUiaDump:
        """Flatten the foreground window's element tree up to ``depth``."""
        if depth < 1:
            raise ValueError("depth must be >= 1")
        window = self._foreground_or_raise()
        elements: list[FakeUiaElement] = []
        truncated = False

        def walk(nodes: Sequence[FakeElement], level: int) -> None:
            nonlocal truncated
            for node in nodes:
                if level <= depth:
                    elements.append(
                        FakeUiaElement(
                            depth=level,
                            name=node.title,
                            class_name=node.class_name,
                            automation_id=node.automation_id,
                            control_type=node.control_type,
                            rect=node.rect,
                            patterns=node.patterns,
                        )
                    )
                    if node.children:
                        walk(node.children, level + 1)
                else:
                    truncated = True

        walk(window.elements, 1)
        return FakeUiaDump(
            depth=depth, truncated=truncated, element_count=len(elements), elements=tuple(elements)
        )

    def key(
        self,
        *,
        text: str | None = None,
        chords: Sequence[tuple[int, tuple[str, ...]]] | None = None,
        dry_run: bool = False,
    ) -> FakeKeyResult:
        """Inject text or key chords into the scripted surface.

        Text goes to the focused element's ``on_key`` (or the window's
        ``on_key`` fallback); chords are counted and delivered to the window's
        ``on_key`` if scripted. Dry runs report what would have happened.
        """
        if text is None and not chords:
            raise ValueError("key requires text or chords")
        if text is not None and chords:
            raise ValueError("key takes text or chords, not both")
        if dry_run:
            would_inject: dict[str, object] = {
                "text_length": len(text) if text is not None else None,
                "chords": [list(chord) for chord in chords] if chords is not None else None,
            }
            return FakeKeyResult(
                dry_run=True,
                text_length=None,
                text_sha256=None,
                chords_sent=None,
                injected_events=0,
                would_inject=would_inject,
            )
        text_length: int | None = None
        text_sha256: str | None = None
        chords_sent: int | None = None
        if text is not None:
            text_length = len(text)
            text_sha256 = hashlib.sha256(text.encode("utf-8")).hexdigest()
            self._deliver_text(text)
        else:
            assert chords is not None
            chords_sent = len(chords)
            window = self._foreground_or_raise()
            if window.on_key is not None:
                for vk, modifiers in chords:
                    window.on_key(self, f"vk={vk}:{'+'.join(modifiers)}")
        self.journal.append(f"key: text_length={text_length} chords={chords_sent}")
        return FakeKeyResult(
            dry_run=False,
            text_length=text_length,
            text_sha256=text_sha256,
            chords_sent=chords_sent,
            injected_events=text_length if text_length is not None else (chords_sent or 0),
            would_inject=None,
        )

    def mouse(
        self,
        *,
        x: int,
        y: int,
        button: str = "left",
        mouse_action: str = "click",
        hwnd: int | None = None,
        dry_run: bool = False,
    ) -> FakeMouseResult:
        """Click/press at window-relative coordinates (helper semantics).

        The point resolves to the deepest scripted element whose rect contains
        it; clicking an element focuses it, then fires its ``on_click`` hook
        (once per click, twice for ``double``). ``down``/``up`` record without
        firing hooks.
        """
        if button not in MOUSE_BUTTONS:
            raise ValueError(f"button must be one of {MOUSE_BUTTONS}, got {button!r}")
        if mouse_action not in MOUSE_ACTIONS:
            raise ValueError(f"mouse_action must be one of {MOUSE_ACTIONS}, got {mouse_action!r}")
        window = self._window_by_hwnd(hwnd) if hwnd is not None else self._foreground_or_raise()
        abs_x = window.rect.left + x
        abs_y = window.rect.top + y
        element = _find_element_at(window.elements, abs_x, abs_y)
        element_name = element.name if element is not None else None
        would_inject = {
            "x": x,
            "y": y,
            "button": button,
            "mouse_action": mouse_action,
            "hwnd": window.hwnd,
            "element": element_name,
        }
        if dry_run:
            return FakeMouseResult(
                dry_run=True,
                x=x,
                y=y,
                button=button,
                mouse_action=mouse_action,
                hwnd=window.hwnd,
                element=element_name,
                injected_events=0,
                would_inject=would_inject,
            )
        clicks = 2 if mouse_action == "double" else 1
        if element is not None and mouse_action in ("click", "double"):
            window.focused_element = element.name
            for _ in range(clicks):
                if element.on_click is not None:
                    element.on_click(self)
        self.journal.append(
            f"mouse {mouse_action} {button} at window-relative ({x},{y}) on "
            f"{element_name or 'no element'}"
        )
        return FakeMouseResult(
            dry_run=False,
            x=x,
            y=y,
            button=button,
            mouse_action=mouse_action,
            hwnd=window.hwnd,
            element=element_name,
            injected_events=clicks,
            would_inject=None,
        )

    def wait_foreground(
        self,
        *,
        title_regex: str | None = None,
        class_name: str | None = None,
        pid: int | None = None,
        timeout_ms: int = 10000,
        poll_ms: int = 250,
    ) -> FakeWaitResult:
        """Poll until the foreground window matches, through the fake clock."""
        if timeout_ms <= 0:
            raise ValueError("timeout_ms must be positive")
        if poll_ms <= 0:
            raise ValueError("poll_ms must be positive")
        pattern = re.compile(title_regex) if title_regex is not None else None
        start = self._clock()
        deadline = start + timeout_ms / 1000
        while True:
            window = self._foreground_window()
            if self._matches(window, pattern, class_name, pid):
                return FakeWaitResult(
                    matched=True,
                    waited_ms=int((self._clock() - start) * 1000),
                    window=self.foreground,
                )
            if self._clock() + poll_ms / 1000 > deadline:
                return FakeWaitResult(
                    matched=False,
                    waited_ms=int((self._clock() - start) * 1000),
                    window=self.foreground,
                )
            self._sleep(poll_ms / 1000)

    def observe(self) -> dict[str, object]:
        """A snapshot of the scripted machine state, for oracle callables.

        Fires ``on_observe`` first -- the scripting point for surfaces whose
        facts never stabilize (replication churn and friends).
        """
        if self.on_observe is not None:
            self.on_observe(self)
        return dict(self.state)

    # -- internals -------------------------------------------------------------

    def _foreground_window(self) -> FakeWindow | None:
        if self.foreground is None:
            return None
        return self.windows.get(self.foreground)

    def _foreground_or_raise(self) -> FakeWindow:
        window = self._foreground_window()
        if window is None:
            raise FakeSurfaceError("no foreground window on this desktop")
        return window

    def _window_by_hwnd(self, hwnd: int) -> FakeWindow:
        for window in self.windows.values():
            if window.hwnd == hwnd:
                return window
        raise FakeSurfaceError(f"no window with hwnd {hwnd}")

    def _deliver_text(self, text: str) -> None:
        if not text:
            return
        window = self._foreground_or_raise()
        focused = (
            _find_element_by_name(window.elements, window.focused_element)
            if window.focused_element is not None
            else None
        )
        if focused is not None and focused.on_key is not None:
            focused.on_key(self, text)
        elif window.on_key is not None:
            window.on_key(self, text)
        else:
            self.journal.append("key delivered; no scripted handler consumed it")

    @staticmethod
    def _matches(
        window: FakeWindow | None,
        pattern: re.Pattern[str] | None,
        class_name: str | None,
        pid: int | None,
    ) -> bool:
        if window is None:
            return False
        if pattern is not None and pattern.search(window.title) is None:
            return False
        if class_name is not None and window.class_name != class_name:
            return False
        return pid is None or window.pid == pid


def _find_element_at(elements: Sequence[FakeElement], x: int, y: int) -> FakeElement | None:
    """The deepest element whose rect contains the absolute point.

    Children beat parents; among overlapping siblings the LAST one wins (it
    is the one painted on top), so a button inside a pane is hit correctly.
    """
    best: FakeElement | None = None
    best_depth = -1
    stack: list[tuple[Sequence[FakeElement], int]] = [(elements, 0)]
    while stack:
        nodes, depth = stack.pop()
        for node in nodes:
            if node.rect.contains(x, y) and depth >= best_depth:
                best = node
                best_depth = depth
            stack.append((node.children, depth + 1))
    return best


def _find_element_by_name(elements: Sequence[FakeElement], name: str) -> FakeElement | None:
    for node in elements:
        if node.name == name:
            return node
        found = _find_element_by_name(node.children, name)
        if found is not None:
            return found
    return None
