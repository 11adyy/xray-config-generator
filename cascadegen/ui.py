from __future__ import annotations

import curses
import json
from pathlib import Path
from typing import Callable

from .generator import build, render_routes, write_output
from .deploy import deploy_cascade, remote_sni_check, remove_cascade, test_panels
from .panel import PanelStatus
from .model import DEFAULT_SNI_POOL, Server, Topology, parse_port_pool, parse_routes
from .sni import SNIResult, check_sni, check_sni_pool, render_sni_report, write_sni_report


class UIError(Exception):
    pass


_FANG_ASCII = [('%***                                                    -% ++', '6422555555555555555555555555555555555555555555555555555516522'), ('-----    ---          .+          +++++++               :% ++', '1111155555555555555555725555555555222222255555555555555576522'), ('...:::...:::------:--+------::::::::------::------++    :% +', '777717777711111111111211111111111111111111111111112255551652'), ('+-...::::-:::::::---------------------::::::....:::---+   %+*', '2177777711117771711111111111111111111117777777777771112555622'), (' *+-:..:.......:-----------------:::.........:::....::---% +*', '5421777777777777111111111111111111777777777777777777711116524'), ('% +*%+-.:::::::----------------:....::::::.......:.:----:+ +*', '6522621771117711111111111111111777777777777777777777111172522'), ('% -     +-::::+:.------------:....................:::.:+:* -*', '6515555521777721711111111111117777777777777777777771777272512'), ('% +         +--..:--:--::::-:::-----:::::::......:::----- %-+', '6525555555552117771171117711771121111111777777777777222115612'), ('%%+         ++-:-------:.:* *******++++-::..:.:.:-+**%%+  %-+', '6625555555552217111111117725423333333322117777777233666255612'), (' %       %*+*+:---------:*%    %%*******+---:...+***-++*  %-+', '5655555556222211111111111245555463333333311177772333122455612'), (' %           +:----------+++--:+*+**+++::--:.::.:---:--*  %+*        +.+', '565555555555521111111111123222223333332771177777712271145562255555555272'), (' %           *:----------::----::-----:......:::...:::-*   +*', '5655555555555211111111111715211172222277777777777777711255524'), (' %*          *:----------:.--:.........::::......::.....:---+*%', '562555555555541111111111177117777777777777777777777777777111246'), ('-***         %:----------+:......::::::.....::::::::::::.......:--:--', '142255555555561111111111117777777777777777777777777777777777777711111'), ('::+*         %:----------+++--::::::.....::::::.............::...::--', '712455555555561111111111122211177777777777177777777777777777777777111'), (':::+          -----------:-+++++-.:::::::::::---------++***+-+++', '7772555555555511111111111112222217771111777771111111112222222222'), ('::::+         +:-------------+++-.....::::::-+++++++*+%', '7777255555555521111111111111122217777777111112222222426'), (':::::-        *:---------------+**++--:..:-:+++++++% +*  *-', '77777155555555611111111111111112442211777711222222265225545'), ('::::::-%       +:--------------:-*%  %%**::+*+++++%%*+*   +', '77771716555555521111111111111111126556662172422222664245554'), (':::::::-% %%    +:--------------:++*%%% *..**++**%***%', '777771716566555521111111111111117224666527744222664226'), (':::::::::*%%%%%%%----------------%*+ %%%%+*%*%%%%**%  %%%  ++', '7777777772666666611111111111111116425666622646666446556665522'), ('::::::::::*%%%%%%--------------:+%***+---++*%  %%%%%%%%%%  +* *', '777777777726666661111111111111112624421111226556666666666552254'), (':::::::::::*%***%--------------++*+-.........-+%%%%***%%*  +*%%%%', '77777777777464666111111111111112222177777777712666666666655226666'), ('::::::::::::*****---------------+-..::::::::...:*%%%%****  +*%**%%%%%%**', '777777777771444441111111111111112177777777777777266664444552264666666644'), ('::::::::::::-****+------------::-.::.........::.:%%%%%%**  ++***********', '777777777777144422111111111111771777777777777777766666644552244444446666')]


class App:
    def __init__(self, stdscr: curses.window) -> None:
        self.stdscr = stdscr
        self.topology = Topology(
            servers=[],
            routes=[],
            port_pool=[443, 8443, 2053, 2083, 2087, 2096],
            sni_pool=DEFAULT_SNI_POOL.copy(),
        )
        self.output_dir = Path("cascade-output")
        self.status = "Ready"
        self.sni_results: dict[str, SNIResult] = {}
        self.panel_results: dict[str, PanelStatus] = {}
        curses.curs_set(0)
        try:
            curses.start_color()
            curses.use_default_colors()
            curses.init_pair(1, curses.COLOR_CYAN, -1)
            curses.init_pair(2, curses.COLOR_GREEN, -1)
            curses.init_pair(3, curses.COLOR_YELLOW, -1)
            curses.init_pair(4, curses.COLOR_RED, -1)
            curses.init_pair(5, curses.COLOR_BLUE, -1)
            curses.init_pair(6, curses.COLOR_MAGENTA, -1)
            # Image-derived Fang palette.  Use 256-color approximations when
            # available, with conservative 8-color fallbacks otherwise.
            palette = [
                curses.COLOR_CYAN, curses.COLOR_WHITE, curses.COLOR_YELLOW,
                curses.COLOR_MAGENTA, curses.COLOR_BLUE, curses.COLOR_WHITE, curses.COLOR_WHITE,
            ]
            if getattr(curses, "COLORS", 0) >= 256:
                palette = [159, 250, 202, 93, 33, 244, 231]
            for idx, fg in enumerate(palette, start=10):
                curses.init_pair(idx, fg, -1)
        except curses.error:
            pass

    def run(self) -> None:
        items: list[tuple[str, Callable[[], None]]] = [
            ("Servers", self.edit_servers),
            ("Routes", self.edit_routes),
            ("Port pool (per server)", self.edit_ports),
            ("SNI targets / check", self.edit_sni),
            ("Inter-server XHTTP/TCP", self.toggle_transport),
            ("Inter-server security AUTO/REALITY/SS", self.toggle_inter_protocol),
            ("Dual entry XHTTP+TCP", self.toggle_dual_entry),
            ("Profile modern/legacy", self.toggle_profile),
            ("Test panel connections", self.test_panel_connections),
            ("Remote SNI check (panels)", self.remote_sni_check),
            ("Preview topology", self.preview),
            ("Generate JSON", self.generate),
            ("Deploy cascade to 3x-ui", self.deploy),
            ("Remove cascade from 3x-ui", self.remove_deployed),
            ("Save topology", self.save_topology),
            ("Load topology", self.load_topology),
            ("Quit", self.quit),
        ]
        idx = 0
        while True:
            self.draw_frame("Xray Cascade Generator")
            h, w = self.stdscr.getmaxyx()
            left_w = min(34, max(26, w // 3))
            self._safe_add(2, 3, "ACTIONS", curses.A_BOLD | curses.color_pair(1))
            for i, (label, _) in enumerate(items):
                attr = curses.A_REVERSE if i == idx else curses.A_NORMAL
                marker = ">" if i == idx else " "
                self._safe_add(4 + i, 3, f"{marker} {label}"[: left_w - 4], attr)

            sep_x = left_w + 1
            for y in range(2, max(2, h - 3)):
                self._safe_add(y, sep_x, "|", curses.color_pair(5))

            # On wide terminals reserve a deliberately large right-hand pane
            # for the image-derived colored Fang ASCII portrait and slogan.
            if w >= 138:
                art_w = min(78, max(54, w - sep_x - 34))
                art_x = max(sep_x + 27, w - art_w - 2)
                art_sep = art_x - 2
                for yy in range(2, max(2, h - 3)):
                    self._safe_add(yy, art_sep, "|", curses.color_pair(5))
                topo_width = max(20, art_sep - (sep_x + 3) - 2)
                self._draw_topology_summary(3, sep_x + 3, topo_width, h - 6)
                self._draw_fang_art(2, art_x, art_w, h - 5)
            else:
                self._draw_topology_summary(3, sep_x + 3, max(20, w - sep_x - 5), h - 6)
            self.draw_status("Up/Down move  Enter open  q quit")
            ch = self.stdscr.getch()
            if ch in (curses.KEY_UP, ord("k")):
                idx = (idx - 1) % len(items)
            elif ch in (curses.KEY_DOWN, ord("j")):
                idx = (idx + 1) % len(items)
            elif ch in (10, 13, curses.KEY_ENTER):
                try:
                    items[idx][1]()
                except UIError as exc:
                    self.status = str(exc)
                except (ValueError, OSError) as exc:
                    self.status = str(exc)
            elif ch in (ord("q"), 27):
                return

    def draw_frame(self, title: str) -> None:
        self.stdscr.erase()
        h, w = self.stdscr.getmaxyx()
        if h < 18 or w < 88:
            self._safe_add(0, 0, "Terminal too small; recommended >= 88x18", curses.color_pair(4))
            return
        top = f"+- {title} " + "-" * max(1, w - len(title) - 7) + "+"
        self._safe_add(0, 1, top[: max(1, w - 2)], curses.A_BOLD)

    def draw_status(self, help_text: str = "") -> None:
        h, w = self.stdscr.getmaxyx()
        self._safe_add(h - 3, 1, "-" * max(1, w - 2), curses.color_pair(1))
        self._safe_add(h - 2, 2, self.status[: max(1, w - 4)], curses.color_pair(3))
        self._safe_add(h - 1, 2, help_text[: max(1, w - 4)])
        self.stdscr.refresh()

    def _safe_add(self, y: int, x: int, text: str, attr: int = 0) -> None:
        try:
            self.stdscr.addstr(y, x, text, attr)
        except curses.error:
            pass

    def _draw_topology_summary(self, y: int, x: int, width: int, height: int) -> None:
        self._safe_add(y, x, "TOPOLOGY", curses.A_BOLD | curses.color_pair(1))
        y += 2
        if not self.topology.servers:
            self._safe_add(y, x, "No servers yet", curses.color_pair(3))
            y += 2
        else:
            self._safe_add(y, x, "Servers:", curses.A_BOLD)
            y += 1
            for s in self.topology.servers[: max(1, height // 3)]:
                pst = self.panel_results.get(s.name)
                ptxt = "OK" if pst and pst.ok else "ERR" if pst else "?"
                self._safe_add(y, x + 2, f"[{s.name}] {s.ip} panel={ptxt}/{s.auth_mode}"[:width])
                y += 1
        y += 1
        self._safe_add(y, x, "Routes:", curses.A_BOLD)
        y += 1
        if not self.topology.routes:
            self._safe_add(y, x + 2, "(none)")
            y += 1
        else:
            for i, route in enumerate(self.topology.routes, 1):
                if y >= self.stdscr.getmaxyx()[0] - 8:
                    break
                self._safe_add(y, x + 2, f"{i}. " + " -> ".join(route) + " -> Internet"[:width])
                y += 1
        y += 1
        if y < self.stdscr.getmaxyx()[0] - 7:
            checked = [self.sni_results.get(h) for h in self.topology.sni_pool]
            good = sum(1 for r in checked if r and r.suitable)
            entry_mode = "dual XHTTP+TCP" if self.topology.dual_entry else f"single {self.topology.transport}"
            self._safe_add(y, x, f"Ports/server: {len(self.topology.port_pool)}   hops={self.topology.transport}/{self.topology.inter_server_protocol} entry={entry_mode}")
            y += 1
            self._safe_add(y, x, f"SNI: {len(self.topology.sni_pool)} candidates, {good} checked PASS")
            y += 1
            self._safe_add(y, x, f"Output: {self.output_dir}"[:width])


    @staticmethod
    def _block_text(text: str) -> list[str]:
        font = {
            "F": ["#####", "#....", "#....", "####.", "#....", "#....", "#...."],
            "U": ["#...#", "#...#", "#...#", "#...#", "#...#", "#...#", ".###."],
            "C": [".####", "#....", "#....", "#....", "#....", "#....", ".####"],
            "K": ["#...#", "#..#.", "#.#..", "##...", "#.#..", "#..#.", "#...#"],
            "Y": ["#...#", "#...#", ".#.#.", "..#..", "..#..", "..#..", "..#.."],
            "O": [".###.", "#...#", "#...#", "#...#", "#...#", "#...#", ".###."],
            "П": ["#####", "#...#", "#...#", "#...#", "#...#", "#...#", "#...#"],
            "Ы": ["#...#", "#...#", "##..#", "#.#.#", "#..##", "#...#", "#...#"],
            "Н": ["#...#", "#...#", "#...#", "#####", "#...#", "#...#", "#...#"],
            "Я": [".####", "#...#", "#...#", ".####", "..#.#", ".#..#", "#...#"],
            "!": ["..#..", "..#..", "..#..", "..#..", "..#..", ".....", "..#.."],
            " ": ["....."] * 7,
        }
        rows = [""] * 7
        for ch in text:
            glyph = font.get(ch, font[" "])
            for i in range(7):
                rows[i] += glyph[i].replace(".", " ") + " "
        return [row.rstrip() for row in rows]

    def _draw_colored_ascii(self, y: int, x: int, text: str, cmap: str, width: int) -> None:
        if not text or width <= 0:
            return
        if len(text) > width:
            # Nearest-neighbour horizontal resampling keeps the actual image
            # conversion recognizable instead of bluntly cropping the snout.
            idxs = [min(len(text) - 1, int(i * len(text) / width)) for i in range(width)]
            text = "".join(text[i] for i in idxs)
            cmap = "".join(cmap[i] if i < len(cmap) else "2" for i in idxs)
        pos = 0
        while pos < len(text):
            cid = cmap[pos] if pos < len(cmap) else "2"
            end = pos + 1
            while end < len(text) and (cmap[end] if end < len(cmap) else "2") == cid:
                end += 1
            pair = 0 if cid == "0" else 9 + int(cid)
            self._safe_add(y, x + pos, text[pos:end], curses.color_pair(pair) if pair else 0)
            pos = end

    def _draw_fang_art(self, y: int, x: int, width: int, height: int) -> None:
        """Colored ASCII conversion of the exact user-supplied Fang image."""
        if height < 18 or width < 36:
            return
        # Leave enough vertical room for the requested two-line block slogan.
        slogan_rows = 15
        room_for_art = max(10, height - slogan_rows - 1)
        source = _FANG_ASCII
        if room_for_art < len(source):
            row_idxs = [min(len(source) - 1, int(i * len(source) / room_for_art)) for i in range(room_for_art)]
            source = [source[i] for i in row_idxs]
        for i, (line, cmap) in enumerate(source):
            if y + i >= self.stdscr.getmaxyx()[0] - 3:
                return
            self._draw_colored_ascii(y + i, x, line, cmap, width)

        sy = y + len(source) + 1
        for block_no, phrase in enumerate(("FUCK YOU", "ПЫНЯ!")):
            rows = self._block_text(phrase)
            # Fit long Latin line into the art pane if needed.
            for ri, row in enumerate(rows):
                if sy + ri >= self.stdscr.getmaxyx()[0] - 3:
                    return
                if len(row) > width:
                    idxs = [min(len(row) - 1, int(i * len(row) / width)) for i in range(width)]
                    row = "".join(row[i] for i in idxs)
                attr = curses.A_BOLD | curses.color_pair(4 if block_no == 0 else 3)
                self._safe_add(sy + ri, x, row[:width], attr)
            sy += 8

    def prompt(self, title: str, initial: str = "") -> str:
        self.stdscr.erase()
        h, w = self.stdscr.getmaxyx()
        self._safe_add(1, 2, title, curses.A_BOLD)
        self._safe_add(3, 2, "> ")
        self._safe_add(3, 4, initial)
        self._safe_add(h - 2, 2, "Enter accept   Ctrl-G cancel   Backspace edits")
        curses.curs_set(1)
        curses.noecho()
        buf = list(initial)
        pos = len(buf)
        try:
            while True:
                visible_w = max(8, w - 8)
                start = max(0, pos - visible_w + 1)
                visible = "".join(buf[start : start + visible_w])
                self._safe_add(3, 4, " " * visible_w)
                self._safe_add(3, 4, visible)
                try:
                    self.stdscr.move(3, 4 + pos - start)
                except curses.error:
                    pass
                self.stdscr.refresh()
                ch = self.stdscr.get_wch()
                if ch in ("\n", "\r"):
                    return "".join(buf).strip()
                if ch == "\x07":
                    raise UIError("Cancelled")
                if ch in (curses.KEY_BACKSPACE, "\b", "\x7f"):
                    if pos > 0:
                        del buf[pos - 1]
                        pos -= 1
                elif ch == curses.KEY_DC:
                    if pos < len(buf):
                        del buf[pos]
                elif ch == curses.KEY_LEFT:
                    pos = max(0, pos - 1)
                elif ch == curses.KEY_RIGHT:
                    pos = min(len(buf), pos + 1)
                elif ch == curses.KEY_HOME:
                    pos = 0
                elif ch == curses.KEY_END:
                    pos = len(buf)
                elif isinstance(ch, str) and ch.isprintable():
                    buf.insert(pos, ch)
                    pos += 1
        finally:
            curses.curs_set(0)

    def prompt_secret(self, title: str, initial: str = "") -> str:
        self.stdscr.erase()
        h, w = self.stdscr.getmaxyx()
        self._safe_add(1, 2, title, curses.A_BOLD)
        self._safe_add(3, 2, "> ")
        self._safe_add(h - 2, 2, "Enter accept   Ctrl-G cancel   input is masked")
        curses.curs_set(1)
        curses.noecho()
        buf = list(initial)
        try:
            while True:
                visible_w = max(8, w - 8)
                shown = "*" * min(len(buf), visible_w)
                self._safe_add(3, 4, " " * visible_w)
                self._safe_add(3, 4, shown)
                try:
                    self.stdscr.move(3, 4 + min(len(buf), visible_w - 1))
                except curses.error:
                    pass
                self.stdscr.refresh()
                ch = self.stdscr.get_wch()
                if ch in ("\n", "\r"):
                    return "".join(buf)
                if ch == "\x07":
                    raise UIError("Cancelled")
                if ch in (curses.KEY_BACKSPACE, "\b", "\x7f"):
                    if buf:
                        buf.pop()
                elif isinstance(ch, str) and ch.isprintable():
                    buf.append(ch)
        finally:
            curses.curs_set(0)

    def _edit_server_fields(self, old: Server | None = None) -> Server:
        name = self.prompt("Server name", old.name if old else "")
        ip = self.prompt("Server IP", old.ip if old else "")
        panel_url = self.prompt(
            "3x-ui panel base URL (include secret web path if configured; blank = JSON only)",
            old.panel_url if old else "",
        )
        auth_mode = self.prompt("Auth mode: auto | token | legacy", old.auth_mode if old else "auto").lower() or "auto"
        api_token = old.api_token if old else ""
        username = old.username if old else ""
        password = old.password if old else ""
        two_factor_code = old.two_factor_code if old else ""
        if panel_url and auth_mode in {"auto", "token"}:
            api_token = self.prompt_secret("API token (blank is OK in auto mode)", api_token)
        if panel_url and auth_mode in {"auto", "legacy"}:
            username = self.prompt("Panel username (blank is OK in auto mode)", username)
            if username:
                password = self.prompt_secret("Panel password", password)
                two_factor_code = self.prompt_secret("2FA code (normally blank; use current code only when needed)", "")
        verify_text = self.prompt("Verify panel TLS certificate? yes/no", "yes" if old and old.verify_tls else "no").lower()
        server = Server(
            name=name,
            ip=ip,
            panel_url=panel_url,
            auth_mode=auth_mode,
            api_token=api_token,
            username=username,
            password=password,
            two_factor_code=two_factor_code,
            verify_tls=verify_text in {"y", "yes", "1", "true"},
        )
        server.validate()
        return server

    def edit_servers(self) -> None:
        idx = 0
        while True:
            self.draw_frame("Servers / 3x-ui access")
            self._safe_add(2, 2, f"{'#':<3} {'NAME':<14} {'IP':<16} {'AUTH':<8} {'PANEL':<8} URL", curses.A_BOLD)
            self._safe_add(3, 2, "-" * 84)
            rows = self.topology.servers
            if rows:
                idx = min(idx, len(rows) - 1)
            h, _ = self.stdscr.getmaxyx()
            max_rows = max(1, h - 8)
            start_row = max(0, min(idx - max_rows + 1, max(0, len(rows) - max_rows)))
            for vi, server in enumerate(rows[start_row:start_row + max_rows]):
                i = start_row + vi
                result = self.panel_results.get(server.name)
                state = "OK" if result and result.ok else "FAIL" if result else "?"
                attr = curses.A_REVERSE if i == idx else (curses.color_pair(2) if state == "OK" else curses.color_pair(4) if state == "FAIL" else 0)
                self._safe_add(4 + vi, 2, f"{i+1:<3} {server.name:<14} {server.ip:<16} {server.auth_mode:<8} {state:<8} {server.panel_url}"[:120], attr)
            self.draw_status("a add  e/Enter edit  t test selected  T test all  d delete  q back")
            ch = self.stdscr.getch()
            if ch in (ord("q"), 27):
                return
            if ch in (curses.KEY_UP, ord("k")) and rows:
                idx = (idx - 1) % len(rows)
            elif ch in (curses.KEY_DOWN, ord("j")) and rows:
                idx = (idx + 1) % len(rows)
            elif ch == ord("a"):
                server = self._edit_server_fields()
                if server.name in {x.name for x in rows}:
                    raise UIError(f"Duplicate server: {server.name}")
                rows.append(server)
                idx = len(rows) - 1
                self.status = f"Added {server.name}"
            elif ch in (ord("e"), 10, 13) and rows:
                old = rows[idx]
                server = self._edit_server_fields(old)
                if server.name != old.name and server.name in {x.name for x in rows}:
                    raise UIError(f"Duplicate server: {server.name}")
                old_name = old.name
                rows[idx] = server
                self.panel_results.pop(old_name, None)
                if old_name != server.name:
                    self.topology.routes = [[server.name if n == old_name else n for n in r] for r in self.topology.routes]
                self.status = f"Updated {server.name}"
            elif ch == ord("t") and rows:
                self._test_one_panel(rows[idx])
            elif ch == ord("T"):
                self.test_panel_connections()
            elif ch == ord("d") and rows:
                removed = rows.pop(idx)
                self.panel_results.pop(removed.name, None)
                self.topology.routes = [r for r in self.topology.routes if removed.name not in r]
                idx = max(0, idx - 1)
                self.status = f"Deleted {removed.name}; routes using it were removed"

    def _test_one_panel(self, server: Server) -> None:
        self.status = f"Testing {server.name}..."
        statuses = test_panels(Topology(
            servers=[server], routes=[[server.name]], port_pool=self.topology.port_pool,
            sni_pool=self.topology.sni_pool, profile=self.topology.profile,
            transport=self.topology.transport, inter_server_protocol=self.topology.inter_server_protocol, xhttp_mode=self.topology.xhttp_mode,
            xhttp_padding=self.topology.xhttp_padding, cascade_id=self.topology.cascade_id,
            fingerprint=self.topology.fingerprint,
        ))
        result = statuses[0]
        self.panel_results[server.name] = result
        if result.ok:
            self.status = f"{server.name}: OK auth={result.auth} api={result.api_style} xray={result.xray_state or '?'} {result.xray_version}"
        else:
            self.status = f"{server.name}: FAIL {result.message}"

    def edit_routes(self) -> None:
        idx = 0
        while True:
            self.draw_frame("Routes")
            self._safe_add(2, 3, "Each route is ordered left -> right; last server exits directly.", curses.color_pair(1))
            rows = self.topology.routes
            if rows:
                idx = min(idx, len(rows) - 1)
            for i, route in enumerate(rows):
                attr = curses.A_REVERSE if i == idx else 0
                self._safe_add(4 + i, 3, f"{i+1:>2}. " + " -> ".join(route) + " -> Internet", attr)
            self.draw_status("a add  e/Enter edit  d delete  Up/Down select  q back")
            ch = self.stdscr.getch()
            if ch in (ord("q"), 27):
                return
            if ch in (curses.KEY_UP, ord("k")) and rows:
                idx = (idx - 1) % len(rows)
            elif ch in (curses.KEY_DOWN, ord("j")) and rows:
                idx = (idx + 1) % len(rows)
            elif ch == ord("a"):
                text = self.prompt("Route, e.g. entry>middle>exit")
                route = parse_routes(text)[0]
                self._validate_route(route)
                rows.append(route)
                idx = len(rows) - 1
                self.status = "Route added"
            elif ch in (ord("e"), 10, 13) and rows:
                text = self.prompt("Route", ">".join(rows[idx]))
                route = parse_routes(text)[0]
                self._validate_route(route)
                rows[idx] = route
                self.status = "Route updated"
            elif ch == ord("d") and rows:
                rows.pop(idx)
                idx = max(0, idx - 1)
                self.status = "Route deleted"

    def _validate_route(self, route: list[str]) -> None:
        known = {s.name for s in self.topology.servers}
        unknown = [n for n in route if n not in known]
        if unknown:
            raise UIError("Unknown server(s): " + ", ".join(unknown))
        if len(set(route)) != len(route):
            raise UIError("Route contains a repeated server")

    def edit_ports(self) -> None:
        initial = ",".join(map(str, self.topology.port_pool))
        text = self.prompt("Port pool: 443,8443,20000-20010", initial)
        self.topology.port_pool = parse_port_pool(text)
        self.status = f"Per-server port pool: {len(self.topology.port_pool)} ports"

    def edit_sni(self) -> None:
        idx = 0
        while True:
            self.draw_frame("SNI targets")
            self._safe_add(2, 2, f"{'STATUS':<7} {'HOST':<31} {'IP':<20} {'TLS':<9} {'ALPN':<6} {'MS':>7}", curses.A_BOLD)
            self._safe_add(3, 2, "-" * 84)
            hosts = self.topology.sni_pool
            if hosts:
                idx = min(idx, len(hosts) - 1)
            h, _ = self.stdscr.getmaxyx()
            max_rows = max(1, h - 8)
            start = max(0, min(idx - max_rows + 1, max(0, len(hosts) - max_rows)))
            for visual_i, host in enumerate(hosts[start : start + max_rows]):
                i = start + visual_i
                r = self.sni_results.get(host)
                if r is None:
                    status, ip, tls, alpn, ms = "?", "", "", "", ""
                    color = curses.color_pair(3)
                elif r.suitable:
                    status, ip, tls, alpn = "PASS", r.ip, r.tls_version, r.alpn
                    ms = "" if r.latency_ms is None else f"{r.latency_ms:.1f}"
                    color = curses.color_pair(2)
                else:
                    status, ip, tls, alpn = "FAIL", r.ip, r.tls_version, r.alpn
                    ms = "" if r.latency_ms is None else f"{r.latency_ms:.1f}"
                    color = curses.color_pair(4)
                attr = curses.A_REVERSE if i == idx else color
                self._safe_add(4 + visual_i, 2, f"{status:<7} {host:<31} {ip[:20]:<20} {tls:<9} {alpn:<6} {ms:>7}", attr)
            self.draw_status("F5/c check all  Enter check one  a add  e edit  d delete  i details  q back")
            ch = self.stdscr.getch()
            if ch in (ord("q"), 27):
                return
            if ch in (curses.KEY_UP, ord("k")) and hosts:
                idx = (idx - 1) % len(hosts)
            elif ch in (curses.KEY_DOWN, ord("j")) and hosts:
                idx = (idx + 1) % len(hosts)
            elif ch == ord("a"):
                host = self.prompt("SNI hostname")
                self._add_sni(host)
                idx = len(hosts) - 1
            elif ch == ord("e") and hosts:
                old = hosts[idx]
                new = self.prompt("SNI hostname", old)
                from .model import HOST_RE
                if not HOST_RE.fullmatch(new):
                    raise UIError(f"Invalid hostname: {new}")
                hosts[idx] = new
                self.sni_results.pop(old, None)
                self.sni_results.pop(new, None)
            elif ch == ord("d") and hosts:
                old = hosts.pop(idx)
                self.sni_results.pop(old, None)
                idx = max(0, idx - 1)
            elif ch in (10, 13) and hosts:
                self.status = f"Checking {hosts[idx]}..."
                self.draw_status("Checking locally via DNS/TCP/TLS 1.3/ALPN...")
                r = check_sni(hosts[idx])
                self.sni_results[r.host] = r
                self.status = self._sni_status_text(r)
            elif ch in (curses.KEY_F5, ord("c")) and hosts:
                self._check_all_sni()
            elif ch == ord("i") and hosts:
                r = self.sni_results.get(hosts[idx])
                if r:
                    self.show_text("SNI details", render_sni_report([r]))
                else:
                    self.status = "Not checked yet"

    def _add_sni(self, host: str) -> None:
        from .model import HOST_RE
        if not HOST_RE.fullmatch(host):
            raise UIError(f"Invalid hostname: {host}")
        if host not in self.topology.sni_pool:
            self.topology.sni_pool.append(host)
        self.sni_results.pop(host, None)
        self.status = f"Added {host}"

    def _check_all_sni(self) -> list[SNIResult]:
        if not self.topology.sni_pool:
            raise UIError("SNI pool is empty")
        self.status = f"Checking {len(self.topology.sni_pool)} SNI targets..."
        self.draw_status("Concurrent local checks: DNS + TCP/443 + certificate/SNI + TLS 1.3 + h2")
        results = check_sni_pool(self.topology.sni_pool)
        self.sni_results.update({r.host: r for r in results})
        good = sum(r.suitable for r in results)
        self.status = f"SNI check complete: {good}/{len(results)} suitable"
        return results

    @staticmethod
    def _sni_status_text(r: SNIResult) -> str:
        if r.suitable:
            return f"PASS {r.host}: {r.ip}, {r.tls_version}, {r.alpn}, {r.latency_ms} ms"
        return f"FAIL {r.host}: {r.error or 'not suitable'}"

    def toggle_transport(self) -> None:
        self.topology.transport = "tcp" if self.topology.transport == "xhttp" else "xhttp"
        self.topology.transport_locked = True
        self.status = f"Inter-server transport: {self.topology.transport} (explicit)"

    def toggle_inter_protocol(self) -> None:
        order = ["auto", "reality", "shadowsocks"]
        current = self.topology.inter_server_protocol if self.topology.inter_server_protocol in order else "auto"
        self.topology.inter_server_protocol = order[(order.index(current) + 1) % len(order)]
        self.status = f"Inter-server security: {self.topology.inter_server_protocol}"

    def toggle_dual_entry(self) -> None:
        self.topology.dual_entry = not self.topology.dual_entry
        self.status = f"Dual entry: {'ON (XHTTP+TCP)' if self.topology.dual_entry else 'OFF'}"

    def toggle_profile(self) -> None:
        self.topology.profile = "legacy" if self.topology.profile == "modern" else "modern"
        self.status = f"Profile: {self.topology.profile}"

    def test_panel_connections(self) -> None:
        if not self.topology.servers:
            raise UIError("No servers")
        self.status = "Testing panel connections..."
        results = test_panels(self.topology)
        self.panel_results.update({r.server: r for r in results})
        lines = ["3X-UI CONNECTION CHECK", "=" * 88]
        for r in results:
            if r.ok:
                lines.append(f"PASS  {r.server:<16} auth={r.auth:<6} api={r.api_style:<6} xray={r.xray_state or '?'} {r.xray_version}  {r.message}")
            else:
                lines.append(f"FAIL  {r.server:<16} {r.message}")
        good = sum(r.ok for r in results)
        self.status = f"Panels: {good}/{len(results)} connected"
        self.show_text("Panel connections", "\n".join(lines))

    def remote_sni_check(self) -> None:
        missing = [s.name for s in self.topology.servers if not s.has_panel_credentials()]
        if missing:
            raise UIError("Panel credentials missing: " + ", ".join(missing))
        self.status = "Running REALITY SNI checks from panel servers..."
        self.draw_status("New panels use scanRealityTarget; old panels are marked fallback/unsupported")
        try:
            selected, report = remote_sni_check(self.topology)
        except Exception as exc:
            raise UIError(f"Remote SNI check failed: {exc}") from exc
        lines = ["REMOTE REALITY SNI CHECK", "=" * 72]
        for server in self.topology.servers:
            row = report.get("servers", {}).get(server.name, {})
            supported = bool(row.get("scanner_supported"))
            lines.append(f"{server.name}: scanner={'yes' if supported else 'no (legacy/fallback)'}")
            if supported:
                for host in self.topology.sni_pool:
                    detail = row.get("targets", {}).get(host, {})
                    if not detail.get("available"):
                        lines.append(f"  ?    {host}: unavailable")
                        continue
                    ok = detail.get("feasible") is True
                    tls = detail.get("tlsVersion") or ("TLS1.3" if detail.get("tls13") else "-")
                    alpn = detail.get("alpn") or ("h2" if detail.get("h2") else "-")
                    reason = detail.get("reason") or ""
                    lines.append(f"  {'PASS' if ok else 'FAIL'} {host}: tls={tls}, alpn={alpn} {reason}")
        lines += ["", "Selected pool: " + (", ".join(selected) if selected else "<none>")]
        self.status = f"Remote SNI: {len(selected)}/{len(self.topology.sni_pool)} usable across scanner-capable panels"
        self.show_text("Remote SNI check", "\n".join(lines))

    def _effective_topology(self, require_sni_check: bool = True) -> tuple[Topology, list[SNIResult]]:
        self.topology.validate()
        results: list[SNIResult] = []
        if require_sni_check:
            missing = [h for h in self.topology.sni_pool if h not in self.sni_results]
            if missing:
                results = self._check_all_sni()
            else:
                results = [self.sni_results[h] for h in self.topology.sni_pool]
            good_hosts = [r.host for r in results if r.suitable]
            if not good_hosts:
                raise UIError("No suitable SNI target. Open 'SNI targets / check' and add another host.")
            data = self.topology.to_dict()
            data["sni_pool"] = good_hosts
            return Topology.from_dict(data), results
        return self.topology, results

    def preview(self) -> None:
        topo, _ = self._effective_topology(require_sni_check=False)
        _, manifest, _ = build(topo)
        self.show_text("Preview", render_routes(manifest))

    def generate(self) -> None:
        topo, results = self._effective_topology(require_sni_check=True)
        out = self.prompt("Output directory", str(self.output_dir))
        self.output_dir = Path(out or "cascade-output")
        manifest = write_output(topo, self.output_dir)
        write_sni_report(results, self.output_dir / "SNI_CHECKS.json")
        (self.output_dir / "SNI_CHECKS.txt").write_text(render_sni_report(results), encoding="utf-8")
        self.status = f"Generated {len(manifest['servers'])} configs; only checked PASS SNI targets were used"
        self.show_text("Generated", render_routes(manifest) + "\n" + render_sni_report(results))

    def deploy(self) -> None:
        topo, results = self._effective_topology(require_sni_check=True)
        missing = [s.name for s in topo.servers if not s.has_panel_credentials()]
        if missing:
            raise UIError("Panel credentials missing: " + ", ".join(missing))
        out = self.prompt("Deployment/output directory", str(self.output_dir))
        self.output_dir = Path(out or "cascade-output")
        self.status = "Deploying cascade through 3x-ui API..."
        try:
            result = deploy_cascade(topo, self.output_dir)
        except Exception as exc:
            raise UIError(f"Deploy failed (rollback attempted): {exc}") from exc
        write_sni_report(results, self.output_dir / "SNI_CHECKS.json")
        (self.output_dir / "SNI_CHECKS.txt").write_text(render_sni_report(results), encoding="utf-8")
        lines = [render_routes(result.manifest), "DEPLOY", "=" * 72]
        if result.remote_sni_pool:
            lines.append("Remote SNI pool: " + ", ".join(result.remote_sni_pool))
        for r in result.servers:
            verified = "runtime OK" if r.runtime_verified else "API OK (old panel: runtime endpoint unavailable)"
            lines.append(f"{r.server}: auth={r.auth}, api={r.api_style}, inbounds={r.created_inbounds}, {verified}")
        self.status = f"Cascade {topo.cascade_id} deployed to {len(result.servers)} server(s)"
        self.show_text("Deploy complete", "\n".join(lines))

    def remove_deployed(self) -> None:
        expected = self.topology.cascade_id
        typed = self.prompt(f"Type cascade id '{expected}' to remove only this cascade")
        if typed != expected:
            raise UIError("Removal cancelled: cascade id did not match")
        try:
            messages = remove_cascade(self.topology)
        except Exception as exc:
            raise UIError(f"Remove failed: {exc}") from exc
        self.status = f"Cascade {expected} removed"
        self.show_text("Remove cascade", "\n".join(messages))

    def save_topology(self) -> None:
        path = Path(self.prompt("Save topology JSON", "topology.json"))
        path.write_text(json.dumps(self.topology.to_dict(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        try:
            path.chmod(0o600)
        except OSError:
            pass
        self.status = f"Saved {path} (contains panel credentials; chmod 600)"

    def load_topology(self) -> None:
        path = Path(self.prompt("Load topology JSON", "topology.json"))
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            self.topology = Topology.from_dict(data)
            self.sni_results.clear()
        except Exception as exc:
            raise UIError(f"Load failed: {exc}") from exc
        self.status = f"Loaded {path}"

    def show_text(self, title: str, text: str) -> None:
        lines = text.splitlines()
        offset = 0
        while True:
            self.stdscr.erase()
            h, w = self.stdscr.getmaxyx()
            self._safe_add(0, 2, title, curses.A_BOLD)
            view_h = max(1, h - 3)
            for i, line in enumerate(lines[offset : offset + view_h]):
                self._safe_add(1 + i, 1, line[: max(1, w - 2)])
            self._safe_add(h - 1, 1, "Up/Down scroll  PgUp/PgDn  q/Esc back", curses.color_pair(3))
            self.stdscr.refresh()
            ch = self.stdscr.getch()
            if ch in (ord("q"), 27, 10, 13):
                return
            if ch in (curses.KEY_DOWN, ord("j")):
                offset = min(max(0, len(lines) - view_h), offset + 1)
            elif ch in (curses.KEY_UP, ord("k")):
                offset = max(0, offset - 1)
            elif ch == curses.KEY_NPAGE:
                offset = min(max(0, len(lines) - view_h), offset + view_h)
            elif ch == curses.KEY_PPAGE:
                offset = max(0, offset - view_h)

    def quit(self) -> None:
        raise SystemExit(0)


def run_ui() -> None:
    curses.wrapper(lambda stdscr: App(stdscr).run())
