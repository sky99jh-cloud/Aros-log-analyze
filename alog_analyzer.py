"""
Cimon ALog Analyzer
- ALog 바이너리 파일에서 텍스트 추출
- ETV 동작 주기 분석
- 인터넷 연결 불필요 (표준 라이브러리 + tkinter 전용)
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import struct
import re
import datetime
import os
import threading


# ─────────────────────────────────────────
#  파싱 로직
# ─────────────────────────────────────────

def unix_to_kst(ts):
    if 1700000000 < ts < 1900000000:
        utc = datetime.datetime(1970, 1, 1) + datetime.timedelta(seconds=ts)
        return utc + datetime.timedelta(hours=9)
    return None


def parse_alog(filepath):
    with open(filepath, "rb") as f:
        data = f.read()

    # 타임스탬프 위치 수집 (중복 제거)
    ts_positions = []
    prev_val = None
    for i in range(0, len(data) - 4, 1):
        val = struct.unpack_from("<I", data, i)[0]
        dt = unix_to_kst(val)
        if dt and val != prev_val:
            ts_positions.append((i, dt, val))
            prev_val = val

    # 레코드 빌드
    records = []
    for idx, (pos, dt, val) in enumerate(ts_positions):
        end = ts_positions[idx + 1][0] if idx + 1 < len(ts_positions) else len(data)
        chunk = data[pos:end]
        records.append((dt, chunk))

    return records


def extract_text_records(records):
    """바이너리 레코드에서 텍스트 추출 → 리스트 반환"""
    rows = []
    for dt, chunk in records:
        text = chunk.decode("cp949", errors="replace")
        parts = re.findall(r"[\x20-\x7e가-힣ㄱ-ㅎㅏ-ㅣ_\-./()]+", text)
        clean = []
        for p in parts:
            p = p.strip()
            if len(p) < 2:
                continue
            if re.fullmatch(r"[0-9A-Fa-f\s]+", p):
                continue
            p = re.sub(r"[\x00-\x1f\x7f]", "", p)
            if len(p) >= 2:
                clean.append(p)

        combined = " ".join(clean)
        if "경보" in combined and "복귀" in combined:
            etype = "복귀"
        elif "경보" in combined:
            etype = "경보발생"
        elif "동작" in combined:
            etype = "동작"
        elif "복귀" in combined:
            etype = "복귀"
        elif "시각변경" in combined or "FLAG" in combined:
            etype = "시각변경"
        else:
            etype = "정보"

        device = ""
        for p in clean:
            if re.search(r"팔공\.", p):
                device = re.sub(r'".*', "", p)[:30]
                break

        desc = ""
        kws = ["경보", "동작", "복귀", "TEMP", "WATER", "AIR", "FLAG", "TX-", "ETV"]
        for p in clean:
            if any(k in p for k in kws) and p != device:
                desc = p[:60]
                break
        if not desc and clean:
            others = [p for p in clean if p != device and "팔공" not in p]
            desc = " / ".join(others[:2])[:60]

        rows.append({
            "dt": dt,
            "etype": etype,
            "device": device,
            "desc": desc,
            "raw": combined[:120],
        })
    return rows


def find_dh_devices(records):
    """D/H_ 로 시작하는 고유 장치명 목록 반환"""
    devices = set()
    for _, chunk in records:
        text = chunk.decode("cp949", errors="replace")
        devices.update(re.findall(r'D/H_\w+', text))
    return sorted(devices)


def extract_etv_events(records):
    """ETV 동작 이벤트만 추출"""
    events = []
    for dt, chunk in records:
        text = chunk.decode("cp949", errors="replace")
        if "ETV" in text and "동작" in text:
            events.append(dt)
    return sorted(events)


def calc_cycles(etv_events):
    """이벤트 쌍으로 동작/대기/주기 계산"""
    if len(etv_events) < 2:
        return []
    pairs = [(etv_events[i], etv_events[i + 1]) for i in range(0, len(etv_events) - 1, 2)]
    results = []
    for idx, (start, end) in enumerate(pairs):
        dur = (end - start).total_seconds()
        if idx + 1 < len(pairs):
            next_start = pairs[idx + 1][0]
            cycle = (next_start - start).total_seconds()
            wait = (next_start - end).total_seconds()
        else:
            cycle = None
            wait = None
        results.append({
            "no": idx + 1,
            "start": start,
            "end": end,
            "duration": dur,
            "wait": wait,
            "cycle": cycle,
        })
    return results


def save_text_file(filepath, rows):
    lines = []
    lines.append("=== Cimon Alarm Log 추출 결과 ===")
    lines.append(f"추출 시각: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} KST")
    lines.append(f"총 레코드 수: {len(rows)}건")
    lines.append("=" * 90)
    lines.append(f"{'시각(KST)':<21} {'유형':<10} {'장치':<30} {'내용'}")
    lines.append("-" * 90)
    for r in rows:
        lines.append(
            f"{r['dt'].strftime('%Y-%m-%d %H:%M:%S')}  [{r['etype']:<6}]  {r['device']:<30}  {r['desc']}"
        )
    lines.append("")
    lines.append("* Cimon for Windows (KDT) .ALog 바이너리에서 텍스트를 추출한 결과입니다.")
    with open(filepath, "w", encoding="utf-8-sig") as f:
        f.write("\n".join(lines))


# ─────────────────────────────────────────
#  UI
# ─────────────────────────────────────────

DARK_BG      = "#1A1C1E"
PANEL_BG     = "#22252A"
CARD_BG      = "#2A2E35"
ACCENT       = "#4A9EFF"
ACCENT2      = "#3DDC97"
WARN         = "#FF6B6B"
TEXT_PRI     = "#E8EAF0"
TEXT_SEC     = "#8B909E"
TEXT_MUTED   = "#565B66"
BORDER       = "#333840"
ROW_EVEN     = "#22252A"
ROW_ODD      = "#1E2126"
ROW_SEL      = "#1E3A5F"

FONT_TITLE   = ("Malgun Gothic", 14, "bold")
FONT_LABEL   = ("Malgun Gothic", 10)
FONT_SMALL   = ("Malgun Gothic", 9)
FONT_MONO    = ("Consolas", 9)
FONT_STAT    = ("Malgun Gothic", 22, "bold")
FONT_STAT_LB = ("Malgun Gothic", 9)
FONT_HEAD    = ("Malgun Gothic", 9, "bold")


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Cimon ALog Analyzer")
        self.geometry("1100x760")
        self.minsize(900, 600)
        self.configure(bg=DARK_BG)

        self._records = []
        self._text_rows = []
        self._cycle_rows = []
        self._dh_devices = []
        self._filepath = ""

        self._build_ui()
        self._apply_treeview_style()

    # ── UI 빌드 ──────────────────────────────

    def _build_ui(self):
        # 헤더
        hdr = tk.Frame(self, bg=PANEL_BG, height=56)
        hdr.pack(fill="x", side="top")
        hdr.pack_propagate(False)

        tk.Label(hdr, text="Cimon", font=("Malgun Gothic", 15, "bold"),
                 bg=PANEL_BG, fg=ACCENT).pack(side="left", padx=(20, 4), pady=14)
        tk.Label(hdr, text="ALog Analyzer", font=("Malgun Gothic", 15),
                 bg=PANEL_BG, fg=TEXT_PRI).pack(side="left", pady=14)

        self._lbl_file = tk.Label(hdr, text="파일을 선택하세요",
                                   font=FONT_SMALL, bg=PANEL_BG, fg=TEXT_MUTED)
        self._lbl_file.pack(side="left", padx=20, pady=14)

        btn_open = tk.Button(hdr, text="  파일 열기  ", font=FONT_LABEL,
                              bg=ACCENT, fg="#fff", relief="flat", cursor="hand2",
                              activebackground="#3A8EEF", activeforeground="#fff",
                              command=self._open_file, padx=6, pady=4)
        btn_open.pack(side="right", padx=(4, 20), pady=12)

        btn_folder = tk.Button(hdr, text="  폴더 열기  ", font=FONT_LABEL,
                                bg=ACCENT2, fg="#111", relief="flat", cursor="hand2",
                                activebackground="#2DC97A",
                                command=self._open_folder, padx=6, pady=4)
        btn_folder.pack(side="right", padx=4, pady=12)

        # 탭바
        tabbar = tk.Frame(self, bg=PANEL_BG, height=40)
        tabbar.pack(fill="x", side="top")
        tabbar.pack_propagate(False)

        self._tab_btns = {}
        self._current_tab = tk.StringVar(value="cycle")
        for key, label in [("cycle", "동작 주기 분석"), ("log", "알람 로그"),
                           ("graph", "동작 그래프"), ("daily", "일별 분석"),
                           ("summary", "요약 통계")]:
            b = tk.Button(tabbar, text=label, font=FONT_LABEL,
                          bg=PANEL_BG, fg=TEXT_SEC, relief="flat", cursor="hand2",
                          activebackground=CARD_BG, activeforeground=TEXT_PRI,
                          pady=8, padx=14,
                          command=lambda k=key: self._switch_tab(k))
            b.pack(side="left")
            self._tab_btns[key] = b

        # 구분선
        tk.Frame(self, bg=BORDER, height=1).pack(fill="x")

        # 메인 컨텐츠
        self._content = tk.Frame(self, bg=DARK_BG)
        self._content.pack(fill="both", expand=True)

        self._frames = {}
        self._frames["cycle"]   = self._build_cycle_tab(self._content)
        self._frames["log"]     = self._build_log_tab(self._content)
        self._frames["graph"]   = self._build_graph_tab(self._content)
        self._frames["daily"]   = self._build_daily_tab(self._content)
        self._frames["summary"] = self._build_summary_tab(self._content)

        self._switch_tab("cycle")

        # 상태바
        sb = tk.Frame(self, bg=PANEL_BG, height=26)
        sb.pack(fill="x", side="bottom")
        sb.pack_propagate(False)
        self._status = tk.Label(sb, text="준비", font=FONT_SMALL,
                                 bg=PANEL_BG, fg=TEXT_MUTED)
        self._status.pack(side="left", padx=16)

    def _switch_tab(self, key):
        self._current_tab.set(key)
        for k, f in self._frames.items():
            f.pack_forget()
        self._frames[key].pack(fill="both", expand=True)
        for k, b in self._tab_btns.items():
            if k == key:
                b.config(bg=CARD_BG, fg=TEXT_PRI,
                         relief="flat")
            else:
                b.config(bg=PANEL_BG, fg=TEXT_SEC, relief="flat")

    # ── 탭: 동작 주기 ─────────────────────────

    def _build_cycle_tab(self, parent):
        frame = tk.Frame(parent, bg=DARK_BG)

        # 상단 키워드 필터
        fbar = tk.Frame(frame, bg=DARK_BG)
        fbar.pack(fill="x", padx=16, pady=(12, 6))

        tk.Label(fbar, text="D/H 장치", font=FONT_LABEL,
                 bg=DARK_BG, fg=TEXT_SEC).pack(side="left")
        self._cycle_device_cb = ttk.Combobox(fbar, values=[], width=12,
                                              state="readonly", font=FONT_LABEL)
        self._cycle_device_cb.pack(side="left", padx=(8, 4), ipady=2)
        self._cycle_device_cb.bind("<<ComboboxSelected>>", self._on_cycle_device_select)

        tk.Label(fbar, text="검색 키워드", font=FONT_LABEL,
                 bg=DARK_BG, fg=TEXT_SEC).pack(side="left", padx=(12, 0))
        self._cycle_kw_var = tk.StringVar(value="D/H_7")
        e = tk.Entry(fbar, textvariable=self._cycle_kw_var, font=FONT_LABEL,
                     bg=CARD_BG, fg=TEXT_PRI, insertbackground=TEXT_PRI,
                     relief="flat", width=14)
        e.pack(side="left", padx=(8, 4), ipady=4)

        tk.Label(fbar, text="동작 키워드", font=FONT_LABEL,
                 bg=DARK_BG, fg=TEXT_SEC).pack(side="left", padx=(12, 0))
        self._cycle_act_var = tk.StringVar(value="동작")
        e2 = tk.Entry(fbar, textvariable=self._cycle_act_var, font=FONT_LABEL,
                      bg=CARD_BG, fg=TEXT_PRI, insertbackground=TEXT_PRI,
                      relief="flat", width=12)
        e2.pack(side="left", padx=(8, 4), ipady=4)

        btn = tk.Button(fbar, text="분석", font=FONT_LABEL,
                        bg=ACCENT2, fg="#111", relief="flat", cursor="hand2",
                        activebackground="#2DC97A", command=self._run_cycle_analysis,
                        padx=10, pady=3)
        btn.pack(side="left", padx=8)

        btn_save = tk.Button(fbar, text="CSV 저장", font=FONT_LABEL,
                              bg=CARD_BG, fg=TEXT_PRI, relief="flat", cursor="hand2",
                              activebackground=BORDER,
                              command=self._save_cycle_csv, padx=10, pady=3)
        btn_save.pack(side="left", padx=4)

        # 통계 카드
        self._stat_frame = tk.Frame(frame, bg=DARK_BG)
        self._stat_frame.pack(fill="x", padx=16, pady=(0, 10))
        self._stat_cards = {}
        for key, label in [("count", "총 동작 횟수"), ("avg_dur", "평균 동작 시간"),
                            ("avg_wait", "평균 대기 시간"), ("avg_cycle", "평균 동작 주기")]:
            c = tk.Frame(self._stat_frame, bg=CARD_BG, padx=18, pady=10)
            c.pack(side="left", padx=(0, 10), pady=4)
            tk.Label(c, text=label, font=FONT_STAT_LB, bg=CARD_BG, fg=TEXT_MUTED).pack(anchor="w")
            lv = tk.Label(c, text="-", font=FONT_STAT, bg=CARD_BG, fg=TEXT_PRI)
            lv.pack(anchor="w")
            self._stat_cards[key] = lv

        # 테이블
        cols = ("no", "start", "end", "duration", "wait", "cycle")
        heads = ("#", "시작", "종료", "동작 시간", "대기 시간", "주기")
        widths = (40, 140, 140, 110, 110, 100)

        tree_wrap = tk.Frame(frame, bg=DARK_BG)
        tree_wrap.pack(fill="both", expand=True, padx=16, pady=(0, 16))

        self._cycle_tree = ttk.Treeview(tree_wrap, columns=cols, show="headings",
                                         selectmode="browse", style="Dark.Treeview")
        for col, head, w in zip(cols, heads, widths):
            self._cycle_tree.heading(col, text=head)
            self._cycle_tree.column(col, width=w, anchor="center", minwidth=40)

        vsb = ttk.Scrollbar(tree_wrap, orient="vertical",
                             command=self._cycle_tree.yview)
        self._cycle_tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self._cycle_tree.pack(side="left", fill="both", expand=True)

        return frame

    # ── 탭: 동작 그래프 ───────────────────────

    def _build_graph_tab(self, parent):
        frame = tk.Frame(parent, bg=DARK_BG)

        fbar = tk.Frame(frame, bg=DARK_BG)
        fbar.pack(fill="x", padx=16, pady=(12, 6))
        tk.Label(fbar, text="장치", font=FONT_LABEL,
                 bg=DARK_BG, fg=TEXT_SEC).pack(side="left")
        self._graph_device_var = tk.StringVar(value="전체 D/H")
        self._graph_device_cb = ttk.Combobox(fbar, textvariable=self._graph_device_var,
                                              values=["전체 D/H"], width=14,
                                              state="readonly", font=FONT_LABEL)
        self._graph_device_cb.pack(side="left", padx=(8, 4), ipady=2)
        self._graph_device_cb.bind("<<ComboboxSelected>>",
                                   lambda _: self._draw_activity_graph())
        tk.Button(fbar, text="새로고침", font=FONT_LABEL,
                  bg=ACCENT2, fg="#111", relief="flat", cursor="hand2",
                  activebackground="#2DC97A",
                  command=self._draw_activity_graph,
                  padx=10, pady=3).pack(side="left", padx=12)

        wrap = tk.Frame(frame, bg=DARK_BG)
        wrap.pack(fill="both", expand=True, padx=16, pady=(0, 4))

        self._graph_canvas = tk.Canvas(wrap, bg=DARK_BG, highlightthickness=0)
        hsb = ttk.Scrollbar(wrap, orient="horizontal",
                             command=self._graph_canvas.xview)
        self._graph_canvas.configure(xscrollcommand=hsb.set)
        hsb.pack(side="bottom", fill="x")
        self._graph_canvas.pack(side="left", fill="both", expand=True)

        self._graph_tooltip = tk.Label(frame, text="", font=FONT_SMALL,
                                        bg=CARD_BG, fg=TEXT_PRI,
                                        padx=8, pady=4, relief="flat")
        self._graph_tooltip.pack(fill="x", padx=16, pady=(0, 8))

        self._graph_rects = []
        self._graph_canvas.bind("<Motion>", self._on_graph_hover)
        self._graph_canvas.bind("<Configure>", lambda *_: self._draw_activity_graph())
        # 마우스 휠 수평 스크롤
        self._graph_canvas.bind("<MouseWheel>",
            lambda e: self._graph_canvas.xview_scroll(-1 if e.delta > 0 else 1, "units"))

        return frame

    def _draw_activity_graph(self):
        canvas = self._graph_canvas
        canvas.delete("all")
        self._graph_rects = []

        selected = self._graph_device_var.get()
        if selected == "전체 D/H":
            self._draw_multi_lane_graph(canvas)
            return

        # 선택 장치의 사이클을 실시간 계산
        rows = (self._compute_device_cycles(selected)
                if selected and self._records else self._cycle_rows)
        if not rows:
            canvas.create_text(
                max(canvas.winfo_width(), 400) // 2, 120,
                text="분석 데이터가 없습니다.\n동작 주기 분석 탭에서 먼저 분석하세요.",
                fill=TEXT_MUTED, font=FONT_LABEL, justify="center")
            return

        # ── 레이아웃 상수 ──
        ML, MR, MT, MB = 54, 24, 48, 72
        CW = max(canvas.winfo_width(), 600)
        CH = max(canvas.winfo_height(), 260)

        # 날짜 기준: 데이터의 첫 이벤트 날짜로 00:00:00 ~ 24:00:00 고정
        base_date = rows[0]["start"].date()
        t_start = datetime.datetime(base_date.year, base_date.month, base_date.day, 0, 0, 0)
        total_sec = 86400  # 24시간 고정

        draw_w = max(CW - ML - MR, 800)
        px_per_sec = draw_w / total_sec

        canvas.configure(scrollregion=(0, 0, ML + draw_w + MR, CH))

        y0 = MT + int((CH - MT - MB) * 0.85)   # y=0 기준선
        y1 = MT + int((CH - MT - MB) * 0.10)   # y=1 기준선

        # ── 제목 + 통계 ──
        title_kw = selected if selected and selected != "전체 D/H" else (
            self._cycle_kw_var.get() if hasattr(self, "_cycle_kw_var") else "ETV")
        total_dur = sum(r["duration"] for r in rows)
        count = len(rows)
        td_h, td_m, td_s = int(total_dur)//3600, (int(total_dur)%3600)//60, int(total_dur)%60
        total_dur_txt = (f"{td_h}시간 {td_m}분 {td_s}초" if td_h
                         else f"{td_m}분 {td_s}초")
        canvas.create_text(
            ML, 14,
            text=f"{title_kw} 동작 타임라인  {base_date.strftime('%Y-%m-%d')}",
            fill=TEXT_PRI, font=FONT_LABEL, anchor="w")
        canvas.create_text(
            ML + draw_w, 14,
            text=f"총 {count}회 동작   /   총 동작 시간 {total_dur_txt}",
            fill=ACCENT2, font=FONT_LABEL, anchor="e")

        # ── Y축 ──
        canvas.create_line(ML, MT, ML, y0 + 6, fill=TEXT_SEC, width=1)
        for val, ypx, color in [(1, y1, ACCENT2), (0, y0, TEXT_SEC)]:
            canvas.create_line(ML - 6, ypx, ML + draw_w, ypx,
                               fill=BORDER, dash=(3, 5))
            canvas.create_text(ML - 10, ypx, text=str(val),
                               fill=color, font=FONT_MONO, anchor="e")

        # ── X축 레이블: 1시간 간격 ──
        interval = 3600
        for t in range(0, total_sec + 1, interval):
            x = ML + int(t * px_per_sec)
            label = f"{t // 3600:02d}:00"
            canvas.create_line(x, y0, x, y0 + 6, fill=TEXT_SEC)
            canvas.create_text(x, y0 + 10, text=label,
                               fill=TEXT_SEC, font=FONT_SMALL, anchor="n")

        # ── 동작 블록 ──
        for r in rows:
            s_sec = (r["start"] - t_start).total_seconds()
            e_sec = (r["end"]   - t_start).total_seconds()
            x1 = ML + int(s_sec * px_per_sec)
            x2 = ML + int(e_sec * px_per_sec)
            if x2 < x1 + 2:
                x2 = x1 + 2

            # 채워진 블록
            canvas.create_rectangle(
                x1, y1, x2, y0,
                fill=ACCENT2, outline=ACCENT2, width=1)
            # 어두운 오버레이로 깊이감
            canvas.create_rectangle(
                x1, y1, x2, y1 + 4,
                fill="#2DC97A", outline="")
            self._graph_rects.append((r, x1, x2))

            # 블록 안 중앙에 번호 표시
            if x2 - x1 >= 18:
                canvas.create_text(
                    (x1 + x2) // 2, (y1 + y0) // 2,
                    text=str(r["no"]),
                    fill=DARK_BG, font=FONT_SMALL)

            # 블록 위에 동작 시간 표시
            dur = int(r["duration"])
            dur_txt = f"{dur//60}분 {dur%60}초" if dur >= 60 else f"{dur}초"
            block_w = x2 - x1
            cx = (x1 + x2) // 2
            if block_w >= 60:
                # 가로로 표시
                canvas.create_text(cx, y1 - 10,
                                   text=dur_txt,
                                   fill=ACCENT2, font=FONT_SMALL, anchor="s")
            elif block_w >= 8:
                # 세로로 표시 (회전)
                canvas.create_text(cx, y1 - 6,
                                   text=dur_txt,
                                   fill=ACCENT2, font=FONT_SMALL,
                                   angle=90, anchor="s")

        # ── 기준선 (0레벨) 실선 ──
        canvas.create_line(ML, y0, ML + draw_w, y0,
                           fill=TEXT_SEC, width=2)

    def _draw_multi_lane_graph(self, canvas):
        """D/H 장치별 멀티레인 타임라인"""
        devices = self._dh_devices
        if not devices or not self._records:
            canvas.create_text(
                max(canvas.winfo_width(), 400) // 2, 120,
                text="D/H 장치가 감지되지 않았습니다.\n파일을 먼저 불러오세요.",
                fill=TEXT_MUTED, font=FONT_LABEL, justify="center")
            return

        # 레이아웃
        ML, MR, MT_TOP = 90, 24, 36
        LANE_H   = 58   # 레인 높이
        LANE_PAD = 10   # 레인 내 상하 여백
        CW = max(canvas.winfo_width(), 700)

        draw_w    = max(CW - ML - MR, 800)
        px_per_sec = draw_w / 86400
        total_h   = MT_TOP + len(devices) * LANE_H + 50

        canvas.configure(scrollregion=(0, 0, ML + draw_w + MR, total_h))

        # 날짜 기준 (첫 레코드 날짜)
        base_dt = self._records[0][0]
        base_date = base_dt.date()
        t_start = datetime.datetime(base_date.year, base_date.month, base_date.day)

        # 제목
        canvas.create_text(ML, 16,
            text=f"D/H 장치별 동작 타임라인  {base_date.strftime('%Y-%m-%d')}",
            fill=TEXT_PRI, font=FONT_LABEL, anchor="w")

        # X축 레이블 (1시간 간격)
        y_xaxis = MT_TOP + len(devices) * LANE_H + 6
        canvas.create_line(ML, y_xaxis, ML + draw_w, y_xaxis, fill=TEXT_SEC, width=1)
        for h in range(0, 25):
            x = ML + int(h * 3600 * px_per_sec)
            canvas.create_line(x, MT_TOP, x, y_xaxis + 5, fill=BORDER, dash=(2, 6))
            canvas.create_line(x, y_xaxis, x, y_xaxis + 5, fill=TEXT_SEC)
            canvas.create_text(x, y_xaxis + 8, text=f"{h:02d}:00",
                               fill=TEXT_SEC, font=FONT_SMALL, anchor="n")

        # 레인별 그리기
        COLORS = [ACCENT2, ACCENT, "#FF9F43", "#FF6B6B", "#A29BFE",
                  "#FD79A8", "#00CEC9", "#FDCB6E", "#6C5CE7", "#E17055"]

        for lane_i, device in enumerate(devices):
            color = COLORS[lane_i % len(COLORS)]
            lane_top = MT_TOP + lane_i * LANE_H
            lane_bot = lane_top + LANE_H
            y0 = lane_bot - LANE_PAD          # 대기(0) 기준선
            y1 = lane_top + LANE_PAD          # 동작(1) 상단

            # 레인 배경 (교번)
            bg = CARD_BG if lane_i % 2 == 0 else ROW_ODD
            canvas.create_rectangle(ML, lane_top, ML + draw_w, lane_bot,
                                     fill=bg, outline="")

            # 장치명 레이블
            canvas.create_text(ML - 6, (lane_top + lane_bot) // 2,
                               text=device, fill=color, font=FONT_SMALL, anchor="e")

            # 대기 기준선
            canvas.create_line(ML, y0, ML + draw_w, y0,
                               fill=BORDER, dash=(3, 4))

            # 동작 블록
            cycles = self._compute_device_cycles(device)
            for r in cycles:
                s_sec = (r["start"] - t_start).total_seconds()
                e_sec = (r["end"]   - t_start).total_seconds()
                x1 = ML + int(s_sec * px_per_sec)
                x2 = ML + int(e_sec * px_per_sec)
                if x2 < x1 + 2:
                    x2 = x1 + 2
                canvas.create_rectangle(x1, y1, x2, y0,
                                         fill=color, outline="")
                # 동작 시간 텍스트 (블록 위)
                dur = int(r["duration"])
                dur_txt = f"{dur//60}분{dur%60}초" if dur >= 60 else f"{dur}초"
                bw = x2 - x1
                if bw >= 50:
                    canvas.create_text((x1+x2)//2, y1 - 4, text=dur_txt,
                                       fill=color, font=FONT_SMALL, anchor="s")
                elif bw >= 8:
                    canvas.create_text((x1+x2)//2, y1 - 3, text=dur_txt,
                                       fill=color, font=FONT_SMALL,
                                       angle=90, anchor="s")
                self._graph_rects.append((r, x1, x2, device))

        # Y축 구분선
        canvas.create_line(ML, MT_TOP, ML, y_xaxis, fill=TEXT_SEC, width=1)

    def _on_graph_hover(self, event):
        cx = self._graph_canvas.canvasx(event.x)
        for entry in self._graph_rects:
            # 단일 모드: (r, x1, x2) / 멀티레인: (r, x1, x2, device)
            r, x1, x2 = entry[0], entry[1], entry[2]
            device_prefix = f"[{entry[3]}]  " if len(entry) == 4 else ""
            if x1 <= cx <= x2:
                dur = int(r["duration"])
                wait_txt = ""
                if r["wait"]:
                    w = int(r["wait"])
                    wait_txt = f"   대기: {w//60}분 {w%60}초"
                self._graph_tooltip.config(
                    text=(f"{device_prefix}#{r['no']}  "
                          f"시작: {r['start'].strftime('%H:%M:%S')}  "
                          f"→  종료: {r['end'].strftime('%H:%M:%S')}  "
                          f"   동작: {dur//60}분 {dur%60}초" + wait_txt),
                    fg=ACCENT2)
                return
        self._graph_tooltip.config(text="", fg=TEXT_MUTED)

    # ── 탭: 알람 로그 ─────────────────────────

    def _build_log_tab(self, parent):
        frame = tk.Frame(parent, bg=DARK_BG)

        fbar = tk.Frame(frame, bg=DARK_BG)
        fbar.pack(fill="x", padx=16, pady=(12, 6))

        tk.Label(fbar, text="검색", font=FONT_LABEL,
                 bg=DARK_BG, fg=TEXT_SEC).pack(side="left")
        self._log_search_var = tk.StringVar()
        self._log_search_var.trace_add("write", lambda *_: self._filter_log())
        e = tk.Entry(fbar, textvariable=self._log_search_var, font=FONT_LABEL,
                     bg=CARD_BG, fg=TEXT_PRI, insertbackground=TEXT_PRI,
                     relief="flat", width=28)
        e.pack(side="left", padx=(8, 12), ipady=4)

        tk.Label(fbar, text="유형 필터", font=FONT_LABEL,
                 bg=DARK_BG, fg=TEXT_SEC).pack(side="left")
        self._log_type_var = tk.StringVar(value="전체")
        cb = ttk.Combobox(fbar, textvariable=self._log_type_var, width=10,
                           state="readonly", font=FONT_LABEL,
                           values=["전체", "경보발생", "동작", "복귀", "시각변경", "정보"])
        cb.pack(side="left", padx=8)
        cb.bind("<<ComboboxSelected>>", lambda _: self._filter_log())

        btn_save = tk.Button(fbar, text="TXT 저장", font=FONT_LABEL,
                              bg=CARD_BG, fg=TEXT_PRI, relief="flat", cursor="hand2",
                              activebackground=BORDER,
                              command=self._save_log_txt, padx=10, pady=3)
        btn_save.pack(side="right", padx=4)

        # 테이블
        cols = ("dt", "etype", "device", "desc")
        heads = ("시각 (KST)", "유형", "장치", "내용")
        widths = (160, 90, 220, 400)

        tree_wrap = tk.Frame(frame, bg=DARK_BG)
        tree_wrap.pack(fill="both", expand=True, padx=16, pady=(0, 16))

        self._log_tree = ttk.Treeview(tree_wrap, columns=cols, show="headings",
                                       selectmode="browse", style="Dark.Treeview")
        for col, head, w in zip(cols, heads, widths):
            self._log_tree.heading(col, text=head)
            self._log_tree.column(col, width=w, anchor="w", minwidth=40)

        vsb = ttk.Scrollbar(tree_wrap, orient="vertical",
                             command=self._log_tree.yview)
        self._log_tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self._log_tree.pack(side="left", fill="both", expand=True)

        return frame

    # ── 탭: 요약 통계 ─────────────────────────

    # ── 탭: 일별 분석 ─────────────────────────

    def _build_daily_tab(self, parent):
        frame = tk.Frame(parent, bg=DARK_BG)

        fbar = tk.Frame(frame, bg=DARK_BG)
        fbar.pack(fill="x", padx=16, pady=(12, 6))

        tk.Label(fbar, text="표시 기준", font=FONT_LABEL,
                 bg=DARK_BG, fg=TEXT_SEC).pack(side="left")
        self._daily_mode = tk.StringVar(value="count")
        for val, label in [("count", "동작 횟수"), ("duration", "총 동작 시간")]:
            tk.Radiobutton(fbar, text=label, variable=self._daily_mode, value=val,
                           font=FONT_LABEL, bg=DARK_BG, fg=TEXT_SEC,
                           selectcolor=CARD_BG, activebackground=DARK_BG,
                           command=self._draw_daily_graph).pack(side="left", padx=(8, 0))

        tk.Button(fbar, text="새로고침", font=FONT_LABEL,
                  bg=ACCENT2, fg="#111", relief="flat", cursor="hand2",
                  activebackground="#2DC97A",
                  command=self._draw_daily_graph,
                  padx=10, pady=3).pack(side="left", padx=12)

        wrap = tk.Frame(frame, bg=DARK_BG)
        wrap.pack(fill="both", expand=True, padx=16, pady=(0, 4))

        self._daily_canvas = tk.Canvas(wrap, bg=DARK_BG, highlightthickness=0)
        hsb = ttk.Scrollbar(wrap, orient="horizontal",
                             command=self._daily_canvas.xview)
        self._daily_canvas.configure(xscrollcommand=hsb.set)
        hsb.pack(side="bottom", fill="x")
        self._daily_canvas.pack(side="left", fill="both", expand=True)

        self._daily_tooltip = tk.Label(frame, text="", font=FONT_SMALL,
                                        bg=CARD_BG, fg=TEXT_PRI, padx=8, pady=4)
        self._daily_tooltip.pack(fill="x", padx=16, pady=(0, 8))

        self._daily_bars = []
        self._daily_data = []
        self._daily_canvas.bind("<Motion>", self._on_daily_hover)
        self._daily_canvas.bind("<Configure>", lambda *_: self._draw_daily_graph())
        self._daily_canvas.bind("<MouseWheel>",
            lambda e: self._daily_canvas.xview_scroll(
                -1 if e.delta > 0 else 1, "units"))

        return frame

    def _run_daily_analysis(self):
        from collections import defaultdict
        devices = self._dh_devices
        if not devices:
            # D/H 장치가 없으면 기존 방식(cycle_rows 기반)으로 fallback
            daily = defaultdict(list)
            for r in self._cycle_rows:
                daily[r["start"].date()].append(r)
            self._daily_data = [
                {"date": date, "count": len(rows),
                 "total_dur": sum(r["duration"] for r in rows),
                 "by_device": {}}
                for date, rows in sorted(daily.items())
            ]
            return

        # 장치별 일별 사이클 계산
        device_daily = {}
        all_dates = set()
        for device in devices:
            cycles = self._compute_device_cycles(device)
            daily = defaultdict(list)
            for r in cycles:
                daily[r["start"].date()].append(r)
            all_dates.update(daily.keys())
            device_daily[device] = daily

        self._daily_data = [
            {
                "date": date,
                "count": sum(len(device_daily[d].get(date, [])) for d in devices),
                "total_dur": sum(
                    sum(r["duration"] for r in device_daily[d].get(date, []))
                    for d in devices),
                "by_device": {
                    d: {
                        "count":     len(device_daily[d].get(date, [])),
                        "total_dur": sum(r["duration"] for r in device_daily[d].get(date, [])),
                    }
                    for d in devices
                },
            }
            for date in sorted(all_dates)
        ]

    def _draw_daily_graph(self):
        _DEVICE_COLORS = [
            ACCENT2, ACCENT, "#FF9F43", "#FF6B6B", "#A29BFE",
            "#FD79A8", "#00CEC9", "#FDCB6E", "#6C5CE7", "#E17055",
        ]
        canvas = self._daily_canvas
        canvas.delete("all")
        self._daily_bars = []

        data = self._daily_data
        if not data:
            canvas.create_text(
                max(canvas.winfo_width(), 400) // 2, 120,
                text="분석 데이터가 없습니다.\n폴더 열기로 파일을 불러오세요.",
                fill=TEXT_MUTED, font=FONT_LABEL, justify="center")
            return

        devices = self._dh_devices
        mode    = self._daily_mode.get()
        nd      = max(len(devices), 1)

        # ── 레이아웃 ──
        LEGEND_H = 24 if devices else 0
        ML, MR = 70, 24
        MT = 36 + LEGEND_H
        MB = 72
        CW = max(canvas.winfo_width(), 600)
        CH = max(canvas.winfo_height(), 280)

        n_days   = len(data)
        grp_w    = max(min((CW - ML - MR) // max(n_days, 1), nd * 22 + 8), nd * 10 + 4)
        draw_w   = max(grp_w * n_days, CW - ML - MR)
        graph_h  = CH - MT - MB
        y_base   = MT + graph_h

        canvas.configure(scrollregion=(0, 0, ML + draw_w + MR, CH))

        # ── 값 배열 ──
        def day_val(d, dev=None):
            if not devices or dev is None:
                return d["count"] if mode == "count" else d["total_dur"] / 60
            bd = d["by_device"].get(dev, {})
            return bd.get("count", 0) if mode == "count" else bd.get("total_dur", 0) / 60

        if devices:
            max_val = max(
                (day_val(d, dev) for d in data for dev in devices), default=1) or 1
        else:
            max_val = max((day_val(d) for d in data), default=1) or 1
        y_unit = "회" if mode == "count" else "분"

        # ── 제목 / 통계 ──
        total_count = sum(d["count"] for d in data)
        total_dur   = sum(d["total_dur"] for d in data)
        th, tm = int(total_dur) // 3600, (int(total_dur) % 3600) // 60
        dur_txt   = f"{th}시간 {tm}분" if th else f"{tm}분"
        date_range = (f"{data[0]['date']} ~ {data[-1]['date']}"
                      if len(data) > 1 else str(data[0]["date"]))
        canvas.create_text(ML, 16,
            text=f"D/H 장치별 일별 동작 분석  ({date_range})",
            fill=TEXT_PRI, font=FONT_LABEL, anchor="w")
        canvas.create_text(ML + draw_w, 16,
            text=f"총 {total_count}회 동작  /  총 동작 시간 {dur_txt}",
            fill=ACCENT2, font=FONT_LABEL, anchor="e")

        # ── 범례 ──
        if devices:
            lx = ML
            for di, dev in enumerate(devices):
                color = _DEVICE_COLORS[di % len(_DEVICE_COLORS)]
                canvas.create_rectangle(lx, 30, lx + 12, 30 + 12,
                                         fill=color, outline="")
                canvas.create_text(lx + 16, 36, text=dev,
                                   fill=color, font=FONT_SMALL, anchor="w")
                lx += len(dev) * 7 + 28

        # ── Y축 ──
        canvas.create_line(ML, MT, ML, y_base + 6, fill=TEXT_SEC, width=1)
        for i in range(6):
            y   = MT + int(graph_h * (1 - i / 5))
            val = max_val * i / 5
            canvas.create_line(ML - 4, y, ML + draw_w, y, fill=BORDER, dash=(3, 5))
            lbl = str(int(round(val))) + y_unit if mode == "count" else f"{val:.0f}분"
            canvas.create_text(ML - 6, y, text=lbl,
                               fill=TEXT_SEC, font=FONT_SMALL, anchor="e")

        # ── 막대 ──
        mb_w = max((grp_w - 6) // nd, 3)   # 장치당 막대 폭
        gap  = max(grp_w - mb_w * nd - 4, 2)

        for i, d in enumerate(data):
            grp_x = ML + i * grp_w
            cx_grp = grp_x + grp_w // 2

            if not devices:
                # D/H 장치 없음: 단일 막대
                v   = day_val(d)
                bx1 = grp_x + 4
                bx2 = grp_x + grp_w - 4
                bh  = int(graph_h * v / max_val) if max_val else 0
                by1 = y_base - bh
                canvas.create_rectangle(bx1, by1, bx2, y_base,
                                         fill=ACCENT2, outline="")
                canvas.create_rectangle(bx1, by1, bx2, by1 + 3,
                                         fill="#2DC97A", outline="")
                val_txt = f"{int(v)}{y_unit}"
                canvas.create_text((bx1+bx2)//2, by1 - 4, text=val_txt,
                                   fill=TEXT_PRI, font=FONT_SMALL, anchor="s")
                self._daily_bars.append((d, None, bx1, bx2))
            else:
                # 장치별 묶음 막대
                bar_start = grp_x + gap // 2 + 2
                for di, dev in enumerate(devices):
                    color = _DEVICE_COLORS[di % len(_DEVICE_COLORS)]
                    v   = day_val(d, dev)
                    bx1 = bar_start + di * mb_w
                    bx2 = bx1 + mb_w - 1
                    bh  = int(graph_h * v / max_val) if max_val else 0
                    by1 = y_base - bh
                    if bh > 0:
                        canvas.create_rectangle(bx1, by1, bx2, y_base,
                                                 fill=color, outline="")
                        canvas.create_rectangle(bx1, by1, bx2, by1 + 2,
                                                 fill=color, outline="")
                    # 값 레이블 (막대 폭 충분할 때)
                    if bh > 14 and mb_w >= 12:
                        val_txt = str(int(v))
                        canvas.create_text((bx1+bx2)//2, by1 + 2,
                                           text=val_txt, fill=DARK_BG,
                                           font=FONT_SMALL, anchor="n")
                    self._daily_bars.append((d, dev, bx1, bx2))

            # 날짜 레이블
            canvas.create_line(cx_grp, y_base, cx_grp, y_base + 5, fill=TEXT_SEC)
            canvas.create_text(cx_grp, y_base + 10,
                               text=d["date"].strftime("%m/%d"),
                               fill=TEXT_SEC, font=FONT_SMALL,
                               anchor="n")

        # 기준선
        canvas.create_line(ML, y_base, ML + draw_w, y_base,
                           fill=TEXT_SEC, width=2)

    def _on_daily_hover(self, event):
        cx = self._daily_canvas.canvasx(event.x)
        for d, dev, bx1, bx2 in self._daily_bars:
            if bx1 <= cx <= bx2:
                if dev:
                    bd  = d["by_device"].get(dev, {})
                    cnt = bd.get("count", 0)
                    dur = int(bd.get("total_dur", 0))
                else:
                    cnt = d["count"]
                    dur = int(d["total_dur"])
                dh, dm, ds = dur // 3600, (dur % 3600) // 60, dur % 60
                dur_txt = f"{dh}시간 {dm}분 {ds}초" if dh else f"{dm}분 {ds}초"
                dev_txt = f"[{dev}]  " if dev else ""
                self._daily_tooltip.config(
                    text=f"{dev_txt}{d['date']}   동작 {cnt}회   총 동작 시간 {dur_txt}",
                    fg=ACCENT2)
                return
        self._daily_tooltip.config(text="", fg=TEXT_MUTED)

    # ── 탭: 요약 통계 ─────────────────────────

    def _build_summary_tab(self, parent):
        frame = tk.Frame(parent, bg=DARK_BG)

        self._summary_text = tk.Text(frame, font=FONT_MONO, bg=CARD_BG,
                                      fg=TEXT_PRI, relief="flat",
                                      insertbackground=TEXT_PRI,
                                      padx=16, pady=12, state="disabled",
                                      wrap="none")
        vsb = ttk.Scrollbar(frame, orient="vertical",
                             command=self._summary_text.yview)
        self._summary_text.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y", padx=(0, 16), pady=16)
        self._summary_text.pack(fill="both", expand=True, padx=16, pady=16)

        return frame

    # ── Treeview 스타일 ───────────────────────

    def _apply_treeview_style(self):
        style = ttk.Style(self)
        style.theme_use("default")
        style.configure("Dark.Treeview",
                         background=ROW_EVEN,
                         foreground=TEXT_PRI,
                         fieldbackground=ROW_EVEN,
                         rowheight=26,
                         font=FONT_MONO,
                         borderwidth=0,
                         relief="flat")
        style.configure("Dark.Treeview.Heading",
                         background=CARD_BG,
                         foreground=TEXT_SEC,
                         font=FONT_HEAD,
                         borderwidth=0,
                         relief="flat")
        style.map("Dark.Treeview",
                  background=[("selected", ROW_SEL)],
                  foreground=[("selected", TEXT_PRI)])
        style.map("Dark.Treeview.Heading",
                  background=[("active", BORDER)])
        style.configure("TScrollbar", troughcolor=PANEL_BG,
                         background=BORDER, borderwidth=0, arrowsize=12)
        style.configure("TCombobox", fieldbackground=CARD_BG,
                         background=CARD_BG, foreground=TEXT_PRI,
                         selectbackground=CARD_BG, selectforeground=TEXT_PRI)
        style.map("TCombobox", fieldbackground=[("readonly", CARD_BG)])
        self.option_add("*TCombobox*Listbox.background", CARD_BG)
        self.option_add("*TCombobox*Listbox.foreground", TEXT_PRI)

    # ── 파일 열기 ─────────────────────────────

    def _open_file(self):
        fp = filedialog.askopenfilename(
            title="ALog 파일 선택",
            filetypes=[("Cimon ALog", "*.ALog *.alog"), ("모든 파일", "*.*")]
        )
        if not fp:
            return
        self._filepath = fp
        self._lbl_file.config(text=os.path.basename(fp), fg=TEXT_SEC)
        self._set_status("파일 로드 중...")
        threading.Thread(target=self._load_file, daemon=True).start()

    def _load_file(self):
        try:
            records = parse_alog(self._filepath)
            text_rows = extract_text_records(records)
            self._records = records
            self._text_rows = text_rows
            self.after(0, self._on_load_done)
        except Exception as e:
            self.after(0, lambda: messagebox.showerror("오류", f"파일 로드 실패:\n{e}"))
            self.after(0, lambda: self._set_status("오류 발생"))

    def _open_folder(self):
        dp = filedialog.askdirectory(title="ALog 폴더 선택")
        if not dp:
            return
        import glob as _glob
        files = sorted(
            _glob.glob(os.path.join(dp, "*.ALog")) +
            _glob.glob(os.path.join(dp, "*.alog"))
        )
        if not files:
            messagebox.showinfo("알림", "폴더에 ALog 파일이 없습니다.")
            return

        # 연/월 선택 다이얼로그
        result = self._ask_year_month()
        if result is None:
            return
        year, month = result

        self._lbl_file.config(
            text=f"{os.path.basename(dp)}/ ({len(files)}개 파일)", fg=TEXT_SEC)
        self._set_status(f"{year}년 {month}월 데이터 로드 중...")
        threading.Thread(
            target=self._load_folder,
            args=(files, year, month),
            daemon=True
        ).start()

    def _ask_year_month(self):
        """연/월 선택 다이얼로그. (year, month) 또는 None 반환."""
        now = datetime.datetime.now()
        result = [None]

        dlg = tk.Toplevel(self)
        dlg.title("분석 월 선택")
        dlg.configure(bg=PANEL_BG)
        dlg.resizable(False, False)
        dlg.grab_set()

        tk.Label(dlg, text="분석할 연/월을 선택하세요",
                 font=FONT_LABEL, bg=PANEL_BG, fg=TEXT_PRI,
                 padx=20, pady=14).grid(row=0, column=0, columnspan=3)

        years  = [str(y) for y in range(now.year - 3, now.year + 1)]
        months = [f"{m:02d}" for m in range(1, 13)]

        year_var  = tk.StringVar(value=str(now.year))
        month_var = tk.StringVar(value=f"{now.month:02d}")

        tk.Label(dlg, text="년", font=FONT_LABEL,
                 bg=PANEL_BG, fg=TEXT_SEC).grid(row=1, column=0, padx=(20, 4), pady=8)
        ttk.Combobox(dlg, textvariable=year_var, values=years,
                     width=7, state="readonly",
                     font=FONT_LABEL).grid(row=1, column=1, padx=4)
        tk.Label(dlg, text="월", font=FONT_LABEL,
                 bg=PANEL_BG, fg=TEXT_SEC).grid(row=1, column=2, padx=4)
        ttk.Combobox(dlg, textvariable=month_var, values=months,
                     width=5, state="readonly",
                     font=FONT_LABEL).grid(row=1, column=3, padx=(4, 20))

        def on_ok():
            result[0] = (int(year_var.get()), int(month_var.get()))
            dlg.destroy()

        def on_cancel():
            dlg.destroy()

        btn_frame = tk.Frame(dlg, bg=PANEL_BG)
        btn_frame.grid(row=2, column=0, columnspan=4, pady=14)
        tk.Button(btn_frame, text="확인", font=FONT_LABEL,
                  bg=ACCENT, fg="#fff", relief="flat", cursor="hand2",
                  activebackground="#3A8EEF", padx=16, pady=4,
                  command=on_ok).pack(side="left", padx=8)
        tk.Button(btn_frame, text="취소", font=FONT_LABEL,
                  bg=CARD_BG, fg=TEXT_PRI, relief="flat", cursor="hand2",
                  activebackground=BORDER, padx=16, pady=4,
                  command=on_cancel).pack(side="left", padx=8)

        dlg.bind("<Return>", lambda _: on_ok())
        dlg.bind("<Escape>", lambda _: on_cancel())

        # 화면 중앙 배치
        self.update_idletasks()
        x = self.winfo_x() + (self.winfo_width()  - dlg.winfo_reqwidth())  // 2
        y = self.winfo_y() + (self.winfo_height() - dlg.winfo_reqheight()) // 2
        dlg.geometry(f"+{x}+{y}")

        dlg.wait_window()
        return result[0]

    def _load_folder(self, files, year, month):
        try:
            import calendar
            last_day = calendar.monthrange(year, month)[1]
            t_from = datetime.datetime(year, month, 1, 0, 0, 0)
            t_to   = datetime.datetime(year, month, last_day, 23, 59, 59)

            all_records = []
            for fp in files:
                all_records.extend(parse_alog(fp))
            all_records.sort(key=lambda x: x[0])
            filtered = [(dt, chunk) for dt, chunk in all_records
                        if t_from <= dt <= t_to]
            if not filtered:
                self.after(0, lambda: messagebox.showinfo(
                    "알림", f"{year}년 {month}월 데이터가 없습니다."))
                self.after(0, lambda: self._set_status("데이터 없음"))
                return
            text_rows = extract_text_records(filtered)
            self._records = filtered
            self._text_rows = text_rows
            self.after(0, lambda: self._lbl_file.config(
                text=f"{year}년 {month:02d}월  ({len(filtered)}개 레코드)", fg=TEXT_SEC))
            self.after(0, self._on_load_done)
        except Exception as e:
            self.after(0, lambda: messagebox.showerror("오류", f"로드 실패:\n{e}"))
            self.after(0, lambda: self._set_status("오류 발생"))

    def _on_load_done(self):
        self._dh_devices = find_dh_devices(self._records)
        self._refresh_device_combos()
        self._populate_log_tree(self._text_rows)
        self._run_cycle_analysis()
        self._update_summary()
        self._set_status(f"로드 완료 — {len(self._text_rows)}개 레코드  |  D/H 장치 {len(self._dh_devices)}개 감지")

    # ── 장치 목록 관리 ────────────────────────

    def _refresh_device_combos(self):
        devices = self._dh_devices
        if hasattr(self, "_cycle_device_cb"):
            self._cycle_device_cb["values"] = devices
            if devices and self._cycle_device_cb.get() not in devices:
                self._cycle_device_cb.set(devices[0])
                self._cycle_kw_var.set(devices[0])
        if hasattr(self, "_graph_device_cb"):
            vals = ["전체 D/H"] + devices
            self._graph_device_cb["values"] = vals
            if self._graph_device_var.get() not in vals:
                self._graph_device_var.set("전체 D/H")

    def _on_cycle_device_select(self, *_):
        device = self._cycle_device_cb.get()
        if device:
            self._cycle_kw_var.set(device)
            self._run_cycle_analysis()

    def _compute_device_cycles(self, device):
        """특정 장치의 cycle_rows 계산"""
        act = self._cycle_act_var.get().strip() or "동작"
        events = []
        for dt, chunk in self._records:
            text = chunk.decode("cp949", errors="replace")
            if device in text and act in text:
                events.append(dt)
        events.sort()
        return calc_cycles(events)

    # ── 주기 분석 ─────────────────────────────

    def _run_cycle_analysis(self):
        if not self._records:
            return
        kw  = self._cycle_kw_var.get().strip()
        act = self._cycle_act_var.get().strip()
        if not kw:
            return

        # 키워드로 이벤트 필터
        events = []
        for dt, chunk in self._records:
            text = chunk.decode("cp949", errors="replace")
            if kw in text and act in text:
                events.append(dt)
        events.sort()
        self._cycle_rows = calc_cycles(events)
        self._populate_cycle_tree(self._cycle_rows)
        self._update_stat_cards(self._cycle_rows)
        self._run_daily_analysis()
        self.after(50, self._draw_activity_graph)
        self.after(50, self._draw_daily_graph)

    def _populate_cycle_tree(self, rows):
        tree = self._cycle_tree
        tree.delete(*tree.get_children())
        for i, r in enumerate(rows):
            dur  = f"{r['duration']/60:.1f}분 ({int(r['duration'])}초)"
            wait = f"{r['wait']/60:.1f}분" if r["wait"] else "-"
            cyc  = f"{r['cycle']/60:.1f}분" if r["cycle"] else "-"
            tag = "odd" if i % 2 else "even"
            tree.insert("", "end", tags=(tag,),
                        values=(r["no"],
                                r["start"].strftime("%H:%M:%S"),
                                r["end"].strftime("%H:%M:%S"),
                                dur, wait, cyc))
        tree.tag_configure("even", background=ROW_EVEN)
        tree.tag_configure("odd",  background=ROW_ODD)

    def _update_stat_cards(self, rows):
        if not rows:
            for k in self._stat_cards:
                self._stat_cards[k].config(text="-")
            return
        durs   = [r["duration"] for r in rows]
        waits  = [r["wait"] for r in rows if r["wait"]]
        cycles = [r["cycle"] for r in rows if r["cycle"]]

        self._stat_cards["count"].config(text=f"{len(rows)}회")
        self._stat_cards["avg_dur"].config(
            text=f"{sum(durs)/len(durs)/60:.1f}분")
        self._stat_cards["avg_wait"].config(
            text=f"{sum(waits)/len(waits)/60:.1f}분" if waits else "-")
        self._stat_cards["avg_cycle"].config(
            text=f"{sum(cycles)/len(cycles)/60:.1f}분" if cycles else "-")

    # ── 로그 탭 ───────────────────────────────

    def _populate_log_tree(self, rows):
        tree = self._log_tree
        tree.delete(*tree.get_children())
        for i, r in enumerate(rows):
            tag = "odd" if i % 2 else "even"
            tree.insert("", "end", tags=(tag,),
                        values=(r["dt"].strftime("%Y-%m-%d %H:%M:%S"),
                                r["etype"], r["device"], r["desc"]))
        tree.tag_configure("even", background=ROW_EVEN)
        tree.tag_configure("odd",  background=ROW_ODD)

    def _filter_log(self):
        q    = self._log_search_var.get().lower()
        ftyp = self._log_type_var.get()
        rows = self._text_rows
        if ftyp != "전체":
            rows = [r for r in rows if r["etype"] == ftyp]
        if q:
            rows = [r for r in rows if q in r["raw"].lower() or
                    q in r["device"].lower() or q in r["desc"].lower()]
        self._populate_log_tree(rows)
        self._set_status(f"{len(rows)}개 표시 중")

    # ── 요약 탭 ───────────────────────────────

    def _update_summary(self):
        if not self._text_rows:
            return
        rows = self._text_rows
        cycle_rows = self._cycle_rows

        from collections import Counter
        etype_cnt = Counter(r["etype"] for r in rows)
        device_cnt = Counter(r["device"] for r in rows if r["device"])
        top_devices = device_cnt.most_common(10)

        durs   = [r["duration"] for r in cycle_rows]
        waits  = [r["wait"] for r in cycle_rows if r["wait"]]
        cycles = [r["cycle"] for r in cycle_rows if r["cycle"]]

        lines = []
        lines.append("=" * 60)
        lines.append(f"  파일: {os.path.basename(self._filepath)}")
        lines.append(f"  분석 시각: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("=" * 60)
        lines.append("")
        lines.append("[ 레코드 요약 ]")
        lines.append(f"  전체 레코드 수: {len(rows)}건")
        for k, v in sorted(etype_cnt.items(), key=lambda x: -x[1]):
            lines.append(f"  {k:<12}: {v}건")
        lines.append("")
        lines.append("[ 상위 장치 (이벤트 수) ]")
        for dev, cnt in top_devices:
            if dev:
                lines.append(f"  {dev:<32}: {cnt}건")
        lines.append("")
        lines.append("[ ETV 동작 주기 분석 ]")
        if durs:
            lines.append(f"  총 동작 횟수  : {len(durs)}회")
            lines.append(f"  동작 시간     : 평균 {sum(durs)/len(durs)/60:.1f}분 "
                          f"/ 최소 {min(durs)/60:.1f}분 / 최대 {max(durs)/60:.1f}분")
            if waits:
                lines.append(f"  대기 시간     : 평균 {sum(waits)/len(waits)/60:.1f}분 "
                              f"/ 최소 {min(waits)/60:.1f}분 / 최대 {max(waits)/60:.1f}분")
            if cycles:
                lines.append(f"  동작 주기     : 평균 {sum(cycles)/len(cycles)/60:.1f}분 "
                              f"/ 최소 {min(cycles)/60:.1f}분 / 최대 {max(cycles)/60:.1f}분")
        else:
            lines.append("  ETV 동작 이벤트 없음")
        lines.append("")
        lines.append("=" * 60)

        txt = self._summary_text
        txt.config(state="normal")
        txt.delete("1.0", "end")
        txt.insert("end", "\n".join(lines))
        txt.config(state="disabled")

    # ── 저장 ──────────────────────────────────

    def _save_cycle_csv(self):
        if not self._cycle_rows:
            messagebox.showinfo("알림", "분석 결과가 없습니다.")
            return
        fp = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv")],
            initialfile="동작주기_분석.csv"
        )
        if not fp:
            return
        with open(fp, "w", encoding="utf-8-sig") as f:
            f.write("번호,시작,종료,동작시간(초),동작시간(분),대기시간(초),대기시간(분),주기(초),주기(분)\n")
            for r in self._cycle_rows:
                dur_m  = f"{r['duration']/60:.2f}"
                wait_s = str(int(r["wait"])) if r["wait"] else ""
                wait_m = f"{r['wait']/60:.2f}" if r["wait"] else ""
                cyc_s  = str(int(r["cycle"])) if r["cycle"] else ""
                cyc_m  = f"{r['cycle']/60:.2f}" if r["cycle"] else ""
                f.write(f"{r['no']},{r['start'].strftime('%Y-%m-%d %H:%M:%S')},"
                        f"{r['end'].strftime('%Y-%m-%d %H:%M:%S')},"
                        f"{int(r['duration'])},{dur_m},"
                        f"{wait_s},{wait_m},{cyc_s},{cyc_m}\n")
        messagebox.showinfo("저장 완료", f"저장됨:\n{fp}")

    def _save_log_txt(self):
        if not self._text_rows:
            messagebox.showinfo("알림", "로그 데이터가 없습니다.")
            return
        fp = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("텍스트", "*.txt")],
            initialfile=f"{os.path.splitext(os.path.basename(self._filepath))[0]}_추출.txt"
        )
        if not fp:
            return
        save_text_file(fp, self._text_rows)
        messagebox.showinfo("저장 완료", f"저장됨:\n{fp}")

    # ── 유틸 ──────────────────────────────────

    def _set_status(self, msg):
        self._status.config(text=msg)


# ─────────────────────────────────────────
#  엔트리포인트
# ─────────────────────────────────────────

if __name__ == "__main__":
    app = App()
    app.mainloop()
