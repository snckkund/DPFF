import sys
import os
import json

_PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import time
from datetime import datetime

from src.main import run_simulation, run_analysis, analyze_events
from src.integrity import verify_all, generate_chain_of_custody
from src.database import ForensicDatabase
from src.reporters.timeline import TimelineReporter
from src.reporters.json_export import JsonExporter
from src.reporters.stix_export import StixExporter
from src.reporters.html import HtmlReporter

# ── Theme Definitions ──────────────────────────────────────────
THEMES = {
    'dark': {
        'bg':           '#0d1117',
        'bg_secondary': '#161b22',
        'bg_card':      '#1c2333',
        'bg_input':     '#0d1117',
        'border':       '#30363d',
        'text':         '#e6edf3',
        'text_muted':   '#8b949e',
        'text_subtle':  '#484f58',
        'accent':       '#2f81f7',
        'accent_hover': '#388bfd',
        'green':        '#3fb950',
        'red':          '#f85149',
        'orange':       '#d29922',
        'purple':       '#bc8cff',
        'yellow':       '#e3b341',
    },
    'light': {
        'bg':           '#ffffff',
        'bg_secondary': '#f6f8fa',
        'bg_card':      '#ffffff',
        'bg_input':     '#ffffff',
        'border':       '#d0d7de',
        'text':         '#1f2328',
        'text_muted':   '#656d76',
        'text_subtle':  '#afb8c1',
        'accent':       '#0969da',
        'accent_hover': '#1a7f37',
        'green':        '#1a7f37',
        'red':          '#cf222e',
        'orange':       '#9a6700',
        'purple':       '#8250df',
        'yellow':       '#9a6700',
    }
}

SEVERITY_COLORS = {
    'dark':  {'CRITICAL': '#f85149', 'HIGH': '#d29922', 'MEDIUM': '#e3b341', 'LOW': '#3fb950'},
    'light': {'CRITICAL': '#cf222e', 'HIGH': '#9a6700', 'MEDIUM': '#9a6700', 'LOW': '#1a7f37'},
}

SOURCE_COLORS_KEYS = {
    'Git': 'accent', 'GitHub': 'text', 'CI Runner': 'orange', 'CI Build': 'orange',
    'CI Runner (benign)': 'green', 'CI Runner (malicious)': 'red',
    'Harbor': 'green', 'Kubernetes': 'accent', 'Kubernetes (benign)': 'green',
    'Kubernetes (malicious)': 'red', 'Docker': 'accent', 'Jenkins': 'orange',
}

APP_VERSION = "v2.0"


class ThemeManager:
    def __init__(self, initial='dark'):
        self._mode = initial
        self._callbacks = []

    @property
    def mode(self):
        return self._mode

    @property
    def C(self):
        return THEMES[self._mode]

    def severity(self, sev):
        return SEVERITY_COLORS[self._mode].get(sev, self.C['red'])

    def source_color(self, source):
        key = SOURCE_COLORS_KEYS.get(source, 'text')
        return self.C[key]

    def toggle(self):
        self._mode = 'light' if self._mode == 'dark' else 'dark'
        for cb in self._callbacks:
            cb()

    def on_change(self, callback):
        self._callbacks.append(callback)


TM = ThemeManager('dark')


# ── Settings Persistence ───────────────────────────────────────
SETTINGS_DIR  = os.path.join(os.path.expanduser('~'), '.dpff')
SETTINGS_FILE = os.path.join(SETTINGS_DIR, 'settings.json')

DEFAULT_SETTINGS = {
    'theme': 'dark',
    'mode':  'simulate',
    'github': {
        'enabled':  True,
        'url':      'http://localhost:3000',
        'org':      'dpff-lab',
        'token':    'dpff-lab-2024',
    },
    'jenkins': {
        'enabled':  True,
        'url':      'http://localhost:9090',
        'user':     'admin',
        'token':    'admin',
    },
    'harbor': {
        'enabled':  False,
        'url':      'https://harbor.local',
        'user':     '',
        'password': '',
    },
    'runtime': {
        'kubernetes':    False,
        'docker':        True,
        'lookback_days': '7',
        'report_path':   'forensic_report.html',
    },
}


def _load_raw_settings() -> dict:
    """Load settings from disk, merging with defaults to fill missing keys."""
    try:
        if os.path.exists(SETTINGS_FILE):
            with open(SETTINGS_FILE, 'r', encoding='utf-8') as f:
                saved = json.load(f)
            # Deep merge: saved over defaults
            merged = {**DEFAULT_SETTINGS}
            for section, values in saved.items():
                if isinstance(values, dict) and section in merged and isinstance(merged[section], dict):
                    merged[section] = {**merged[section], **values}
                else:
                    merged[section] = values
            return merged
    except Exception:
        pass
    return dict(DEFAULT_SETTINGS)


def _save_raw_settings(data: dict):
    """Persist settings dict to disk."""
    try:
        os.makedirs(SETTINGS_DIR, exist_ok=True)
        with open(SETTINGS_FILE, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass


class ForensicApp(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title(f"DPFF  ·  DevSecOps Pipeline Forensics Framework  {APP_VERSION}")
        self.geometry("1440x900")
        self.minsize(1100, 700)

        self.style = ttk.Style()
        self.style.theme_use('clam')

        # State
        self.current_findings = []
        self.current_events = []
        self.current_integrity = {}
        self.current_custody = {}
        self.current_inv_id = ""
        self.current_duration = 0.0
        self._history_mode = False      # True when Incidents tree shows history rows
        self._history_id_map = {}       # maps short iid -> full investigation ID

        self._apply_theme()
        self._build_layout()

        TM.on_change(self._on_theme_change)
        self.mode_var.trace('w', self._toggle_config_panel)
        self._toggle_config_panel()
        self._load_settings()      # ← load persisted settings over defaults
        self._load_env_vars()      # ← env vars override saved settings

        # Auto-save on close
        self.protocol('WM_DELETE_WINDOW', self._on_close)

    # ── Theme ──────────────────────────────────────────────────
    def _apply_theme(self):
        C = TM.C
        self.configure(bg=C['bg'])
        s = self.style

        s.configure('.', font=('Segoe UI', 10), background=C['bg'], foreground=C['text'])
        s.configure('TFrame', background=C['bg'])
        s.configure('TLabel', background=C['bg'], foreground=C['text'])

        # Toolbar
        s.configure('Toolbar.TFrame', background=C['bg_secondary'])
        s.configure('Toolbar.TLabel',  background=C['bg_secondary'], foreground=C['text_muted'],
                    font=('Segoe UI', 9, 'bold'))
        s.configure('AppTitle.TLabel', background=C['bg_secondary'], foreground=C['text'],
                    font=('Segoe UI', 11, 'bold'))
        s.configure('AppVer.TLabel',   background=C['bg_secondary'], foreground=C['text_muted'],
                    font=('Segoe UI', 9))
        s.configure('Status.TLabel',   background=C['bg_secondary'], foreground=C['accent'],
                    font=('Segoe UI', 9))
        s.configure('Integrity.TLabel', background=C['bg_secondary'], foreground=C['green'],
                    font=('Segoe UI', 9, 'bold'))

        # Separator
        s.configure('TSeparator', background=C['border'])

        # Buttons
        s.configure('Run.TButton',   font=('Segoe UI', 10, 'bold'), padding=[12, 6])
        s.configure('Theme.TButton', font=('Segoe UI', 10),         padding=[6, 6])
        s.configure('Action.TButton', font=('Segoe UI', 9),         padding=[8, 4])
        s.configure('Eye.TButton',    font=('Segoe UI', 9),         padding=[3, 2], width=3)

        # Combobox
        s.configure('TCombobox', fieldbackground=C['bg_input'], background=C['bg_secondary'],
                    foreground=C['text'], selectbackground=C['accent'])
        s.map('TCombobox', fieldbackground=[('readonly', C['bg_input'])],
              foreground=[('readonly', C['text'])])

        # Checkbutton
        s.configure('TCheckbutton', background=C['bg'], foreground=C['text'])

        # Notebook
        s.configure('Main.TNotebook', background=C['bg_secondary'], tabposition='n', padding=0,
                    borderwidth=0)
        s.configure('Main.TNotebook.Tab', padding=[18, 10], font=('Segoe UI', 10, 'bold'),
                    background=C['bg_secondary'], foreground=C['text_muted'])
        s.map('Main.TNotebook.Tab',
              background=[('selected', C['bg']), ('!selected', C['bg_secondary'])],
              foreground=[('selected', C['accent']), ('!selected', C['text_muted'])])

        # Treeview
        s.configure('Forensic.Treeview', background=C['bg_secondary'], foreground=C['text'],
                    fieldbackground=C['bg_secondary'], font=('Segoe UI', 9), rowheight=30,
                    borderwidth=0, relief='flat')
        s.configure('Forensic.Treeview.Heading', background=C['bg_card'], foreground=C['text_muted'],
                    font=('Segoe UI', 9, 'bold'), relief='flat', borderwidth=0)
        s.map('Forensic.Treeview',
              background=[('selected', C['accent'])],
              foreground=[('selected', '#ffffff')])

        # Scrollbar
        s.configure('TScrollbar', background=C['bg_secondary'], troughcolor=C['bg'],
                    arrowcolor=C['text_muted'], borderwidth=0)

        # LabelFrame
        s.configure('Section.TLabelframe', background=C['bg_card'], relief='flat', borderwidth=0)
        s.configure('Section.TLabelframe.Label', background=C['bg_card'], foreground=C['text_muted'],
                    font=('Segoe UI', 8, 'bold'))
        s.configure('Group.TLabelframe', background=C['bg_secondary'], relief='solid', borderwidth=1)
        s.configure('Group.TLabelframe.Label', background=C['bg_secondary'], foreground=C['accent'],
                    font=('Segoe UI', 9, 'bold'))

        # Entry
        s.configure('TEntry', fieldbackground=C['bg_input'], foreground=C['text'],
                    insertcolor=C['text'], borderwidth=1)

        # KPI styles
        s.configure('KPIValue.TLabel', background=C['bg_card'], foreground=C['text'],
                    font=('Segoe UI', 28, 'bold'))
        s.configure('KPITitle.TLabel', background=C['bg_card'], foreground=C['text_muted'],
                    font=('Segoe UI', 9, 'bold'))
        s.configure('KPICard.TFrame', background=C['bg_card'])
        s.configure('KPISub.TLabel', background=C['bg_card'], foreground=C['text_subtle'],
                    font=('Segoe UI', 8))

        # PanedWindow
        s.configure('TPanedwindow', background=C['border'])

    def _on_theme_change(self):
        self._apply_theme()
        # Re-render all dynamic canvases/widgets
        try:
            self._refresh_all_widgets()
        except Exception:
            pass

    def _refresh_all_widgets(self):
        C = TM.C
        # Toolbar bg
        self.toolbar.configure(style='Toolbar.TFrame')
        # Update text widgets
        for txt in [self.txt_details, self.txt_report, self.txt_activity]:
            txt.configure(bg=C['bg'], fg=C['text'],
                          insertbackground=C['text'], selectbackground=C['accent'])
        # Update canvas backgrounds
        self.timeline_canvas.configure(bg=C['bg'])
        self.chart_canvas.configure(bg=C['bg_card'])
        # Re-tag detail widget
        self._configure_text_tags(self.txt_details)
        self._configure_report_tags(self.txt_report)
        # Re-render canvases
        self.render_timeline()
        self.render_dashboard()
        # Update theme button text
        self.btn_theme.configure(text='☀  Day Mode' if TM.mode == 'dark' else '🌙  Night Mode')
        # Refresh treeview tags
        for sev, _ in SEVERITY_COLORS['dark'].items():
            self.tree.tag_configure(f'sev_{sev}',
                                    foreground=TM.severity(sev),
                                    font=('Segoe UI', 9, 'bold'))

    # ── Layout ─────────────────────────────────────────────────
    def _build_layout(self):
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)

        self._build_toolbar()

        self.notebook = ttk.Notebook(self, style='Main.TNotebook')
        self.notebook.grid(row=1, column=0, sticky='nsew', padx=0, pady=0)

        # Tabs
        self.tab_dashboard = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_dashboard, text='  📈  Dashboard  ')
        self._build_dashboard_tab()

        self.tab_incidents = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_incidents, text='  🚨  Incidents  ')
        self._build_incidents_tab()

        self.tab_timeline = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_timeline, text='  📊  Timeline  ')
        self._build_timeline_tab()

        self.tab_report = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_report, text='  📋  Report  ')
        self._build_report_tab()

        # Config panel
        self.frame_config = ttk.LabelFrame(self, text='  Analysis Configuration  ',
                                            style='Group.TLabelframe', padding=(16, 12))
        self.frame_config.grid(row=2, column=0, sticky='ew', padx=12, pady=(0, 8))
        self._build_config_panel()

    # ── Toolbar ───────────────────────────────────────────────
    def _build_toolbar(self):
        C = TM.C
        self.toolbar = ttk.Frame(self, style='Toolbar.TFrame')
        self.toolbar.grid(row=0, column=0, sticky='ew')

        # Left: Title + version
        title_frame = ttk.Frame(self.toolbar, style='Toolbar.TFrame', padding=(12, 8))
        title_frame.pack(side='left')
        ttk.Label(title_frame, text='DPFF', style='AppTitle.TLabel').pack(side='left')
        ttk.Label(title_frame, text=f'  {APP_VERSION}  ·  DevSecOps Forensic Framework',
                  style='AppVer.TLabel').pack(side='left')

        # Left: separator
        ttk.Separator(self.toolbar, orient='vertical').pack(side='left', fill='y', padx=8, pady=4)

        # Mode selector
        ttk.Label(self.toolbar, text='Mode', style='Toolbar.TLabel',
                  padding=(0, 8)).pack(side='left', padx=(4, 2))
        self.mode_var = tk.StringVar(value='simulate')
        self.combo_mode = ttk.Combobox(self.toolbar, textvariable=self.mode_var,
                                        values=['simulate', 'analyze', 'history'],
                                        state='readonly', width=11, font=('Segoe UI', 10))
        self.combo_mode.pack(side='left', padx=4, pady=4)

        # Run button
        self.btn_run = ttk.Button(self.toolbar, text='▶   Run Investigation',
                                   command=self.start_investigation, style='Run.TButton')
        self.btn_run.pack(side='left', padx=(8, 4), pady=4)

        # Status
        self.lbl_status = ttk.Label(self.toolbar, text='Ready — select a mode and run.',
                                     style='Status.TLabel', padding=(8, 8))
        self.lbl_status.pack(side='left', padx=4)

        # Right side
        self.lbl_integrity = ttk.Label(self.toolbar, text='', style='Integrity.TLabel',
                                        padding=(0, 8))
        self.lbl_integrity.pack(side='right', padx=12)

        ttk.Separator(self.toolbar, orient='vertical').pack(side='right', fill='y', padx=4, pady=4)

        self.btn_theme = ttk.Button(self.toolbar, text='☀  Day Mode',
                                     command=self._toggle_theme, style='Action.TButton')
        self.btn_theme.pack(side='right', padx=8, pady=4)

        # Progress bar (hidden by default, shown during investigation)
        self.progressbar = ttk.Progressbar(
            self.toolbar, mode='indeterminate', length=120, style='TProgressbar')
        self.progressbar.pack(side='left', padx=(8, 0), pady=6)
        self.progressbar.pack_forget()   # hidden until needed

    def _toggle_theme(self):
        TM.toggle()  # fires _on_theme_change via callback

    # ── Tab: Dashboard ─────────────────────────────────────────
    def _build_dashboard_tab(self):
        C = TM.C
        t = self.tab_dashboard
        t.columnconfigure((0, 1, 2, 3), weight=1)
        t.rowconfigure(1, weight=1)

        # KPI cards row
        self.kpi_frames = {}
        self.kpi_value_vars = {}
        self.kpi_sub_vars = {}

        kpi_defs = [
            ('EVENTS ANALYZED',   '—', 'Total forensic events collected', '🔍'),
            ('INCIDENTS FOUND',   '—', 'Correlated security incidents',   '🚨'),
            ('CRITICAL ALERTS',   '—', 'High-severity findings',          '⚠️'),
            ('EVIDENCE INTEGRITY','—', 'Chain-of-custody status',         '🔒'),
        ]
        for i, (title, default, subtitle, icon) in enumerate(kpi_defs):
            card = ttk.Frame(t, style='KPICard.TFrame', padding=(24, 20))
            card.grid(row=0, column=i, sticky='nsew', padx=(12 if i == 0 else 6, 6 if i < 3 else 12), pady=20)
            card.columnconfigure(0, weight=1)

            ttk.Label(card, text=f'{icon}  {title}', style='KPITitle.TLabel').grid(
                row=0, column=0, sticky='w')

            val_var = tk.StringVar(value=default)
            self.kpi_value_vars[title] = val_var
            ttk.Label(card, textvariable=val_var, style='KPIValue.TLabel').grid(
                row=1, column=0, sticky='w', pady=(8, 2))

            sub_var = tk.StringVar(value=subtitle)
            self.kpi_sub_vars[title] = sub_var
            ttk.Label(card, textvariable=sub_var, style='KPISub.TLabel').grid(
                row=2, column=0, sticky='w')

            self.kpi_frames[title] = card

        # Bottom left: severity chart
        chart_outer = ttk.Frame(t, style='KPICard.TFrame', padding=(20, 16))
        chart_outer.grid(row=1, column=0, columnspan=2, sticky='nsew',
                         padx=(12, 6), pady=(0, 16))
        chart_outer.columnconfigure(0, weight=1)
        chart_outer.rowconfigure(1, weight=1)

        ttk.Label(chart_outer, text='SEVERITY DISTRIBUTION', style='KPITitle.TLabel').grid(
            row=0, column=0, sticky='w', pady=(0, 8))

        self.chart_canvas = tk.Canvas(chart_outer, bg=C['bg_card'],
                                       highlightthickness=0, height=180)
        self.chart_canvas.grid(row=1, column=0, sticky='nsew')

        # Bottom right: recent activity
        act_outer = ttk.Frame(t, style='KPICard.TFrame', padding=(20, 16))
        act_outer.grid(row=1, column=2, columnspan=2, sticky='nsew',
                       padx=(6, 12), pady=(0, 16))
        act_outer.columnconfigure(0, weight=1)
        act_outer.rowconfigure(1, weight=1)

        ttk.Label(act_outer, text='RECENT ACTIVITY LOG', style='KPITitle.TLabel').grid(
            row=0, column=0, sticky='w', pady=(0, 8))

        self.txt_activity = tk.Text(act_outer, bg=C['bg'], fg=C['text_muted'],
                                     font=('Consolas', 9), relief='flat',
                                     padx=10, pady=10, cursor='arrow')
        act_scroll = ttk.Scrollbar(act_outer, orient='vertical',
                                    command=self.txt_activity.yview)
        self.txt_activity.configure(yscrollcommand=act_scroll.set)
        self.txt_activity.grid(row=1, column=0, sticky='nsew')
        act_scroll.grid(row=1, column=1, sticky='ns')
        self._log_activity('System initialized. Select a mode and click Run Investigation.')
        self.txt_activity.configure(state='disabled')

    def _log_activity(self, msg):
        ts = datetime.now().strftime('%H:%M:%S')
        self.txt_activity.configure(state='normal')
        self.txt_activity.insert('end', f'[{ts}]  {msg}\n')
        self.txt_activity.see('end')
        self.txt_activity.configure(state='disabled')

    def render_dashboard(self):
        C = TM.C
        findings = self.current_findings
        events   = self.current_events
        integrity = self.current_integrity

        # KPI values
        self.kpi_value_vars['EVENTS ANALYZED'].set(str(len(events)) if events else '—')
        self.kpi_value_vars['INCIDENTS FOUND'].set(str(len(findings)) if findings is not None else '—')
        crit = sum(1 for f in findings if f.severity == 'CRITICAL')
        self.kpi_value_vars['CRITICAL ALERTS'].set(str(crit) if findings else '—')

        int_ok = integrity.get('integrity_intact', None)
        if int_ok is True:
            self.kpi_value_vars['EVIDENCE INTEGRITY'].set('INTACT')
            self.kpi_sub_vars['EVIDENCE INTEGRITY'].set('All hashes verified ✓')
        elif int_ok is False:
            self.kpi_value_vars['EVIDENCE INTEGRITY'].set('TAMPERED')
            self.kpi_sub_vars['EVIDENCE INTEGRITY'].set('Hash mismatch detected!')
        else:
            self.kpi_value_vars['EVIDENCE INTEGRITY'].set('—')
            self.kpi_sub_vars['EVIDENCE INTEGRITY'].set('Run an investigation first')

        # Severity chart
        c = self.chart_canvas
        c.delete('all')
        c.update_idletasks()
        w = c.winfo_width() or 400

        if not findings:
            c.create_text(w // 2, 80, text='No data  —  run an investigation to see results.',
                          fill=C['text_subtle'], font=('Segoe UI', 10))
            return

        counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for f in findings:
            if f.severity in counts:
                counts[f.severity] += 1

        max_val = max(counts.values()) or 1
        n = len(counts)
        pad_l, pad_r, pad_t, pad_b = 30, 20, 16, 36
        usable_w = w - pad_l - pad_r
        bar_w = max(20, usable_w // (n * 2) - 4)
        gap    = usable_w // n
        base_y = 180 - pad_b
        max_h  = base_y - pad_t

        for idx, sev in enumerate(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']):
            count = counts[sev]
            h = (count / max_val) * max_h if count > 0 else 4
            x = pad_l + idx * gap + (gap - bar_w) // 2
            color = TM.severity(sev)

            # Bar with rounded top (fake: two rects)
            c.create_rectangle(x, base_y - h, x + bar_w, base_y,
                                fill=color, outline='', width=0)
            # Value above bar
            c.create_text(x + bar_w // 2, base_y - h - 10,
                          text=str(count), fill=C['text'],
                          font=('Segoe UI', 10, 'bold'))
            # Label below
            c.create_text(x + bar_w // 2, base_y + 14,
                          text=sev, fill=C['text_muted'],
                          font=('Segoe UI', 8, 'bold'))
            # Baseline
            c.create_line(pad_l, base_y, w - pad_r, base_y,
                          fill=C['border'], width=1)

    # ── Tab: Incidents ─────────────────────────────────────────
    def _build_incidents_tab(self):
        C = TM.C
        t = self.tab_incidents
        t.columnconfigure(0, weight=1)
        t.rowconfigure(0, weight=1)

        paned = ttk.PanedWindow(t, orient='horizontal')
        paned.grid(row=0, column=0, sticky='nsew', padx=0, pady=0)

        # Left: incident list
        list_frame = ttk.Frame(paned)
        paned.add(list_frame, weight=1)
        list_frame.columnconfigure(0, weight=1)
        list_frame.rowconfigure(1, weight=1)

        ttk.Label(list_frame, text='Detected Incidents',
                  font=('Segoe UI', 10, 'bold'), padding=(12, 8)).grid(
            row=0, column=0, sticky='w')

        self.tree = ttk.Treeview(
            list_frame,
            columns=('id', 'rule', 'severity', 'mitre', 'conf', 'cause'),
            show='headings', style='Forensic.Treeview'
        )
        headings = [('#', 'id', 32), ('Rule ID', 'rule', 80), ('Severity', 'severity', 78),
                    ('MITRE', 'mitre', 90), ('Conf.', 'conf', 50), ('Root Cause', 'cause', 0)]
        for label, col, w in headings:
            self.tree.heading(col, text=label, anchor='w')
            kw = {'width': w, 'stretch': False} if w else {'stretch': True}
            self.tree.column(col, anchor='w', **kw)

        vsb = ttk.Scrollbar(list_frame, orient='vertical', command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.grid(row=1, column=0, sticky='nsew')
        vsb.grid(row=1, column=1, sticky='ns')
        self.tree.bind('<<TreeviewSelect>>', self._on_incident_select)

        # Severity row tags
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            self.tree.tag_configure(f'sev_{sev}',
                                    foreground=TM.severity(sev),
                                    font=('Segoe UI', 9, 'bold'))

        # Right: details panel
        detail_frame = ttk.Frame(paned)
        paned.add(detail_frame, weight=2)
        detail_frame.columnconfigure(0, weight=1)
        detail_frame.rowconfigure(1, weight=1)

        ttk.Label(detail_frame, text='Evidence Details',
                  font=('Segoe UI', 10, 'bold'), padding=(12, 8)).grid(
            row=0, column=0, sticky='w')

        self.txt_details = tk.Text(detail_frame, wrap='word', state='disabled',
                                    bg=C['bg'], fg=C['text'],
                                    insertbackground=C['text'],
                                    selectbackground=C['accent'],
                                    font=('Consolas', 10), relief='flat',
                                    padx=16, pady=12, cursor='arrow')
        vsb2 = ttk.Scrollbar(detail_frame, orient='vertical',
                              command=self.txt_details.yview)
        self.txt_details.configure(yscrollcommand=vsb2.set)
        self.txt_details.grid(row=1, column=0, sticky='nsew')
        vsb2.grid(row=1, column=1, sticky='ns')
        self._configure_text_tags(self.txt_details)

    def _configure_text_tags(self, widget):
        C = TM.C
        widget.tag_configure('h1',     foreground=C['accent'],    font=('Segoe UI', 13, 'bold'))
        widget.tag_configure('h2',     foreground=C['text'],      font=('Segoe UI', 11, 'bold'))
        widget.tag_configure('label',  foreground=C['text_muted'],font=('Segoe UI', 9,  'bold'))
        widget.tag_configure('value',  foreground=C['text'],      font=('Segoe UI', 10))
        widget.tag_configure('mono',   foreground=C['text_muted'],font=('Consolas', 9))
        widget.tag_configure('hash',   foreground=C['text_subtle'],font=('Consolas', 8))
        widget.tag_configure('divider',foreground=C['border'],    font=('Consolas', 8))
        widget.tag_configure('intact',      foreground=C['green'], font=('Segoe UI', 10, 'bold'))
        widget.tag_configure('compromised', foreground=C['red'],   font=('Segoe UI', 10, 'bold'))
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            widget.tag_configure(f'sev_{sev}', foreground=TM.severity(sev),
                                 font=('Segoe UI', 10, 'bold'))

    def _on_incident_select(self, _event):
        sel = self.tree.selection()
        if not sel:
            return

        if self._history_mode:
            # ── History drill-down ──
            iid = sel[0]
            full_id = self._history_id_map.get(iid, iid)
            self._render_history_detail(full_id)
            return

        # ── Normal incident detail ──
        if not self.current_findings:
            return
        try:
            idx = int(sel[0])
        except (ValueError, TypeError):
            return
        if not (0 <= idx < len(self.current_findings)):
            return

        inc = self.current_findings[idx]
        t = self.txt_details
        t.configure(state='normal')
        t.delete('1.0', 'end')

        rule_id = getattr(inc, 'rule_id', 'UNKNOWN')
        t.insert('end', f'Incident #{idx + 1}  —  {rule_id}\n', 'h1')
        t.insert('end', '─' * 64 + '\n\n', 'divider')

        mitre  = getattr(inc, 'mitre_id',   'N/A')
        conf   = getattr(inc, 'confidence', None)
        fields = [
            ('Severity',     inc.severity),
            ('MITRE ATT&CK', mitre),
            ('Confidence',   f'{conf * 100:.0f}%' if conf is not None else 'N/A'),
            ('Root Cause',   inc.root_cause),
        ]
        for lbl, val in fields:
            t.insert('end', f'  {lbl:<18s}  ', 'label')
            tag = f'sev_{inc.severity}' if lbl == 'Severity' else 'value'
            t.insert('end', f'{val}\n', tag)

        t.insert('end', f'\n  Evidence Timeline  ({len(inc.timeline)} events)\n', 'h2')
        t.insert('end', '─' * 64 + '\n', 'divider')

        for ev in inc.timeline:
            ts = ev.timestamp.strftime('%Y-%m-%d %H:%M:%S') if hasattr(ev.timestamp, 'strftime') else str(ev.timestamp)
            t.insert('end', f'\n  [{ts}]  ', 'mono')
            t.insert('end', f'[{ev.source}]  {ev.event_type}\n', 'value')
            t.insert('end', f'  {ev.details}\n', 'mono')
            if ev.evidence_hash:
                t.insert('end', f'  SHA-256: {ev.evidence_hash}\n', 'hash')
            t.insert('end', '  ' + '·' * 60 + '\n', 'divider')

        t.configure(state='disabled')

    def _render_history_detail(self, full_id: str):
        """Load a past investigation from DB and display its summary in the details panel."""
        t = self.txt_details
        t.configure(state='normal')
        t.delete('1.0', 'end')
        t.insert('end', f'Loading investigation {full_id}…\n', 'mono')
        t.configure(state='disabled')
        self.update_idletasks()

        def _load():
            try:
                db  = ForensicDatabase()
                inv = db.load_investigation(full_id)
            except Exception as ex:
                self.after(0, lambda: self._show_detail_error(str(ex)))
                return
            self.after(0, lambda: self._render_history_inv(inv))

        threading.Thread(target=_load, daemon=True).start()

    def _show_detail_error(self, msg: str):
        t = self.txt_details
        t.configure(state='normal')
        t.delete('1.0', 'end')
        t.insert('end', f'Error loading investigation:\n{msg}', 'mono')
        t.configure(state='disabled')

    def _render_history_inv(self, inv: dict):
        """Render a loaded investigation dict into the Evidence Details panel."""
        if not inv:
            self._show_detail_error('Investigation not found in database.')
            return

        findings = inv.get('findings', [])
        events   = inv.get('events', [])

        t = self.txt_details
        t.configure(state='normal')
        t.delete('1.0', 'end')

        t.insert('end', f'Investigation  {inv["id"]}\n', 'h1')
        t.insert('end', '─' * 64 + '\n\n', 'divider')

        for lbl, val in [
            ('Timestamp',    inv.get('timestamp', '')[:19]),
            ('Mode',         inv.get('mode', '').upper()),
            ('Events',       str(inv.get('event_count', len(events)))),
            ('Incidents',    str(inv.get('finding_count', len(findings)))),
            ('Duration',     f'{inv.get("duration_seconds", 0):.2f} s'),
        ]:
            t.insert('end', f'  {lbl:<20s}  ', 'label')
            t.insert('end', f'{val}\n', 'value')

        rh = inv.get('root_hash', '')
        if rh:
            t.insert('end', f'  {"Merkle Root":<20s}  ', 'label')
            t.insert('end', f'{rh[:48]}\u2026\n', 'mono')

        t.insert('end', '\n')

        if findings:
            t.insert('end', f'Incidents  ({len(findings)} detected)\n', 'h2')
            t.insert('end', '─' * 64 + '\n', 'divider')
            for i, f in enumerate(findings, 1):
                rule_id = getattr(f, 'rule_id', '—')
                mitre   = getattr(f, 'mitre_id', '—')
                conf    = getattr(f, 'confidence', None)
                t.insert('end', f'\n  #{i}  {rule_id}\n', 'h2')
                t.insert('end', f'  {"Severity":<18s}  ', 'label')
                t.insert('end', f'{f.severity}\n', f'sev_{f.severity}')
                for lbl, val in [
                    ('MITRE', mitre),
                    ('Confidence', f'{conf * 100:.0f}%' if conf is not None else 'N/A'),
                    ('Root Cause', f.root_cause),
                ]:
                    t.insert('end', f'  {lbl:<18s}  ', 'label')
                    t.insert('end', f'{val}\n', 'value')
                t.insert('end', f'\n  Evidence  ({len(f.timeline)} event(s))\n', 'label')
                for ev in f.timeline:
                    ts = ev.timestamp.strftime('%Y-%m-%d %H:%M:%S') \
                         if hasattr(ev.timestamp, 'strftime') else str(ev.timestamp)
                    t.insert('end', f'    [{ts}]  [{ev.source}]  {ev.event_type}\n', 'mono')
                    t.insert('end', f'    {ev.details}\n', 'hash')
                t.insert('end', '  ' + '─' * 60 + '\n', 'divider')
        else:
            t.insert('end', '  No incidents recorded for this investigation.\n', 'value')

        if events:
            t.insert('end', f'\nAll Events  ({len(events)} total)\n', 'h2')
            t.insert('end', '─' * 64 + '\n', 'divider')
            for ev in events[:50]:  # cap at 50 for readability
                ts = ev.timestamp.strftime('%H:%M:%S') if hasattr(ev.timestamp, 'strftime') else str(ev.timestamp)[:8]
                t.insert('end', f'  [{ts}]  [{ev.source}]  {ev.event_type}\n', 'mono')
            if len(events) > 50:
                t.insert('end', f'  … and {len(events) - 50} more events.\n', 'hash')

        t.configure(state='disabled')

    # ── Tab: Timeline ──────────────────────────────────────────
    def _build_timeline_tab(self):
        C = TM.C
        t = self.tab_timeline
        t.columnconfigure(0, weight=1)
        t.rowconfigure(0, weight=1)

        wrapper = ttk.Frame(t)
        wrapper.grid(row=0, column=0, sticky='nsew')
        wrapper.columnconfigure(0, weight=1)
        wrapper.rowconfigure(0, weight=1)

        self.timeline_canvas = tk.Canvas(wrapper, bg=C['bg'], highlightthickness=0)
        vsb = ttk.Scrollbar(wrapper, orient='vertical', command=self.timeline_canvas.yview)
        self.timeline_canvas.configure(yscrollcommand=vsb.set)
        self.timeline_canvas.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        self.timeline_canvas.bind('<MouseWheel>',
            lambda e: self.timeline_canvas.yview_scroll(-1 * (e.delta // 120), 'units'))

        # Legend bar
        leg = ttk.Frame(t)
        leg.grid(row=1, column=0, sticky='ew', padx=16, pady=(4, 8))
        ttk.Label(leg, text='Legend:', font=('Segoe UI', 8, 'bold'),
                  foreground=TM.C['text_muted']).pack(side='left', padx=(0, 12))
        for txt, key in [('● Malicious', 'red'), ('● Benign', 'green'),
                         ('● Infrastructure', 'accent'), ('● CI / Build', 'orange')]:
            tk.Label(leg, text=txt, bg=TM.C['bg'], fg=TM.C[key],
                     font=('Segoe UI', 9)).pack(side='left', padx=10)

    def render_timeline(self):
        C = TM.C
        c = self.timeline_canvas
        c.delete('all')
        events   = self.current_events
        findings = self.current_findings

        if not events:
            c.create_text(400, 60, text='No events to display.  Run an investigation first.',
                          fill=C['text_subtle'], font=('Segoe UI', 11))
            return

        mal_set = set()
        ev_finding = {}
        for f in findings:
            for e in f.timeline:
                mal_set.add(id(e))
                ev_finding[id(e)] = f

        x_line   = 100
        y_start  = 40
        row_h    = 82
        total_h  = y_start + len(events) * row_h + 40

        c.create_line(x_line, 10, x_line, total_h, fill=C['border'], width=2, dash=(4, 4))

        for i, e in enumerate(events):
            y       = y_start + i * row_h
            is_mal  = id(e) in mal_set
            finding = ev_finding.get(id(e))

            # Node dot
            r = 7
            nc = C['red'] if is_mal else TM.source_color(e.source)
            c.create_oval(x_line - r, y - r, x_line + r, y + r,
                          fill=nc, outline=C['bg'], width=2)

            # Timestamp
            ts = e.timestamp.strftime('%H:%M:%S') if hasattr(e.timestamp, 'strftime') else str(e.timestamp)[:8]
            c.create_text(x_line - 14, y, text=ts, anchor='e',
                          fill=C['text_muted'], font=('Consolas', 8))

            # Card
            cx   = x_line + 24
            cw   = max(700, c.winfo_width() - cx - 20)
            ch   = 60
            bg_c = C['bg_card'] if is_mal else C['bg_secondary']
            bd_c = C['red']    if is_mal else C['border']

            c.create_rectangle(cx, y - ch // 2, cx + cw, y + ch // 2,
                                fill=bg_c, outline=bd_c, width=1)
            if is_mal:
                c.create_rectangle(cx, y - ch // 2, cx + 4, y + ch // 2,
                                   fill=C['red'], outline='')

            # Source + type
            src_c = C['red'] if is_mal else TM.source_color(e.source)
            c.create_text(cx + 14, y - 13, text=e.source, anchor='w',
                          fill=src_c, font=('Segoe UI', 9, 'bold'))
            c.create_text(cx + 140, y - 13, text=e.event_type, anchor='w',
                          fill=C['text'], font=('Segoe UI', 9))
            # Details
            dtl = e.details[:110] + ('…' if len(e.details) > 110 else '')
            c.create_text(cx + 14, y + 7, text=dtl, anchor='w',
                          fill=C['text_muted'], font=('Consolas', 8))
            # Hash
            if e.evidence_hash:
                c.create_text(cx + 14, y + 21, text=f'SHA-256: {e.evidence_hash[:28]}…',
                              anchor='w', fill=C['text_subtle'], font=('Consolas', 7))

            # Finding badge (right)
            if finding:
                badge = f'{finding.rule_id}  ·  {finding.mitre_id}  ·  {finding.severity}'
                c.create_text(cx + cw - 14, y - 13, text=badge, anchor='e',
                              fill=TM.severity(finding.severity),
                              font=('Segoe UI', 8, 'bold'))
                c.create_text(cx + cw - 14, y + 7,
                              text=f'{finding.confidence * 100:.0f}% confidence',
                              anchor='e', fill=C['text_muted'], font=('Segoe UI', 8))

        c.configure(scrollregion=(0, 0, 1200, total_h))

    # ── Tab: Report ────────────────────────────────────────────
    def _build_report_tab(self):
        C = TM.C
        t = self.tab_report
        t.columnconfigure(0, weight=1)
        t.rowconfigure(0, weight=1)

        self.txt_report = tk.Text(t, wrap='word', state='disabled',
                                   bg=C['bg'], fg=C['text'],
                                   insertbackground=C['text'],
                                   selectbackground=C['accent'],
                                   font=('Segoe UI', 10), relief='flat',
                                   padx=32, pady=24, cursor='arrow')
        vsb = ttk.Scrollbar(t, orient='vertical', command=self.txt_report.yview)
        self.txt_report.configure(yscrollcommand=vsb.set)
        self.txt_report.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        self._configure_report_tags(self.txt_report)

    def _configure_report_tags(self, w):
        C = TM.C
        w.tag_configure('title',    foreground=C['accent'],  font=('Segoe UI', 18, 'bold'))
        w.tag_configure('section',  foreground=C['accent'],  font=('Segoe UI', 12, 'bold'))
        w.tag_configure('subtitle', foreground=C['text'],    font=('Segoe UI', 11, 'bold'))
        w.tag_configure('label',    foreground=C['text_muted'], font=('Segoe UI', 9, 'bold'))
        w.tag_configure('value',    foreground=C['text'],    font=('Segoe UI', 10))
        w.tag_configure('mono',     foreground=C['text_muted'], font=('Consolas', 9))
        w.tag_configure('intact',   foreground=C['green'],   font=('Segoe UI', 10, 'bold'))
        w.tag_configure('tampered', foreground=C['red'],     font=('Segoe UI', 10, 'bold'))
        w.tag_configure('evidence', foreground=C['text_muted'], font=('Consolas', 9))
        w.tag_configure('divider',  foreground=C['border'],  font=('Consolas', 8))
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            w.tag_configure(f'sev_{sev}', foreground=TM.severity(sev),
                            font=('Segoe UI', 10, 'bold'))

    def render_report(self):
        t        = self.txt_report
        findings = self.current_findings
        events   = self.current_events
        integrity= self.current_integrity
        custody  = self.current_custody
        inv_id   = self.current_inv_id
        duration = self.current_duration

        t.configure(state='normal')
        t.delete('1.0', 'end')

        t.insert('end', 'DPFF Forensic Investigation Report\n', 'title')
        t.insert('end', f'Generated {datetime.now().strftime("%Y-%m-%d  %H:%M:%S")}    '
                         f'Investigation ID: {inv_id or "—"}\n\n', 'mono')

        t.insert('end', 'Summary\n', 'section')
        t.insert('end', '─' * 72 + '\n', 'divider')
        for lbl, val in [
            ('Events Analyzed',  str(len(events))),
            ('Incidents Detected', str(len(findings))),
            ('Analysis Duration', f'{duration:.2f} s'),
            ('Evidence Sources',  str(len(set(e.source for e in events))) if events else '0'),
        ]:
            t.insert('end', f'  {lbl:<28s}  ', 'label')
            t.insert('end', f'{val}\n', 'value')

        t.insert('end', f'  {"Evidence Integrity":<28s}  ', 'label')
        if integrity.get('integrity_intact'):
            t.insert('end', '✓ INTACT\n', 'intact')
        else:
            t.insert('end', '✗ TAMPERED\n', 'tampered')

        if custody.get('root_hash'):
            t.insert('end', f'  {"Merkle Root Hash":<28s}  ', 'label')
            t.insert('end', f'{custody["root_hash"][:48]}…\n', 'mono')

        t.insert('end', '\n')

        if findings:
            t.insert('end', f'Detected Incidents  ({len(findings)} total)\n', 'section')
            t.insert('end', '─' * 72 + '\n\n', 'divider')
            for i, f in enumerate(findings, 1):
                t.insert('end', f'  Incident #{i}  ·  {f.rule_id}\n', 'subtitle')
                t.insert('end', f'  {"Severity":<20s}  ', 'label')
                t.insert('end', f'{f.severity}\n', f'sev_{f.severity}')
                for lbl, val in [('MITRE ATT&CK', f.mitre_id),
                                  ('Confidence', f'{f.confidence * 100:.0f}%'),
                                  ('Root Cause', f.root_cause)]:
                    t.insert('end', f'  {lbl:<20s}  ', 'label')
                    t.insert('end', f'{val}\n', 'value')
                t.insert('end', f'\n  Evidence ({len(f.timeline)} events)\n', 'label')
                for ev in f.timeline:
                    ts = ev.timestamp.strftime('%Y-%m-%d %H:%M:%S') \
                         if hasattr(ev.timestamp, 'strftime') else str(ev.timestamp)
                    t.insert('end', f'    [{ts}]  [{ev.source}]  {ev.event_type}\n', 'mono')
                    t.insert('end', f'    {ev.details}\n', 'evidence')
                t.insert('end', '\n  ' + '─' * 68 + '\n\n', 'divider')
        else:
            t.insert('end', '  ✓  No security incidents detected.  Pipeline is clean.\n', 'intact')

        t.insert('end', 'Export Files\n', 'section')
        t.insert('end', '─' * 72 + '\n', 'divider')
        for lbl, path in [('HTML Report', 'forensic_report.html'),
                           ('Interactive Timeline', 'forensic_timeline.html'),
                           ('JSON Export', 'forensic_export.json'),
                           ('STIX 2.1 Bundle', 'forensic_export_stix.json')]:
            exists = '✓' if os.path.exists(path) else '✗'
            t.insert('end', f'  {exists}  {lbl:<26s}  ', 'label')
            t.insert('end', f'{path}\n', 'mono')

        t.configure(state='disabled')

    # ── Config Panel ───────────────────────────────────────────
    def _build_config_panel(self):
        p = self.frame_config
        for col in range(4):
            p.columnconfigure(col, weight=1)

        def grp(title, col):
            f = ttk.LabelFrame(p, text=f'  {title}  ', style='Group.TLabelframe', padding=(14, 10))
            f.grid(row=0, column=col, sticky='nsew', padx=(0 if col > 0 else 0, 8), pady=4)
            f.columnconfigure(1, weight=1)
            return f

        def row(parent, r, label, widget, padtop=4):
            ttk.Label(parent, text=label, font=('Segoe UI', 9)
                      ).grid(row=r, column=0, sticky='w', pady=(padtop, 0), padx=(0, 8))
            widget.grid(row=r, column=1, sticky='ew', pady=(padtop, 0))

        def entry(parent, default='', show=''):
            e = ttk.Entry(parent, show=show)
            if default:
                e.insert(0, default)
            return e

        def toggle_show(e):
            e.configure(show='' if e.cget('show') == '*' else '*')

        # ── Source Control ──
        g = grp('Source Control  (GitHub / Gitea)', 0)
        g.columnconfigure(1, weight=1)
        self.var_gh = tk.BooleanVar(value=True)
        ttk.Checkbutton(g, text='Enable', variable=self.var_gh).grid(
            row=0, column=0, columnspan=2, sticky='w')
        self.ent_gh_url   = entry(g, 'http://localhost:3000')
        self.ent_gh_org   = entry(g, 'dpff-lab')
        self.ent_gh_token = entry(g, show='*')
        self.ent_gh_token.insert(0, 'dpff-lab-2024')  # lab default
        row(g, 1, 'Base URL', self.ent_gh_url,   padtop=8)
        row(g, 2, 'Org / User', self.ent_gh_org)
        row(g, 3, 'API Token', self.ent_gh_token)
        ttk.Button(g, text='👁', style='Eye.TButton',
                   command=lambda: toggle_show(self.ent_gh_token)).grid(
            row=3, column=2, padx=(4, 0), pady=(4, 0))

        # ── CI Server ──
        g2 = grp('CI Server  (Jenkins)', 1)
        self.var_jen = tk.BooleanVar(value=True)
        ttk.Checkbutton(g2, text='Enable', variable=self.var_jen).grid(
            row=0, column=0, columnspan=2, sticky='w')
        self.ent_jen_url   = entry(g2, 'http://localhost:9090')
        self.ent_jen_user  = entry(g2, 'admin')  # lab default
        self.ent_jen_token = entry(g2, show='*')
        self.ent_jen_token.insert(0, 'admin')        # lab default
        row(g2, 1, 'Jenkins URL', self.ent_jen_url,   padtop=8)
        row(g2, 2, 'Username',    self.ent_jen_user)
        row(g2, 3, 'API Token',   self.ent_jen_token)
        ttk.Button(g2, text='👁', style='Eye.TButton',
                   command=lambda: toggle_show(self.ent_jen_token)).grid(
            row=3, column=2, padx=(4, 0), pady=(4, 0))

        # ── Registry ──
        g3 = grp('Registry  (Harbor)', 2)
        self.var_har = tk.BooleanVar(value=True)
        ttk.Checkbutton(g3, text='Enable', variable=self.var_har).grid(
            row=0, column=0, columnspan=2, sticky='w')
        self.ent_har_url  = entry(g3, 'https://harbor.local')
        self.ent_har_user = entry(g3)
        self.ent_har_pass = entry(g3, show='*')
        row(g3, 1, 'Registry URL', self.ent_har_url,  padtop=8)
        row(g3, 2, 'Username',     self.ent_har_user)
        row(g3, 3, 'Password',     self.ent_har_pass)
        ttk.Button(g3, text='👁', style='Eye.TButton',
                   command=lambda: toggle_show(self.ent_har_pass)).grid(
            row=3, column=2, padx=(4, 0), pady=(4, 0))

        # ── Runtime ──
        g4 = grp('Runtime  &  Settings', 3)
        self.var_k8s = tk.BooleanVar(value=True)
        self.var_doc = tk.BooleanVar(value=True)
        ttk.Checkbutton(g4, text='Kubernetes', variable=self.var_k8s).grid(
            row=0, column=0, sticky='w')
        ttk.Checkbutton(g4, text='Docker',     variable=self.var_doc).grid(
            row=1, column=0, sticky='w', pady=(2, 8))
        ttk.Separator(g4, orient='horizontal').grid(row=2, column=0, columnspan=2, sticky='ew', pady=6)
        self.ent_days        = entry(g4, '7')
        self.ent_report_path = entry(g4, 'forensic_report.html')
        row(g4, 3, 'Lookback (days)', self.ent_days,        padtop=4)
        row(g4, 4, 'Report filename', self.ent_report_path, padtop=4)
        ttk.Button(g4, text='📂', style='Eye.TButton',
                   command=self._browse_report_path).grid(
            row=4, column=2, padx=(4, 0), pady=(4, 0))

        # One-click lab defaults
        ttk.Button(g4, text='⟳  Load Lab Defaults', style='Action.TButton',
                   command=self._load_lab_defaults).grid(
            row=5, column=0, columnspan=2, sticky='ew', pady=(10, 0))

    def _toggle_config_panel(self, *_):
        if self.mode_var.get() == 'analyze':
            self.frame_config.grid()
        else:
            self.frame_config.grid_remove()

    def _browse_report_path(self):
        """Open a Save-As dialog to pick the HTML report output path."""
        default_dir = os.path.join(os.path.expanduser('~'), 'Documents', 'DPFF')
        os.makedirs(default_dir, exist_ok=True)
        path = filedialog.asksaveasfilename(
            title='Save Report As',
            initialdir=default_dir,
            initialfile='forensic_report.html',
            defaultextension='.html',
            filetypes=[('HTML Report', '*.html'), ('All files', '*.*')]
        )
        if path:
            self.ent_report_path.delete(0, 'end')
            self.ent_report_path.insert(0, path)

    def _load_env_vars(self):
        """Load credentials from environment variables (overrides defaults)."""
        for var, ent in [
            ('GITHUB_TOKEN',  self.ent_gh_token),
            ('GITEA_URL',     self.ent_gh_url),
            ('JENKINS_USER',  self.ent_jen_user),
            ('JENKINS_TOKEN', self.ent_jen_token),
            ('HARBOR_USER',   self.ent_har_user),
            ('HARBOR_PASS',   self.ent_har_pass),
        ]:
            val = os.getenv(var, '')
            if val:
                ent.delete(0, 'end')
                ent.insert(0, val)

    def _load_lab_defaults(self):
        """One-click fill with known .env.lab values."""
        defaults = {
            self.ent_gh_url:    'http://localhost:3000',
            self.ent_gh_org:    'dpff-lab',
            self.ent_gh_token:  'dpff-lab-2024',
            self.ent_jen_url:   'http://localhost:9090',
            self.ent_jen_user:  'admin',
            self.ent_jen_token: 'admin',
            self.ent_har_url:   'https://harbor.local',
        }
        for ent, val in defaults.items():
            ent.delete(0, 'end')
            ent.insert(0, val)
        self.ent_har_user.delete(0, 'end')
        self.ent_har_pass.delete(0, 'end')
        self.var_har.set(False)   # Harbor disabled in lab
        self.var_k8s.set(False)   # Kubernetes disabled in lab
        self.var_doc.set(True)
        self._log_activity('Lab defaults loaded from .env.lab')

    def _save_settings(self):
        """Collect all config panel values and persist to ~/.dpff/settings.json."""
        data = {
            'theme': TM.mode,
            'mode':  self.mode_var.get(),
            'github': {
                'enabled': self.var_gh.get(),
                'url':     self.ent_gh_url.get(),
                'org':     self.ent_gh_org.get(),
                'token':   self.ent_gh_token.get(),
            },
            'jenkins': {
                'enabled': self.var_jen.get(),
                'url':     self.ent_jen_url.get(),
                'user':    self.ent_jen_user.get(),
                'token':   self.ent_jen_token.get(),
            },
            'harbor': {
                'enabled':  self.var_har.get(),
                'url':      self.ent_har_url.get(),
                'user':     self.ent_har_user.get(),
                'password': self.ent_har_pass.get(),
            },
            'runtime': {
                'kubernetes':    self.var_k8s.get(),
                'docker':        self.var_doc.get(),
                'lookback_days': self.ent_days.get(),
                'report_path':   self.ent_report_path.get(),
            },
        }
        _save_raw_settings(data)

    def _load_settings(self):
        """Apply persisted settings to all config panel widgets."""
        s = _load_raw_settings()

        # Theme
        saved_theme = s.get('theme', 'dark')
        if saved_theme != TM.mode:
            TM.toggle()

        # Mode combo
        self.mode_var.set(s.get('mode', 'simulate'))

        # GitHub
        gh = s.get('github', {})
        self.var_gh.set(gh.get('enabled', True))
        for ent, key, default in [
            (self.ent_gh_url,   'url',   'http://localhost:3000'),
            (self.ent_gh_org,   'org',   'dpff-lab'),
            (self.ent_gh_token, 'token', 'dpff-lab-2024'),
        ]:
            ent.delete(0, 'end')
            ent.insert(0, gh.get(key, default))

        # Jenkins
        jen = s.get('jenkins', {})
        self.var_jen.set(jen.get('enabled', True))
        for ent, key, default in [
            (self.ent_jen_url,   'url',   'http://localhost:9090'),
            (self.ent_jen_user,  'user',  'admin'),
            (self.ent_jen_token, 'token', 'admin'),
        ]:
            ent.delete(0, 'end')
            ent.insert(0, jen.get(key, default))

        # Harbor
        har = s.get('harbor', {})
        self.var_har.set(har.get('enabled', False))
        for ent, key, default in [
            (self.ent_har_url,  'url',      'https://harbor.local'),
            (self.ent_har_user, 'user',     ''),
            (self.ent_har_pass, 'password', ''),
        ]:
            ent.delete(0, 'end')
            ent.insert(0, har.get(key, default))

        # Runtime
        rt = s.get('runtime', {})
        self.var_k8s.set(rt.get('kubernetes', False))
        self.var_doc.set(rt.get('docker', True))
        for ent, key, default in [
            (self.ent_days,        'lookback_days', '7'),
            (self.ent_report_path, 'report_path',   'forensic_report.html'),
        ]:
            ent.delete(0, 'end')
            ent.insert(0, rt.get(key, default))

        self._log_activity(f'Settings loaded from {SETTINGS_FILE}')

    def _on_close(self):
        """Save settings then destroy the window."""
        self._save_settings()
        self.destroy()


    def start_investigation(self):
        mode = self.mode_var.get()
        if mode == 'history':
            self._show_history()
            return

        if mode == 'analyze':
            # Propagate all credentials to environment so collectors can read them
            os.environ['GITHUB_TOKEN']  = self.ent_gh_token.get()
            os.environ['GITEA_USER']    = 'dpff-admin'  # Gitea admin user for basic auth
            os.environ['GITEA_PASS']    = self.ent_gh_token.get()
            os.environ['JENKINS_USER']  = self.ent_jen_user.get()
            os.environ['JENKINS_TOKEN'] = self.ent_jen_token.get()
            os.environ['HARBOR_USER']   = self.ent_har_user.get()
            os.environ['HARBOR_PASS']   = self.ent_har_pass.get()

        self.btn_run.configure(state='disabled')
        self.lbl_status.configure(text='⏳  Running investigation…', foreground=TM.C['orange'])
        self.lbl_integrity.configure(text='')
        self._log_activity(f'Investigation started  (mode: {mode})')
        # Show + start progress bar
        self.progressbar.pack(side='left', padx=(8, 0), pady=6)
        self.progressbar.start(12)

        threading.Thread(target=self._run_thread, args=(mode,), daemon=True).start()

    def _run_thread(self, mode):
        try:
            t0 = time.time()

            class Args:
                config = 'config.yaml'

            def _status(msg):
                """Post a message to the Activity Log from the worker thread."""
                self.after(0, lambda m=msg: self._log_activity(m))

            if mode == 'simulate':
                events = run_simulation(Args())
                _status(f'Simulation: {len(events)} events loaded')
            else:
                def _collect(collector, name):
                    """Run a single collector, log result or error."""
                    try:
                        result = collector.collect()
                        _status(f'✓  {name}: {len(result)} event(s)')
                        return result
                    except Exception as exc:
                        _status(f'✗  {name}: FAILED — {exc}')
                        return []

                override = {
                    'collector_settings': {
                        'github':     {'enabled': self.var_gh.get(),  'org': self.ent_gh_org.get(),
                                       'base_url': self.ent_gh_url.get(), 'token': self.ent_gh_token.get()},
                        'jenkins':    {'enabled': self.var_jen.get(), 'url': self.ent_jen_url.get(),
                                       'user': self.ent_jen_user.get()},
                        'harbor':     {'enabled': self.var_har.get(), 'url': self.ent_har_url.get()},
                        'kubernetes': {'enabled': self.var_k8s.get()},
                        'docker':     {'enabled': self.var_doc.get()},
                    },
                    'analysis_settings': {'lookback_days': int(self.ent_days.get() or 7)},
                }
                cs = override['collector_settings']
                from src.collectors.github import GitHubCollector
                from src.collectors.jenkins import JenkinsCollector
                from src.collectors.harbor import HarborCollector
                from src.collectors.kubernetes import KubernetesCollector
                from src.collectors.docker_collector import DockerCollector
                from src.integrity import hash_events
                events = []
                events += _collect(GitHubCollector(cs),     'GitHub/Gitea')
                events += _collect(JenkinsCollector(cs),    'Jenkins')
                events += _collect(HarborCollector(cs),     'Harbor')
                events += _collect(KubernetesCollector(cs), 'Kubernetes')
                events += _collect(DockerCollector(cs),     'Docker')
                hash_events(events)
                _status(f'Collection complete — {len(events)} total events')

            findings = analyze_events(events)
            duration = time.time() - t0
            integrity = verify_all(events)
            custody   = generate_chain_of_custody(events) if events else {}

            db     = ForensicDatabase()
            inv_id = db.save_investigation(
                mode=mode, events=events, findings=findings,
                root_hash=custody.get('root_hash', ''), duration_seconds=duration
            )

            try:
                HtmlReporter(self.ent_report_path.get() or 'forensic_report.html').generate(findings)
                TimelineReporter('forensic_timeline.html').generate(events, findings)
                JsonExporter('forensic_export.json').export(
                    events=events, findings=findings, investigation_id=inv_id,
                    mode=mode, duration=duration, integrity=integrity, custody=custody)
                StixExporter('forensic_export_stix.json').export(
                    events=events, findings=findings, investigation_id=inv_id)
            except Exception:
                pass

            self.after(0, lambda: self._on_results(findings, events, integrity, custody, inv_id, duration))

        except Exception as ex:
            self.after(0, lambda: messagebox.showerror('Investigation Error', str(ex)))
            self.after(0, lambda: self.btn_run.configure(state='normal'))
            self.after(0, lambda: self.lbl_status.configure(
                text='Error during investigation.', foreground=TM.C['red']))
        finally:
            self.after(0, self._stop_progress)

    def _stop_progress(self):
        """Stop and hide the progress bar."""
        self.progressbar.stop()
        self.progressbar.pack_forget()

    def _on_results(self, findings, events, integrity, custody, inv_id, duration):
        self._history_mode = False       # back to normal incident-select mode
        self.current_findings = findings
        self.current_events   = events
        self.current_integrity= integrity
        self.current_custody  = custody
        self.current_inv_id   = inv_id
        self.current_duration = duration

        # Update incident list
        self.tree.delete(*self.tree.get_children())
        for i, f in enumerate(findings):
            tag = f'sev_{f.severity}'
            self.tree.insert('', 'end', iid=i,
                             values=(i + 1, f.rule_id, f.severity, f.mitre_id,
                                     f'{f.confidence * 100:.0f}%', f.root_cause),
                             tags=(tag,))

        # Status bar
        self.lbl_status.configure(
            text=f'✓  {len(events)} events · {len(findings)} incident(s) · {duration:.1f}s',
            foreground=TM.C['green'])

        # Integrity badge
        if integrity.get('integrity_intact'):
            self.lbl_integrity.configure(text='🔒  Evidence: INTACT', foreground=TM.C['green'])
        else:
            self.lbl_integrity.configure(text='⚠  Evidence: TAMPERED', foreground=TM.C['red'])

        self.btn_run.configure(state='normal')
        self._log_activity(
            f'Complete — {len(events)} events, {len(findings)} incident(s) detected in {duration:.1f}s')

        self.render_dashboard()
        self.render_timeline()
        self.render_report()

    def _show_history(self):
        self._history_mode = True
        self._history_id_map = {}
        db = ForensicDatabase()
        records = db.list_investigations()
        self.tree.delete(*self.tree.get_children())

        if not records:
            self.lbl_status.configure(
                text='No past investigations found.', foreground=TM.C['text_muted'])
            self._log_activity('History: no records found.')
            return

        for inv in records:
            short_id = inv['id'][:8]
            iid = f'hist_{short_id}'
            self._history_id_map[iid] = inv['id']
            self.tree.insert('', 'end', iid=iid,
                             values=(
                                 short_id,
                                 inv['mode'].upper(),
                                 f'{inv["event_count"]} events',
                                 f'{inv["finding_count"]} incidents',
                                 '',
                                 inv['timestamp'][:19]
                             ))

        self.lbl_status.configure(
            text=f'History — {len(records)} past investigation(s)  ·  click a row to view details',
            foreground=TM.C['accent'])
        self._log_activity(f'History loaded — {len(records)} record(s). Click a row to drill down.')


if __name__ == '__main__':
    app = ForensicApp()
    app.mainloop()
