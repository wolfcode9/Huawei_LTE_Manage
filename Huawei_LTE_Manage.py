"""
================================================================================
Huawei LTE Manager Pro v2.0.0 - TW Edition
================================================================================
用途描述：本程式為 Huawei 4G 路由器之鎖頻管理工具 (台灣專用)

主要功能：
    1. 信號指標：進行「極佳/良好/普通/較弱/極差」五級信號判定。
    2. 頻段鎖定：支援 B1/B3/B7/B8/B28/B38 鎖定功能。
    3. 簡訊管理：簡訊讀取/刪除管理。

標準函式庫 (無需安裝任何套件)：
    - urllib (HTTP 請求)
    - xml.etree.ElementTree (XML 解析)
    - hashlib (MD5 / SHA256)
    - base64 (認證編碼)
    - tkinter (GUI)

程式開發： WolfCode9 Re-engineered | 更新日期：2026/05/31
================================================================================
"""

import tkinter as tk
from tkinter import ttk, messagebox
import threading
import time
import re
import hashlib
import base64
import warnings
import urllib.request
import xml.etree.ElementTree as ET
from http.cookiejar import CookieJar
from configparser import ConfigParser

warnings.filterwarnings("ignore", category=DeprecationWarning)

# ── 設定 ────────────────────────────────────────────────────────────────────
CONFIG_FILE = "config.ini"
SECRET_KEY  = "Huawei_Internal_Secure_Key_2026_WolfCode9"

# ── 頻段常數 (Huawei LTE Band bitmask) ──────────────────────────────────────
BAND_VALUES = {
    "AUTO": 0x7FFFFFFFFFFFFFFF,   # 全頻段
    "1":    0x1,                  # B1  2100 MHz
    "3":    0x4,                  # B3  1800 MHz
    "7":    0x40,                 # B7  2600 MHz
    "8":    0x80,                 # B8   900 MHz
    "28":   0x8000000,            # B28  700 MHz
    "38":   0x2000000000,         # B38 TDD 2600 MHz
}
BAND_LABELS = {
    "AUTO": "自動 (All Bands)",
    "1":    "B1 (2100MHz)",
    "3":    "B3 (1800MHz)",
    "7":    "B7 (2600MHz)",
    "8":    "B8 (900MHz)",
    "28":   "B28 (700MHz)",
    "38":   "B38 (TDD 2600MHz)",
}


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  HuaweiAPI — 自製 HTTP 層  (完全照 Salamek Session.py 邏輯重建)           ║
# ╚══════════════════════════════════════════════════════════════════════════╝
class HuaweiAPI:
    """
    Huawei 路由器 HTTP API 客戶端。
    
    Salamek 原作的關鍵發現：
    1. Token 不是從 XML body 取，而是從 HTTP response header 取
       - 初始化：GET html/index.html → 解析 HTML meta csrf_token
       - 或備援：GET /api/webserver/SesTokInfo → XML TokInfo
    2. 每次 POST 回應的 header 中會有新 token：
       - __RequestVerificationTokenone (登入後)
       - __RequestVerificationToken    (一般請求後)
    3. session cookie 由 urllib CookieJar 自動維護
    """

    def __init__(self, host: str, password: str, timeout: int = 8):
        self.base     = f"http://{host}"
        self.password = password
        self.timeout  = timeout
        # token list，原作者用 list，[0] 用於送出，[1] 備用
        self.tokens: list[str] = []
        # CookieJar 自動維護 session cookie
        self.cookie_jar = CookieJar()
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.cookie_jar)
        )

    # ── 低層 HTTP ──────────────────────────────────────────────────────────
    def _request(self, path: str, data: bytes | None = None) -> tuple[ET.Element, dict]:
        """
        統一的 HTTP 請求入口，回傳 (ET.Element, response_headers)
        data=None → GET，data=bytes → POST
        """
        headers = {
            "User-Agent":       "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "Accept":           "application/xml, text/xml, */*; q=0.01",
            "X-Requested-With": "XMLHttpRequest",
            "Content-Type":     "application/x-www-form-urlencoded; charset=UTF-8",
        }
        if self.tokens:
            headers["__RequestVerificationToken"] = self.tokens[0]

        req = urllib.request.Request(
            self.base + path,
            data=data,
            headers=headers,
            method="POST" if data is not None else "GET",
        )
        with self.opener.open(req, timeout=self.timeout) as resp:
            raw          = resp.read()
            resp_headers = dict(resp.headers)

        # 從 response header 更新 token（Salamek 的核心機制）
        # header 名稱可能是（大小寫不一）：
        #   __RequestVerificationTokenone  (登入成功後，新 token for 後續請求)
        #   __RequestVerificationToken     (一般請求後輪換)
        new_tokens = []
        for k, v in resp_headers.items():
            kl = k.lower()
            if kl == "__requestverificationtokenone":
                new_tokens.insert(0, v)
            elif kl == "__requestverificationtoken":
                new_tokens.append(v)
        if new_tokens:
            self.tokens = new_tokens

        return ET.fromstring(raw), resp_headers

    def _get(self, path: str) -> ET.Element:
        root, _ = self._request(path)
        return root

    def _post(self, path: str, body: str) -> ET.Element:
        root, _ = self._request(path, body.encode("utf-8"))
        return root

    @staticmethod
    def _xml_val(root: ET.Element, *tags) -> str:
        for tag in tags:
            v = root.findtext(tag)
            if v is not None:
                return v
        return ""

    @staticmethod
    def _build_xml(**fields) -> str:
        inner = "".join(f"<{k}>{v}</{k}>" for k, v in fields.items())
        return f"<?xml version='1.0' encoding='UTF-8'?><request>{inner}</request>"

    # ── 初始化 Session + Token ──────────────────────────────────────────────
    def _init_session(self):
        """
        取得初始 Session Cookie 與 CSRF Token。
        
        原作者 Session._initialize_csrf_tokens_and_session() 邏輯：
        先 GET 首頁 HTML，從 <meta name="csrf_token" content="..."> 取 token。
        若首頁沒有 meta（部分韌體），才用 /api/webserver/SesTokInfo。
        """
        import re as _re

        # 方法1：GET 首頁，解析 HTML meta csrf_token
        try:
            req = urllib.request.Request(
                self.base + "/",
                headers={"User-Agent": "Mozilla/5.0"}
            )
            with self.opener.open(req, timeout=self.timeout) as resp:
                html = resp.read().decode("utf-8", errors="ignore")
                resp_headers = dict(resp.headers)

            # 從 response header 取 token
            for k, v in resp_headers.items():
                if k.lower() == "__requestverificationtoken":
                    self.tokens = [v]
                    return

            # 從 HTML <meta name="csrf_token" content="..."> 取 token
            m = _re.search(
                r'<meta\s+name=["\']csrf_token["\']\s+content=["\']([^"\']+)["\']',
                html, _re.I
            )
            if m:
                self.tokens = [m.group(1)]
                return
        except Exception:
            pass

        # 方法2：備援，GET /api/webserver/SesTokInfo
        req2 = urllib.request.Request(
            self.base + "/api/webserver/SesTokInfo",
            headers={"User-Agent": "Mozilla/5.0"}
        )
        with self.opener.open(req2, timeout=self.timeout) as resp2:
            raw2         = resp2.read()
            resp_headers2 = dict(resp2.headers)

        # 先從 header 找
        for k, v in resp_headers2.items():
            if k.lower() == "__requestverificationtoken":
                self.tokens = [v]
                return

        # 再從 XML body 找
        try:
            root2 = ET.fromstring(raw2)
            tok   = root2.findtext("TokInfo")
            if tok:
                self.tokens = [tok]
                return
        except Exception:
            pass

        raise ConnectionError("無法取得 CSRF Token，請確認路由器 IP。")

    # ── 認證 ───────────────────────────────────────────────────────────────
    def connect(self):
        """
        完整登入流程（照 Salamek Session + User 邏輯）：

        1. _init_session()           — 取 Cookie + Token
        2. GET /api/user/state-login — 取 password_type（帶 retry）
        3. POST /api/user/login      — 送雜湊密碼
        """
        # Step 1
        self._init_session()

        # Step 2: 取 password_type，retry 5 次（原作者有此邏輯）
        pw_type = 4
        for attempt in range(5):
            try:
                state   = self._get("/api/user/state-login")
                pt_str  = self._xml_val(state, "password_type")
                pw_type = int(pt_str) if pt_str else 4
                break
            except Exception:
                time.sleep((attempt + 1) * 0.1)

        # Step 3: 登入
        pw_encoded = self._encode_password(self.password, pw_type)
        body = self._build_xml(
            Username=    "admin",
            Password=    pw_encoded,
            password_type=str(pw_type),
        )
        resp = self._post("/api/user/login", body)
        code = self._xml_val(resp, "code")
        if code and code != "0":
            raise ConnectionError(f"登入失敗 (code={code})，請確認密碼。")

    def _encode_password(self, password: str, password_type: int) -> str:
        """
        照 Salamek User._encode_password() 逐字翻譯：

        password_type 4 (SHA256)：
            pw_b64       = base64( sha256(password).hexdigest().encode('ascii') )
            concentrated = b'admin' + pw_b64 + token.encode('UTF-8')
            result       = base64( sha256(concentrated).hexdigest().encode('ascii') )

        password_type 0 (BASE64，舊機)：
            result = base64( password.encode('UTF-8') )
        """
        if not password:
            return ""

        if password_type == 4:
            pw_b64 = base64.b64encode(
                hashlib.sha256(password.encode("UTF-8")).hexdigest().encode("ascii")
            )
            tok = self.tokens[0] if self.tokens else ""
            concentrated = b"admin" + pw_b64 + tok.encode("UTF-8")
            result = base64.b64encode(
                hashlib.sha256(concentrated).hexdigest().encode("ascii")
            )
            return result.decode("UTF-8")
        else:
            return base64.b64encode(password.encode("UTF-8")).decode("UTF-8")

    def logout(self):
        try:
            self._post("/api/user/logout", self._build_xml(Logout="1"))
        except Exception:
            pass

    # ── 裝置資訊 ───────────────────────────────────────────────────────────
    def device_information(self) -> dict:
        return {c.tag: c.text for c in self._get("/api/device/information")}

    def monitoring_status(self) -> dict:
        return {c.tag: c.text for c in self._get("/api/monitoring/status")}

    def traffic_statistics(self) -> dict:
        return {c.tag: c.text for c in self._get("/api/monitoring/traffic-statistics")}

    def signal(self) -> dict:
        return {c.tag: c.text for c in self._get("/api/device/signal")}

    def current_plmn(self) -> dict:
        return {c.tag: c.text for c in self._get("/api/net/current-plmn")}

    def net_mode(self) -> dict:
        return {c.tag: c.text for c in self._get("/api/net/net-mode")}

    def set_net_mode(self, lteband: str, networkband: str = "3fffffff",
                     networkmode: str = "00") -> bool:
        body = self._build_xml(
            NetworkMode=networkmode,
            NetworkBand=networkband,
            LTEBand=lteband,
        )
        resp = self._post("/api/net/net-mode", body)
        code = self._xml_val(resp, "code")
        if code and code != "0":
            raise RuntimeError(f"設定失敗 (code={code})")
        return True

    def get_sms_list(self, page_index: int = 1, read_count: int = 50,
                     box_type: int = 1) -> list:
        body = self._build_xml(
            PageIndex=str(page_index),
            ReadCount=str(read_count),
            BoxType=str(box_type),
            SortType="0",
            Ascending="0",
            UnreadPreferred="0",
        )
        resp = self._post("/api/sms/sms-list", body)
        messages = []
        for msg in resp.iter("Message"):
            messages.append({c.tag: (c.text or "") for c in msg})
        return messages

    def delete_sms(self, index: str) -> bool:
        resp = self._post("/api/sms/delete-sms", self._build_xml(Index=str(index)))
        code = self._xml_val(resp, "code")
        if code and code != "0":
            raise RuntimeError(f"刪除失敗 (code={code})")
        return True


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  工具函式                                                                 ║
# ╚══════════════════════════════════════════════════════════════════════════╝
def get_md5_stream() -> str:
    k1 = hashlib.md5((SECRET_KEY + "_A").encode()).hexdigest()
    k2 = hashlib.md5((SECRET_KEY + "_B").encode()).hexdigest()
    return k1 + k2

def encrypt_password(password: str) -> str:
    if not password:
        return ""
    try:
        key = get_md5_stream()
        padded = password.ljust(32, "\0")
        enc = "".join(chr(ord(padded[i]) ^ ord(key[i])) for i in range(32))
        return enc.encode("latin-1").hex()
    except Exception:
        return ""

def decrypt_password(hex_str: str) -> str:
    if not hex_str or len(hex_str) != 64:
        return ""
    try:
        key = get_md5_stream()
        raw = bytes.fromhex(hex_str).decode("latin-1")
        dec = "".join(chr(ord(raw[i]) ^ ord(key[i])) for i in range(32))
        return dec.strip("\0")
    except Exception:
        return ""

def evaluate_signal(rsrp) -> tuple:
    """回傳 (說明文字, 顏色)"""
    if rsrp is None:
        return "未連線", "#6c757d"
    try:
        m = re.search(r"-?\d+", str(rsrp))
        val = int(m.group()) if m else -140
    except Exception:
        val = -140
    if val >= -70:   return "極佳 (Excellent)", "#2e7d32"
    if val >= -85:   return "良好 (Good)",      "#1565c0"
    if val >= -95:   return "普通 (Fair)",       "#00838f"
    if val >= -105:  return "較弱 (Weak)",       "#d35400"
    return             "極差 (Poor)",            "#c62828"

def format_speed(s) -> str:
    s = int(s or 0)
    if s < 1_048_576:
        return f"{s/1024:.1f} KB/s"
    return f"{s/1_048_576:.2f} MB/s"


# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  RouterApp — Tkinter GUI                                                 ║
# ╚══════════════════════════════════════════════════════════════════════════╝
class RouterApp:
    def __init__(self, root: tk.Tk):
        self.root  = root
        self.root.title("Huawei LTE Manager Pro v2.0.0 - TW Edition")

        w, h = 620, 430
        sw = root.winfo_screenwidth()
        sh = root.winfo_screenheight()
        root.geometry(f"{w}x{h}+{(sw-w)//2}+{(sh-h)//2}")
        root.resizable(False, False)

        self.config = ConfigParser()
        self._load_config()

        self.api: HuaweiAPI | None = None
        self.is_connected = False

        self._build_top()
        self._build_notebook()

        threading.Thread(target=self._signal_loop, daemon=True).start()

        if self.saved_ip and self.saved_pw:
            self.root.after(500, self.toggle_login)

    # ── Config ─────────────────────────────────────────────────────────────
    def _load_config(self):
        try:
            self.config.read(CONFIG_FILE)
            self.saved_ip = self.config.get("Settings", "ip", fallback="192.168.8.1")
            self.saved_pw = decrypt_password(self.config.get("Settings", "pw", fallback=""))
        except Exception:
            self.saved_ip, self.saved_pw = "192.168.8.1", ""

    def _save_config(self):
        if not self.config.has_section("Settings"):
            self.config.add_section("Settings")
        self.config.set("Settings", "ip", self.ip_entry.get())
        if self.remember_var.get():
            self.config.set("Settings", "pw", encrypt_password(self.pw_entry.get()))
        else:
            self.config.remove_option("Settings", "pw")
        with open(CONFIG_FILE, "w") as f:
            self.config.write(f)

    # ── Top Bar ────────────────────────────────────────────────────────────
    def _build_top(self):
        top = tk.Frame(self.root, bg="#ffffff", bd=1, relief="flat", padx=15, pady=12)
        top.pack(fill="x")

        tk.Label(top, text="位址:", bg="white", fg="#7f8c8d",
                 font=("Microsoft JhengHei", 9)).pack(side="left")
        self.ip_entry = tk.Entry(top, width=15, relief="groove", bd=1)
        self.ip_entry.insert(0, self.saved_ip)
        self.ip_entry.pack(side="left", padx=(2, 10))

        tk.Label(top, text="密碼:", bg="white", fg="#7f8c8d",
                 font=("Microsoft JhengHei", 9)).pack(side="left")
        self.pw_entry = tk.Entry(top, show="*", width=12, relief="groove", bd=1)
        self.pw_entry.insert(0, self.saved_pw)
        self.pw_entry.pack(side="left", padx=(2, 5))

        self.remember_var = tk.BooleanVar(value=bool(self.saved_pw))
        tk.Checkbutton(top, text="記憶密碼", variable=self.remember_var,
                       bg="white", font=("Microsoft JhengHei", 8), fg="#7f8c8d"
                       ).pack(side="left", padx=5)

        self.conn_btn = ttk.Button(top, text="連接設備", command=self.toggle_login)
        self.conn_btn.pack(side="left", padx=5)

        self.status_var = tk.StringVar(value="OFFLINE")
        self.status_lbl = tk.Label(top, textvariable=self.status_var, bg="white",
                                   font=("Arial", 9, "bold"), fg="#e74c3c")
        self.status_lbl.pack(side="right")

    # ── Notebook ───────────────────────────────────────────────────────────
    def _build_notebook(self):
        nb = ttk.Notebook(self.root)
        nb.pack(fill="both", expand=True, padx=10, pady=5)
        self.notebook = nb

        self.tab_monitor    = tk.Frame(nb, bg="#f4f7f6")
        self.tab_management = tk.Frame(nb, bg="#f4f7f6")
        self.tab_sms        = tk.Frame(nb, bg="#f4f7f6")

        nb.add(self.tab_monitor,    text=" 狀態監控 ")
        nb.add(self.tab_management, text=" 頻段管理 ")
        nb.add(self.tab_sms,        text=" 簡訊管理 ")

        self._build_monitor_tab()
        self._build_management_tab()
        self._build_sms_tab()

    # ── 狀態監控 Tab ───────────────────────────────────────────────────────
    def _build_monitor_tab(self):
        main = tk.Frame(self.tab_monitor, bg="#f4f7f6", padx=15, pady=5)
        main.pack(fill="both", expand=True)

        # 系統資訊
        info_f = ttk.LabelFrame(main, text=" 系統資訊 ", padding=12)
        info_f.pack(fill="x", pady=5)
        self.info_vars = {k: tk.StringVar(value="--") for k in
                          ["DeviceName", "SoftwareVersion", "Operator",
                           "Msisdn", "MacAddress1", "WanIPAddress"]}
        fields = [
            ("型號:",  "DeviceName"),   ("版本:", "SoftwareVersion"),
            ("MAC:",   "MacAddress1"),  ("電信:", "Operator"),
            ("門號:",  "Msisdn"),       ("外網:", "WanIPAddress"),
        ]
        for i, (lbl, key) in enumerate(fields):
            row, col = divmod(i, 3)
            col *= 2
            tk.Label(info_f, text=lbl, fg="#7f8c8d",
                     font=("Microsoft JhengHei", 9)).grid(row=row, column=col, sticky="w", pady=3)
            tk.Label(info_f, textvariable=self.info_vars[key],
                     font=("Consolas", 9, "bold")).grid(row=row, column=col+1, sticky="w", padx=(5, 20))

        # 即時信號
        sig_f = ttk.LabelFrame(main, text=" 即時資訊 ", padding=12)
        sig_f.pack(fill="x", pady=5)

        self.lv_var  = tk.StringVar(value="等待連線...")
        self.lv_disp = tk.Label(sig_f, textvariable=self.lv_var,
                                font=("Microsoft JhengHei", 14, "bold"), fg="#6c757d")
        self.lv_disp.pack(anchor="w", pady=(0, 10))

        val_grid = tk.Frame(sig_f)
        val_grid.pack(fill="x")
        self.sig_vars = {k: tk.StringVar(value="--") for k in ["rsrp", "sinr", "rsrq", "rssi"]}
        for i, (txt, key) in enumerate([
            ("RSRP 強度:", "rsrp"), ("SINR 品質:", "sinr"),
            ("RSRQ 干擾:", "rsrq"), ("RSSI 總能:", "rssi"),
        ]):
            cont = tk.Frame(val_grid)
            cont.grid(row=0, column=i, sticky="w", padx=8)
            tk.Label(cont, text=txt, font=("Microsoft JhengHei", 9), fg="#7f8c8d").pack(side="left")
            tk.Label(cont, textvariable=self.sig_vars[key],
                     font=("Consolas", 10, "bold"), fg="#34495e", width=6).pack(side="left")

        tk.Frame(sig_f, height=1, bg="#e0e0e0").pack(fill="x", pady=15)

        speed_f = tk.Frame(sig_f)
        speed_f.pack(fill="x")
        self.speed_vars = {
            "down": tk.StringVar(value="0 KB/s"),
            "up":   tk.StringVar(value="0 KB/s"),
        }
        for k, lbl, clr in [("down", "▼ 即時下載", "#1565c0"), ("up", "▲ 即時上傳", "#d35400")]:
            cont = tk.Frame(speed_f)
            cont.pack(side="left", expand=True)
            tk.Label(cont, text=lbl, font=("Microsoft JhengHei", 10, "bold"), fg=clr).pack()
            tk.Label(cont, textvariable=self.speed_vars[k],
                     font=("Consolas", 15, "bold"), fg=clr).pack()

    # ── 頻段管理 Tab ───────────────────────────────────────────────────────
    def _build_management_tab(self):
        main = tk.Frame(self.tab_management, bg="#f4f7f6", padx=15, pady=5)
        main.pack(fill="both", expand=True)

        band_f = ttk.LabelFrame(main, text=" 頻段鎖定 ", padding=12)
        band_f.pack(fill="x", pady=5)

        self.band_vars    = {}
        self.band_widgets = {}
        grid_f = tk.Frame(band_f)
        grid_f.pack(fill="x")
        for i, b_id in enumerate(BAND_VALUES):
            var = tk.BooleanVar()
            cb  = tk.Checkbutton(
                grid_f, text=BAND_LABELS[b_id], variable=var,
                font=("Microsoft JhengHei", 9), state="disabled",
                command=lambda b=b_id: self._on_band_check(b)
            )
            cb.grid(row=i//4, column=i%4, sticky="w", padx=10, pady=5)
            self.band_vars[b_id]    = var
            self.band_widgets[b_id] = cb

        self.apply_btn = ttk.Button(band_f, text="套用鎖頻設定",
                                    state="disabled", command=self._start_apply)
        self.apply_btn.pack(fill="x", pady=(5, 0))

    # ── 簡訊管理 Tab ───────────────────────────────────────────────────────
    def _build_sms_tab(self):
        sms_main = tk.Frame(self.tab_sms, bg="#f4f7f6", padx=15, pady=10)
        sms_main.pack(fill="both", expand=True)

        btn_f = tk.Frame(sms_main, bg="#f4f7f6")
        btn_f.pack(fill="x", pady=(0, 10))

        self.sms_delete_btn = ttk.Button(btn_f, text="刪除所選", width=12,
                                          command=self._delete_sms, state="disabled")
        self.sms_delete_btn.pack(side="left")

        self.sms_count_var = tk.StringVar(value="簡訊數: --")
        tk.Label(btn_f, textvariable=self.sms_count_var, bg="#f4f7f6",
                 font=("Microsoft JhengHei", 9)).pack(side="right")

        list_f = tk.Frame(sms_main)
        list_f.pack(fill="x")

        cols = ("idx", "phone", "date", "preview")
        self.sms_tree = ttk.Treeview(list_f, columns=cols, show="headings", height=4)
        self.sms_tree.heading("idx",     text="#");              self.sms_tree.column("idx",     width=40,  anchor="center")
        self.sms_tree.heading("phone",   text="發送者");         self.sms_tree.column("phone",   width=130)
        self.sms_tree.heading("date",    text="時間");           self.sms_tree.column("date",    width=150)
        self.sms_tree.heading("preview", text="預覽內容");       self.sms_tree.column("preview", width=280)

        scy = ttk.Scrollbar(list_f, orient="vertical", command=self.sms_tree.yview)
        self.sms_tree.configure(yscrollcommand=scy.set)
        self.sms_tree.pack(side="left", fill="both", expand=True)
        scy.pack(side="right", fill="y")
        self.sms_tree.bind("<<TreeviewSelect>>", self._on_sms_selected)

        content_f = ttk.LabelFrame(sms_main, text=" 簡訊內容 ", padding=10)
        content_f.pack(fill="both", expand=True, pady=(10, 0))

        self.sms_text = tk.Text(content_f, height=15, font=("Microsoft JhengHei", 10),
                                bg="#ffffff", relief="flat", padx=12, pady=12)
        stx = ttk.Scrollbar(content_f, orient="vertical", command=self.sms_text.yview)
        self.sms_text.configure(yscrollcommand=stx.set)
        self.sms_text.pack(side="left", fill="both", expand=True)
        stx.pack(side="right", fill="y")
        self.sms_text.config(state="disabled")

    # ── 連線邏輯 ───────────────────────────────────────────────────────────
    def toggle_login(self):
        if not self.is_connected:
            self.conn_btn.config(text="連線中...", state="disabled")
            threading.Thread(target=self._perform_connection, daemon=True).start()
        else:
            self._perform_logout()

    def _perform_connection(self):
        self._save_config()
        host = self.ip_entry.get().strip()
        pw   = self.pw_entry.get()
        try:
            api = HuaweiAPI(host, pw, timeout=5)
            api.connect()
            dev    = api.device_information()
            status = api.monitoring_status()
            plmn   = api.current_plmn()
            self.root.after(0, lambda: self._on_connected(api, dev, status, plmn))
        except Exception as e:
            msg = str(e)
            self.root.after(0, lambda m=msg: self._on_conn_fail(m))

    def _on_connected(self, api, dev, status, plmn):
        self.api          = api
        self.is_connected = True
        self.status_var.set("CONNECTED")
        self.status_lbl.config(fg="#2ecc71")
        self.conn_btn.config(text="中斷連線", state="normal")

        for k in self.info_vars:
            val = dev.get(k) or status.get(k) or "--"
            if k == "Operator":
                val = plmn.get("FullName") or plmn.get("ShortName") or "--"
            if k == "WanIPAddress":
                val = status.get("WanIPAddress", "--")
            self.info_vars[k].set(val)

        self.apply_btn.config(state="normal")
        for cb in self.band_widgets.values():
            cb.config(state="normal")
        self.sms_delete_btn.config(state="normal")

        self._refresh_current_bands()
        self._refresh_sms()

    def _on_conn_fail(self, msg):
        self.conn_btn.config(text="連接設備", state="normal")
        messagebox.showerror("連線失敗", f"無法連接路由器：\n{msg}")

    def _perform_logout(self):
        if self.api:
            threading.Thread(target=self.api.logout, daemon=True).start()
        self.api          = None
        self.is_connected = False
        self.status_var.set("OFFLINE")
        self.status_lbl.config(fg="#e74c3c")
        self.conn_btn.config(text="連接設備")

        for v in self.info_vars.values():  v.set("--")
        for v in self.sig_vars.values():   v.set("--")
        for v in self.speed_vars.values(): v.set("0 KB/s")
        self.lv_var.set("等待連線...")
        self.lv_disp.config(fg="#6c757d")

        self.apply_btn.config(state="disabled")
        for cb in self.band_widgets.values(): cb.config(state="disabled")
        self.sms_delete_btn.config(state="disabled")
        self.sms_count_var.set("簡訊數: --")
        self._clear_sms_content()
        for i in self.sms_tree.get_children(): self.sms_tree.delete(i)

    # ── 頻段 ───────────────────────────────────────────────────────────────
    def _refresh_current_bands(self):
        try:
            net  = self.api.net_mode()
            raw  = str(net.get("LTEBand", "0"))
            mask = int(raw, 16) if not raw.startswith("0x") else int(raw, 0)
            is_auto = (mask >= BAND_VALUES["AUTO"])
            self.band_vars["AUTO"].set(is_auto)
            for b_id, bval in BAND_VALUES.items():
                if b_id == "AUTO":
                    continue
                self.band_vars[b_id].set(False if is_auto else bool(mask & bval))
        except Exception:
            pass

    def _on_band_check(self, b_id):
        if b_id == "AUTO" and self.band_vars["AUTO"].get():
            for k in self.band_vars:
                if k != "AUTO":
                    self.band_vars[k].set(False)
        elif b_id != "AUTO" and self.band_vars[b_id].get():
            self.band_vars["AUTO"].set(False)

    def _start_apply(self):
        threading.Thread(target=self._apply_settings, daemon=True).start()

    def _apply_settings(self):
        sel = [b for b, v in self.band_vars.items() if v.get()]
        if not sel:
            return
        try:
            if "AUTO" in sel:
                mask = BAND_VALUES["AUTO"]
            else:
                mask = 0
                for b in sel:
                    mask |= BAND_VALUES[b]
            self.api.set_net_mode(lteband=f"{mask:x}")
            messagebox.showinfo("成功", "頻段鎖定指令已送達")
            self._refresh_current_bands()
        except Exception as e:
            messagebox.showerror("錯誤", f"無法設定頻段：{e}")

    # ── 信號監控迴圈 ───────────────────────────────────────────────────────
    def _signal_loop(self):
        while True:
            if self.is_connected and self.api:
                try:
                    sig   = self.api.signal()
                    traf  = self.api.traffic_statistics()
                    ws    = self.api.monitoring_status()

                    lv, col = evaluate_signal(sig.get("rsrp"))
                    self.root.after(0, lambda v=lv, c=col: (
                        self.lv_var.set(v),
                        self.lv_disp.config(fg=c)
                    ))
                    for k in self.sig_vars:
                        self.sig_vars[k].set(sig.get(k, "--"))
                    self.speed_vars["down"].set(format_speed(traf.get("CurrentDownloadRate", 0)))
                    self.speed_vars["up"].set(format_speed(traf.get("CurrentUploadRate", 0)))
                    self.info_vars["WanIPAddress"].set(ws.get("WanIPAddress", "--"))
                except Exception:
                    pass
            time.sleep(1)

    # ── 簡訊 ───────────────────────────────────────────────────────────────
    def _refresh_sms(self):
        if not self.is_connected:
            return
        threading.Thread(target=self._fetch_sms, daemon=True).start()
        threading.Timer(60, self._refresh_sms).start()

    def _fetch_sms(self):
        try:
            messages = self.api.get_sms_list()
            self.root.after(0, lambda: self._update_sms_ui(messages))
        except Exception:
            self.root.after(0, lambda: self.sms_count_var.set("讀取失敗"))

    def _update_sms_ui(self, messages):
        for i in self.sms_tree.get_children():
            self.sms_tree.delete(i)
        self.sms_count_var.set(f"簡訊數: {len(messages)}")
        for m in messages:
            content = str(m.get("Content", ""))
            preview = content.replace("\n", " ").replace("\r", "")
            self.sms_tree.insert(
                "", "end",
                values=(m.get("Index"), m.get("Phone"), m.get("Date"), preview),
                tags=(content,)
            )

    def _on_sms_selected(self, _event):
        sel = self.sms_tree.selection()
        if not sel:
            return
        content = self.sms_tree.item(sel[0], "tags")[0]
        self.sms_text.config(state="normal")
        self.sms_text.delete("1.0", tk.END)
        self.sms_text.insert("1.0", content)
        self.sms_text.config(state="disabled")

    def _delete_sms(self):
        sel = self.sms_tree.selection()
        if not sel:
            messagebox.showwarning("提示", "請先選取要刪除的簡訊")
            return
        if not messagebox.askyesno("確認", "確定要刪除選中的簡訊嗎？"):
            return

        def _task():
            try:
                idx = self.sms_tree.item(sel[0], "values")[0]
                self.api.delete_sms(idx)
                self.root.after(0, lambda: (self._clear_sms_content(), self._refresh_sms()))
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("錯誤", f"刪除失敗：{e}"))

        threading.Thread(target=_task, daemon=True).start()

    def _clear_sms_content(self):
        self.sms_text.config(state="normal")
        self.sms_text.delete("1.0", tk.END)
        self.sms_text.config(state="disabled")


# ── 入口 ────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    root = tk.Tk()
    app  = RouterApp(root)
    root.mainloop()
