"""
================================================================================
Huawei LTE Manager Pro v1.3.5 - TW Edition
================================================================================
用途描述：本程式為 Huawei 4G 路由器之鎖頻管理工具 (台灣專用)  

主要功能：
    1. 信號指標：進行「極優/優/良/中/差」五級信號判定。
    2. 頻段鎖定：支援 B1/B3/B7/B8/B28/B38 鎖定功能。
    3. 性能分析：整合 Speedtest 網路測速。
    4. 簡訊管理：簡訊讀取/刪除管理。
    
需求套件：
    - huawei-lte-api==1.7.3
    - speedtest-cli==2.1.3  

程式開發： WolfCode9 | 更新日期： 2026/01/07
================================================================================
"""

import tkinter as tk
from tkinter import ttk, messagebox
import threading, time, re, hashlib, warnings
import speedtest
from configparser import ConfigParser
from huawei_lte_api.Client import Client
from huawei_lte_api.Connection import Connection
from huawei_lte_api.enums.net import LTEBandEnum

# 過濾掉 API 庫中因 Python 版本更新產生的 DeprecationWarning 警告訊息
warnings.filterwarnings("ignore", category=DeprecationWarning) 

# 配置與金鑰
CONFIG_FILE = "config.ini"
SECRET_KEY = "Huawei_Internal_Secure_Key_2026_WolfCode9" 

# --- 安全工具函式 ---
def get_md5_stream():
    """ 生成雙重 MD5 加密串作為異或運算的 Key """
    k1 = hashlib.md5((SECRET_KEY + "_A").encode()).hexdigest()
    k2 = hashlib.md5((SECRET_KEY + "_B").encode()).hexdigest()
    return k1 + k2

def encrypt_password(password):
    """ 簡單異或加密：防止密碼以明文存放在 INI 檔中 """
    if not password: return ""
    try:
        key = get_md5_stream()
        padded_pw = password.ljust(32, '\0')
        encrypted = "".join(chr(ord(padded_pw[i]) ^ ord(key[i])) for i in range(32))
        return encrypted.encode('latin-1').hex()
    except: return ""

def decrypt_password(hex_str):
    """ 解密儲存在 INI 檔中的 16 進位加密字串 """
    if not hex_str or len(hex_str) != 64: return ""
    try:
        key = get_md5_stream()
        encrypted_raw = bytes.fromhex(hex_str).decode('latin-1')
        decrypted = "".join(chr(ord(encrypted_raw[i]) ^ ord(key[i])) for i in range(32))
        return decrypted.strip('\0')
    except: return ""

def evaluate_signal(rsrp):
    """ 根據 RSRP (參考信號接收功率) 數值判定信號品質與對應顏色 """
    if rsrp is None: return "未連線", "#6c757d"
    try:
        m = re.search(r"-?\d+", str(rsrp))
        val = int(m.group()) if m else -140
    except: val = -140
    
    if val >= -85:  return "極優 (Excellent+)", "#2e7d32"
    if val >= -95:  return "優 (Excellent)", "#1565c0"
    if val >= -105: return "良 (Good)", "#00838f"
    if val >= -115: return "中 (Fair)", "#d35400"
    return "差 (Poor)", "#c62828"

# 頻段對照表
BAND_MAP = {
    "AUTO": (LTEBandEnum.ALL, "自動 (All Bands)"),
    "1": (LTEBandEnum.B1, "B1 (2100MHz)"),
    "3": (LTEBandEnum.B3, "B3 (1800MHz)"),
    "7": (LTEBandEnum.B7, "B7 (2600MHz)"),
    "8": (LTEBandEnum.B8, "B8 (900MHz)"),
    "28": (LTEBandEnum.B28, "B28 (700MHz)"),
    "38": (LTEBandEnum.B38, "B38 (TDD 2600MHz)")    
}

class RouterApp:
    def __init__(self, root):
        self.root = root
        self.root.title(f"Huawei LTE Manager Pro v1.3.5 - TW Edition")
        
        # 視窗居中設定
        width, height = 620, 500
        screen_w = self.root.winfo_screenwidth()
        screen_h = self.root.winfo_screenheight()
        self.root.geometry(f"{width}x{height}+{int((screen_w-width)/2)}+{int((screen_h-height)/2)}")
        self.root.resizable(False, False)
        
        self.config = ConfigParser()
        self.load_config()

        # --- UI: 頂部登入列 ---
        top_f = tk.Frame(root, bg="#ffffff", bd=1, relief="flat", padx=15, pady=12)
        top_f.pack(fill="x")
        
        tk.Label(top_f, text="位址:", bg="white", fg="#7f8c8d", font=("Microsoft JhengHei", 9)).pack(side="left")
        self.ip_entry = tk.Entry(top_f, width=15, relief="groove", bd=1)
        self.ip_entry.insert(0, self.saved_ip)
        self.ip_entry.pack(side="left", padx=(2, 10))

        tk.Label(top_f, text="密碼:", bg="white", fg="#7f8c8d", font=("Microsoft JhengHei", 9)).pack(side="left")
        self.pw_entry = tk.Entry(top_f, show="*", width=12, relief="groove", bd=1)
        self.pw_entry.insert(0, self.saved_pw)
        self.pw_entry.pack(side="left", padx=(2, 5))

        self.remember_var = tk.BooleanVar(value=True if self.saved_pw else False)
        tk.Checkbutton(top_f, text="記憶密碼", variable=self.remember_var, bg="white", font=("Microsoft JhengHei", 8), fg="#7f8c8d").pack(side="left", padx=5)
        
        self.conn_btn = ttk.Button(top_f, text="連接設備", command=self.toggle_login)
        self.conn_btn.pack(side="left", padx=5)
        
        self.status_var = tk.StringVar(value="OFFLINE")
        self.status_lbl = tk.Label(top_f, textvariable=self.status_var, bg="white", font=("Arial", 9, "bold"), fg="#e74c3c")
        self.status_lbl.pack(side="right")

        # --- UI: 分頁系統 ---
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=5)

        self.tab_monitor = tk.Frame(self.notebook, bg="#f4f7f6")
        self.tab_management = tk.Frame(self.notebook, bg="#f4f7f6")
        self.tab_sms = tk.Frame(self.notebook, bg="#f4f7f6")
        
        self.notebook.add(self.tab_monitor, text=" 狀態監控 ")
        self.notebook.add(self.tab_management, text=" 頻段管理 ")
        self.notebook.add(self.tab_sms, text=" 簡訊管理 ")

        self._build_monitor_tab()
        self._build_management_tab()
        self._build_sms_tab()

        self.client = None
        self.is_connected = False
        
        threading.Thread(target=self.signal_monitor_loop, daemon=True).start()

    def _build_monitor_tab(self):
        main_f = tk.Frame(self.tab_monitor, bg="#f4f7f6", padx=15, pady=5)
        main_f.pack(fill="both", expand=True)

        info_f = ttk.LabelFrame(main_f, text=" 系統資訊 ", padding=12)
        info_f.pack(fill="x", pady=5)
        self.info_vars = {k: tk.StringVar(value="--") for k in ["DeviceName", "SoftwareVersion", "Operator", "Msisdn", "MacAddress1", "WanIPAddress"]}
        fields = [("型號:", "DeviceName"), ("版本:", "SoftwareVersion"), ("MAC:", "MacAddress1"), ("電信:", "Operator"), ("門號:", "Msisdn"), ("外網:", "WanIPAddress")]
        for i, (label, key) in enumerate(fields):
            row, col = i // 3, (i % 3) * 2
            tk.Label(info_f, text=label, fg="#7f8c8d", font=("Microsoft JhengHei", 9)).grid(row=row, column=col, sticky="w", pady=3)
            tk.Label(info_f, textvariable=self.info_vars[key], font=("Consolas", 9, "bold")).grid(row=row, column=col+1, sticky="w", padx=(5, 20))

        sig_f = ttk.LabelFrame(main_f, text=" 即時資訊 ", padding=12)
        sig_f.pack(fill="x", pady=5)
        self.lv_var = tk.StringVar(value="等待連線...")
        self.lv_disp = tk.Label(sig_f, textvariable=self.lv_var, font=("Microsoft JhengHei", 14, "bold"), fg="#6c757d")
        self.lv_disp.pack(anchor="w", pady=(0, 10))
        
        val_grid = tk.Frame(sig_f); val_grid.pack(fill="x")
        self.sig_vars = {k: tk.StringVar(value="--") for k in ["rsrp", "sinr", "rsrq", "rssi"]}
        for i, (txt, key) in enumerate([("RSRP 強度:", "rsrp"), ("SINR 品質:", "sinr"), ("RSRQ 干擾:", "rsrq"), ("RSSI 總能:", "rssi")]):
            cont = tk.Frame(val_grid); cont.grid(row=0, column=i, sticky="w", padx=8)
            tk.Label(cont, text=txt, font=("Microsoft JhengHei", 9), fg="#7f8c8d").pack(side="left")
            tk.Label(cont, textvariable=self.sig_vars[key], font=("Consolas", 10, "bold"), fg="#34495e", width=6).pack(side="left")

        tk.Frame(sig_f, height=1, bg="#e0e0e0").pack(fill="x", pady=15)
        speed_f = tk.Frame(sig_f); speed_f.pack(fill="x")
        self.speed_vars = {"down": tk.StringVar(value="0 KB/s"), "up": tk.StringVar(value="0 KB/s")}
        for k, lbl, clr in [("down", "▼ 即時下載", "#1565c0"), ("up", "▲ 即時上傳", "#d35400")]:
            cont = tk.Frame(speed_f); cont.pack(side="left", expand=True)
            tk.Label(cont, text=lbl, font=("Microsoft JhengHei", 10, "bold"), fg=clr).pack()
            tk.Label(cont, textvariable=self.speed_vars[k], font=("Consolas", 15, "bold"), fg=clr).pack()

    def _build_management_tab(self):
        main_f = tk.Frame(self.tab_management, bg="#f4f7f6", padx=15, pady=5)
        main_f.pack(fill="both", expand=True)

        band_f = ttk.LabelFrame(main_f, text=" 頻段鎖定 ", padding=12)
        band_f.pack(fill="x", pady=5)
        self.band_vars = {}; self.band_widgets = {}
        grid_f = tk.Frame(band_f); grid_f.pack(fill="x")
        for i, b_id in enumerate(list(BAND_MAP.keys())):
            var = tk.BooleanVar()
            cb = tk.Checkbutton(grid_f, text=BAND_MAP[b_id][1], variable=var, font=("Microsoft JhengHei", 9), state="disabled", command=lambda b=b_id: self.on_band_check(b))
            cb.grid(row=i//4, column=i%4, sticky="w", padx=10, pady=5)
            self.band_vars[b_id] = var
            self.band_widgets[b_id] = cb
        self.apply_btn = ttk.Button(band_f, text="套用鎖頻設定", state="disabled", command=self.start_apply_thread)
        self.apply_btn.pack(fill="x", pady=(5, 0))

        st_f = ttk.LabelFrame(main_f, text=" 網路測速 (Speedtest) ", padding=12)
        st_f.pack(fill="x", pady=5)
        st_result_f = tk.Frame(st_f); st_result_f.pack(fill="x", pady=(0, 10))
        self.st_vars = {"ping": tk.StringVar(value="-- ms"), "dl": tk.StringVar(value="-- Mbps"), "ul": tk.StringVar(value="-- Mbps")}
        for k, lbl, clr in [("ping", "延遲 (Ping)", "#7f8c8d"), ("dl", "▼ 測速下載", "#2980b9"), ("ul", "▲ 測速上傳", "#8e44ad")]:
            cont = tk.Frame(st_result_f); cont.pack(side="left", expand=True)
            tk.Label(cont, text=lbl, font=("Microsoft JhengHei", 9), fg=clr).pack()
            tk.Label(cont, textvariable=self.st_vars[k], font=("Consolas", 15, "bold"), fg=clr).pack()
            
        tk.Frame(st_f, height=1, bg="#e0e0e0").pack(fill="x", pady=5)
        st_bot = tk.Frame(st_f); st_bot.pack(fill="x", pady=(5, 0))
        self.test_btn = ttk.Button(st_bot, text="開始網路測速", command=self.start_speedtest_thread)
        self.test_btn.pack(fill="x")
        self.st_status = tk.Label(st_bot, text="準備就緒", font=("Microsoft JhengHei", 8), fg="#95a5a6")
        self.st_status.pack()

    def _build_sms_tab(self):
        """ 建立簡訊管理分頁 (包含初始狀態控制) """
        sms_main = tk.Frame(self.tab_sms, bg="#f4f7f6", padx=15, pady=10)
        sms_main.pack(fill="both", expand=True)

        btn_f = tk.Frame(sms_main, bg="#f4f7f6")
        btn_f.pack(fill="x", pady=(0, 10))

        self.sms_delete_btn = ttk.Button(btn_f, text="刪除所選", width=12, command=self.delete_sms, state="disabled")
        self.sms_delete_btn.pack(side="left", padx=0)
        
        self.sms_count_var = tk.StringVar(value="簡訊數: --")
        tk.Label(btn_f, textvariable=self.sms_count_var, bg="#f4f7f6", font=("Microsoft JhengHei", 9)).pack(side="right")

        list_f = tk.Frame(sms_main)
        list_f.pack(fill="x", expand=False) 
        
        cols = ("idx", "phone", "date", "preview")
        self.sms_tree = ttk.Treeview(list_f, columns=cols, show="headings", height=8)
        self.sms_tree.heading("idx", text="#"); self.sms_tree.column("idx", width=40, anchor="center")
        self.sms_tree.heading("phone", text="發送者"); self.sms_tree.column("phone", width=130)
        self.sms_tree.heading("date", text="時間"); self.sms_tree.column("date", width=150)
        self.sms_tree.heading("preview", text="預覽內容"); self.sms_tree.column("preview", width=280)
        
        scy = ttk.Scrollbar(list_f, orient="vertical", command=self.sms_tree.yview)
        self.sms_tree.configure(yscrollcommand=scy.set)
        self.sms_tree.pack(side="left", fill="both", expand=True)
        scy.pack(side="right", fill="y")
        self.sms_tree.bind("<<TreeviewSelect>>", self.on_sms_selected)

        content_f = ttk.LabelFrame(sms_main, text=" 簡訊內容 ", padding=10)
        content_f.pack(fill="both", expand=True, pady=(10, 0)) 
        self.sms_text = tk.Text(content_f, height=15, font=("Microsoft JhengHei", 10), bg="#ffffff", relief="flat", padx=12, pady=12)
        stx = ttk.Scrollbar(content_f, orient="vertical", command=self.sms_text.yview)
        self.sms_text.configure(yscrollcommand=stx.set)
        self.sms_text.pack(side="left", fill="both", expand=True)
        stx.pack(side="right", fill="y")
        self.sms_text.config(state="disabled")
        
    # --- 核心業務邏輯 ---

    def toggle_login(self):
        if not self.is_connected:
            self.conn_btn.config(text="連線中...", state="disabled")
            threading.Thread(target=self.perform_connection, daemon=True).start()
        else: self.perform_logout()

    def perform_connection(self):
        self.save_config()
        url = f"http://admin:{self.pw_entry.get()}@{self.ip_entry.get().strip()}/"
        try:
            conn = Connection(url, timeout=5)
            client = Client(conn)
            dev = client.device.information()
            status = client.monitoring.status()
            plmn = client.net.current_plmn()
            self.root.after(0, lambda: self.on_connection_success(client, dev, status, plmn))
        except Exception as e: 
            err_msg = str(e)
            self.root.after(0, lambda m=err_msg: self.on_connection_fail(m))

    def on_connection_success(self, client, dev, status, plmn):
        """ 連線成功：更新 UI 並啟用所有控制項 """
        self.client = client
        self.is_connected = True
        self.status_var.set("CONNECTED"); self.status_lbl.config(fg="#2ecc71")
        self.conn_btn.config(text="中斷連線", state="normal")
        
        for k in self.info_vars: 
            val = dev.get(k) or status.get(k) or plmn.get(k) or '--'
            if k == "Operator": val = plmn.get('FullName', '--')
            self.info_vars[k].set(val)
            
        # 啟用頻道管理 UI
        self.apply_btn.config(state="normal")
        for cb in self.band_widgets.values(): cb.config(state="normal")
        
        # 啟用簡訊管理按鈕
        #self.sms_refresh_btn.config(state="normal")
        self.sms_delete_btn.config(state="normal")
        
        self.refresh_current_bands()
        self.refresh_sms()

    def on_connection_fail(self, msg):
        self.conn_btn.config(text="連接設備", state="normal")
        messagebox.showerror("失敗", f"連線錯誤: {msg}")

    def perform_logout(self):
        """ 登出：中斷連線並恢復 UI 為禁用狀態 """
        self.is_connected = False; self.client = None
        self.status_var.set("OFFLINE"); self.status_lbl.config(fg="#e74c3c")
        self.conn_btn.config(text="連接設備")
        for var in self.info_vars.values(): var.set("--")
        for var in self.sig_vars.values(): var.set("--")
        for var in self.speed_vars.values(): var.set("0 KB/s")
        
        # 禁用頻道管理
        self.apply_btn.config(state="disabled")
        for cb in self.band_widgets.values(): cb.config(state="disabled")
        
        # 禁用簡訊管理
        #self.sms_refresh_btn.config(state="disabled")
        self.sms_delete_btn.config(state="disabled")
        self.sms_count_var.set("簡訊數: --")
        self._clear_sms_content()
        for i in self.sms_tree.get_children(): self.sms_tree.delete(i)

    def refresh_current_bands(self):
        try:
            net = self.client.net.net_mode()
            band_str = str(net.get('LTEBand', '0'))
            curr_mask = int(band_str, 16) if '0x' not in band_str else int(band_str, 0)
            is_auto = (curr_mask >= LTEBandEnum.ALL.value)
            self.band_vars["AUTO"].set(is_auto)
            for b_id, (val, _) in BAND_MAP.items():
                if b_id == "AUTO": continue
                v = val.value if hasattr(val, 'value') else val
                self.band_vars[b_id].set(False if is_auto else (curr_mask & v) == v)
        except: pass

    def on_band_check(self, b_id):
        if b_id == "AUTO" and self.band_vars["AUTO"].get():
            for k in self.band_vars: 
                if k != "AUTO": self.band_vars[k].set(False)
        elif b_id != "AUTO" and self.band_vars[b_id].get():
            self.band_vars["AUTO"].set(False)

    def start_apply_thread(self): 
        threading.Thread(target=self.apply_settings, daemon=True).start()

    def apply_settings(self):
        sel = [b for b, v in self.band_vars.items() if v.get()]
        if not sel: return
        try:
            mask = LTEBandEnum.ALL.value if "AUTO" in sel else sum(BAND_MAP[b][0].value for b in sel)
            self.client.net.set_net_mode(lteband=f"{mask:x}", networkband="3fffffff", networkmode="00")
            messagebox.showinfo("成功", "頻段鎖定指令已送達")
            self.refresh_current_bands()
        except Exception as e: 
            messagebox.showerror("錯誤", f"無法設定頻段: {e}")

    def signal_monitor_loop(self):
        while True:
            if self.is_connected and self.client:
                try:
                    sig = self.client.device.signal()                           
                    self.info_vars["WanIPAddress"].set(self.client.monitoring.status().get("WanIPAddress", "--"))
                    traf = self.client.monitoring.traffic_statistics()
                    lv, col = evaluate_signal(sig.get("rsrp"))
                    self.root.after(0, lambda v=lv, c=col: (self.lv_var.set(v), self.lv_disp.config(fg=c)))
                    for k in self.sig_vars: self.sig_vars[k].set(sig.get(k, "--"))
                    self.speed_vars["down"].set(self.format_speed(traf.get('CurrentDownloadRate', 0)))
                    self.speed_vars["up"].set(self.format_speed(traf.get('CurrentUploadRate', 0)))
                except: pass
            time.sleep(1)

    def start_speedtest_thread(self):
        """啟動網路測速執行緒 (按下時先初始化數值)"""
        # 1. 禁用按鈕防止重複點擊
        self.test_btn.config(state="disabled")
        
        # 2. 初始化測速數值為初始狀態
        self.st_vars["ping"].set("-- ms")
        self.st_vars["dl"].set("-- Mbps")
        self.st_vars["ul"].set("-- Mbps")
        
        # 3. 更新狀態文字
        self.st_status.config(text="測速中...", fg="#e67e22")
        
        # 4. 啟動非同步執行緒
        threading.Thread(target=self.run_speedtest, daemon=True).start()
        
    def run_speedtest(self):
        """執行外部網路測速 (speedtest-cli)
        修正：解決 get_best_server 無法跳出的問題，並優化連線穩定度。
        """
        def _test_logic():
            try:
                # 1. 建立測速物件，縮短連線超時設定
                st = speedtest.Speedtest(secure=False, timeout=30)
                
                # 2. 獲取最佳伺服器 (直接獲取，不執行完整的 get_servers)
                self.root.after(0, lambda: self.st_status.config(text="尋找最佳伺服器...", fg="#e67e22"))
                
                # 尋找最佳測速伺服器
                st.get_best_server() 
                
                # 3. 執行下載測試
                self.root.after(0, lambda: self.st_status.config(text="下載測速中...", fg="#e67e22"))
                d = st.download(threads=None) / 1e6
                
                # 4. 執行上傳測試
                self.root.after(0, lambda: self.st_status.config(text="上傳測速中...", fg="#e67e22"))
                u = st.upload(threads=None, pre_allocate=False) / 1e6 # pre_allocate=False 減少記憶體佔用
                
                p = st.results.ping
                
                # 更新 UI
                self.root.after(0, lambda: [
                    self.st_vars["ping"].set(f"{p:.0f} ms"),
                    self.st_vars["dl"].set(f"{d:.2f} Mbps"),
                    self.st_vars["ul"].set(f"{u:.2f} Mbps"),
                    self.st_status.config(text="測速完成", fg="#2e7d32"),
                    self.test_btn.config(state="normal")
                ])
                
            except Exception as e:
                print(f"Speedtest 錯誤: {e}")
                self.root.after(0, lambda: [
                    self.st_status.config(text="測速失敗 (伺服器無回應)", fg="#c0392b"),
                    self.test_btn.config(state="normal")
                ])

        # 使用守護執行緒啟動測試
        t = threading.Thread(target=_test_logic, daemon=True)
        t.start()
        
        # 啟動一個超時監控程式，如果 180 秒後執行緒還在跑，強制恢復按鈕狀態
        def watchdog():
            time.sleep(180)
            if t.is_alive():
                self.root.after(0, lambda: [
                    self.st_status.config(text="測速超時已中止", fg="#c0392b"),
                    self.test_btn.config(state="normal")
                ])
        
        threading.Thread(target=watchdog, daemon=True).start()

    # --- SMS 相關輔助 ---
    def refresh_sms(self):
        if not self.is_connected: return        
        threading.Thread(target=self._fetch_sms_task, daemon=True).start()

    def _fetch_sms_task(self):
        try:
            sms_messages = self.client.sms.get_sms_list()
            messages = sms_messages.get("Messages", {}).get("Message", [])
            if isinstance(messages, dict): messages = [messages]
            
            # 回主執行緒更新 Treeview
            self.root.after(0, lambda: self._update_sms_ui(messages))
        except: 
            self.root.after(0, lambda: self.sms_count_var.set("讀取失敗"))
        

    def _update_sms_ui(self, messages):
        for i in self.sms_tree.get_children(): self.sms_tree.delete(i)
        self.sms_count_var.set(f"簡訊數: {len(messages)}")
        for m in messages:
            content = str(m.get('Content', ''))
            preview = content.replace('\n', ' ').replace('\r', '')
            self.sms_tree.insert("", "end", values=(m.get('Index'), m.get('Phone'), m.get('Date'), preview), tags=(content,))

    def on_sms_selected(self, event):
        sel = self.sms_tree.selection()
        if not sel: return
        full_content = self.sms_tree.item(sel[0], "tags")[0]
        self.sms_text.config(state="normal")
        self.sms_text.delete("1.0", tk.END)
        self.sms_text.insert("1.0", full_content)
        self.sms_text.config(state="disabled")

    def delete_sms(self):
        sel = self.sms_tree.selection()
        if not sel: 
            messagebox.showwarning("提示", "請先選取要刪除的簡訊")
            return
        if not messagebox.askyesno("確認", "確定要刪除選中的簡訊嗎？"): return
        def _del_task():
            try:
                idx = self.sms_tree.item(sel[0], "values")[0]
                self.client.sms.delete_sms(idx)
                self.root.after(0, lambda: [self._clear_sms_content(), self.refresh_sms()])
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("錯誤", f"刪除失敗: {e}"))
        threading.Thread(target=_del_task, daemon=True).start()

    def _clear_sms_content(self):
        self.sms_text.config(state="normal")
        self.sms_text.delete("1.0", tk.END)
        self.sms_text.config(state="disabled")

    # --- 資料持久化 ---
    def load_config(self):
        try:
            self.config.read(CONFIG_FILE)
            self.saved_ip = self.config.get("Settings", "ip", fallback="192.168.8.1")
            self.saved_pw = decrypt_password(self.config.get("Settings", "pw", fallback=""))
        except: self.saved_ip, self.saved_pw = "192.168.8.1", ""

    def save_config(self):
        if not self.config.has_section("Settings"): self.config.add_section("Settings")
        self.config.set("Settings", "ip", self.ip_entry.get())
        if self.remember_var.get(): 
            self.config.set("Settings", "pw", encrypt_password(self.pw_entry.get()))
        else: 
            self.config.remove_option("Settings", "pw")
        with open(CONFIG_FILE, "w") as f: self.config.write(f)

    def format_speed(self, s):
        s = int(s)
        return f"{s/1024:.1f} KB/s" if s < 1048576 else f"{s/1048576:.2f} MB/s"

if __name__ == "__main__":
    root = tk.Tk()
    app = RouterApp(root)
    root.mainloop()
