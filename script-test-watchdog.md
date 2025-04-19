حتماً! اینم یه **اسکریپت کامل و یکپارچه** که:

1. یه دایرکتوری رو به‌صورت **بازگشتی (recursive)** مانیتور می‌کنه؛  
2. هر وقت **فایل جدیدی** اضافه شد،  
3. اون فایل رو با API آنتی‌ویروست اسکن می‌کنه،  
4. اگه ویروسی بود، حذفش می‌کنه و لاگ می‌گیره.

---

### 🛠️ فایل نهایی: `multiav_monitor.py`

```python
import os
import time
import logging
import configparser
import requests
import warnings
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# suppress warnings
warnings.filterwarnings("ignore", category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

# Load config
config = configparser.ConfigParser()
config.read("config.conf")  # اگه جای دیگه‌ایه، آدرس رو تغییر بده

enabled = config.getboolean("MultiAV", "enabled", fallback=True)
if not enabled:
    print("🚫 تست توسط آنتی‌ویروس غیرفعال است.")
    exit(0)

ghoghnoos_ip = config.get("MultiAV", "ghoghnoos_ip")
apikey = config.get("MultiAV", "apikey")
scan_url = f"https://{ghoghnoos_ip}/multiav/api/scan"

# Logging setup
log_file = "/var/log/scan_log.txt"
os.makedirs(os.path.dirname(log_file), exist_ok=True)
logging.basicConfig(filename=log_file, level=logging.INFO, format='%(asctime)s - %(message)s')

# Function: Scan file
def scan_file(file_path):
    if not os.path.isfile(file_path):
        logging.error(f"File not found: {file_path}")
        return

    print(f"🛡️ در حال اسکن: {file_path}")
    data = {"apikey": apikey, "scantype": "file"}
    with open(file_path, "rb") as f:
        files = {"file": f}
        response = requests.post(scan_url, data=data, files=files, verify=False)

    logging.info(f"Scan upload status: {response.status_code} - {response.text}")
    if response.status_code != 200:
        print("❌ ارسال فایل برای اسکن با مشکل مواجه شد.")
        return

    result = response.json()
    if result.get("Status") != "Success":
        logging.error(f"API error: {result}")
        return

    scan_id = result.get("Unique_Scan_Identifier")
    if not scan_id:
        logging.error("Unique Scan Identifier is missing.")
        return

    result_url = f"https://{ghoghnoos_ip}/multiav/api/scan?ScanID={scan_id}"
    for _ in range(60):  # تا ۵ دقیقه منتظر بمون
        result_response = requests.get(result_url, verify=False)
        if result_response.status_code != 200:
            logging.error("Error getting scan result.")
            time.sleep(5)
            continue

        scan_result = result_response.json()
        status = scan_result['Scan']['Result']['Antiviruses_Results']['Status']
        if status == 2:  # Scan complete
            rate = scan_result['Scan']['Result']['Detection_Rate']
            if rate.startswith("0/"):
                print("✅ فایل پاک است.")
                logging.info(f"File clean: {file_path} - Rate: {rate}")
            else:
                print("⚠️ ویروس شناسایی شد!")
                logging.warning(f"Infected file: {file_path} - Rate: {rate}")
                try:
                    os.remove(file_path)
                    logging.info(f"Deleted infected file: {file_path}")
                except Exception as e:
                    logging.error(f"Error deleting file: {e}")
            break
        else:
            time.sleep(5)

# File system watcher
class NewFileHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory:
            scan_file(event.src_path)

def start_monitoring(directory):
    print(f"👀 مانیتور دایرکتوری: {directory}")
    event_handler = NewFileHandler()
    observer = Observer()
    observer.schedule(event_handler, path=directory, recursive=True)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("⛔ متوقف شد.")
        observer.stop()
    observer.join()

if __name__ == "__main__":
    watch_dir = config.get("MultiAV", "watch_directory", fallback="/tmp/watchme")
    os.makedirs(watch_dir, exist_ok=True)
    start_monitoring(watch_dir)
```

---

### 🧾 مثال فایل کانفیگ `config.conf`

```ini
[MultiAV]
enabled = yes
ghoghnoos_ip = 192.168.1.100
apikey = your_api_key_here
watch_directory = /home/user/Downloads
```

---

### 🚀 اجرای اسکریپت:
```bash
python3 multiav_monitor.py
```

---

ا


آره دقیقاً! اگه اسکریپتت رو به‌صورت **سرویس `systemd`** راه‌اندازی کنی:

### ✅ چه اتفاقی می‌افته؟

- **دائماً در حال اجراست**، حتی بعد از ری‌استارت سیستم.
- اگر سرویس به هر دلیلی کرش کنه یا قطع بشه، **systemd خودش دوباره اجراش می‌کنه**.
- همه فایل‌هایی که در دایرکتوری مشخص شده (و زیرشاخه‌هاش) ایجاد بشن، **بلافاصله شناسایی و اسکن می‌شن.**

---

## 🚀 مراحل ساخت سرویس systemd

### 1. اسکریپت رو بذار یه جای مطمئن، مثلاً:
```bash
sudo cp multiav_monitor.py /usr/local/bin/
sudo chmod +x /usr/local/bin/multiav_monitor.py
```

### 2. ساخت فایل سرویس systemd:

```bash
sudo nano /etc/systemd/system/multiav.service
```

🔽 محتواش این باشه:

```ini
[Unit]
Description=MultiAV Directory Monitor
After=network.target

[Service]
ExecStart=/usr/bin/python3 /usr/local/bin/multiav_monitor.py
Restart=always
User=root
WorkingDirectory=/usr/local/bin

[Install]
WantedBy=multi-user.target
```

### 3. فعال‌سازی سرویس:

```bash
sudo systemctl daemon-reexec
sudo systemctl daemon-reload
sudo systemctl enable multiav.service
sudo systemctl start multiav.service
```

### 4. بررسی وضعیت:

```bash
sudo systemctl status multiav.service
```

---

## 📦 نکات مهم:

- **دایرکتوری مانیتور‌شونده** باید در فایل `config.conf` مشخص بشه.
- مطمئن شو کاربر `root` یا کاربری که سرویس رو اجرا می‌کنه، به اون دایرکتوری دسترسی داره.
- برای دیدن لاگ‌ها:
  ```bash
  journalctl -u multiav.service -f
  ```

---

اگه خواستی لاگ‌ها رو تو فایل خاص بریزی یا بخوای به‌جای root با یه کاربر محدود اجراش کنی، می‌تونم تنظیماتشو برات بیارم. دوست داری یه نسخه‌ی آماده با `systemd` هم بسازم برات؟
