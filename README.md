# MultiAV File Scanner

## ✨ Overview
This script allows you to scan files using the **MultiAV API**. It uploads a file, retrieves scan results, and takes action based on the detection outcome.

## 🛠️ Features
- Uploads files for scanning via MultiAV API
- Logs scan results and status
- Deletes infected files automatically
- Configurable via `config.conf`

## 🔧 Requirements
- Python 3.x
- `requests` library
- `configparser` library

## ⚡ Installation
1. Clone the repository:
   ```sh
   git clone https://github.com/milad6745/MultiAv.git
   cd MultiAv
   ```
2. Install dependencies:
   ```sh
   pip install -r requirements.txt
   ```

## 🔧 Configuration
Modify `config.conf` with your **API key** and **MultiAV server IP**:
```ini
[MultiAV]
enabled = true
ghoghnoos_ip = YOUR_SERVER_IP
apikey = YOUR_API_KEY
```

## ⚖️ Usage
Run the script with:
```sh
python scanner.py <file_name> <working_directory>
```
Example:
```sh
python scanner.py test.exe /home/user/downloads
```

## 🔎 How It Works
1. Reads API key and server IP from `config.conf`
2. Uploads the specified file to MultiAV API
3. Waits for scan completion
4. Logs and displays the scan result
5. If the file is infected, it is **automatically deleted**

## 📝 Logging
- Logs are saved in `scan_log.txt` inside the working directory.

## 🚀 Contribution
Feel free to submit issues or pull requests for improvements.

## 💎 License
This project is licensed under the **MIT License**.

