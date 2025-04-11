# AI System Call Optimizer


A real-time system call monitoring and optimization tool using **eBPF**, **Flask**, and optional **AI (Groq API)** for performance analysis and smart recommendations.

![Performance-Metrics](./static/images/Screenshot%20from%202025-04-05%2014-50-08.png)
![Interface](./static/images/Screenshot%20from%202025-04-05%2014-50-20.png)
![Optimization-Recommendations](./static/images/Screenshot%20from%202025-04-05%2014-50-23.png)

## 📌 Features

- 🟢 Real-time monitoring with eBPF
- 📊 Execution time & resource metrics (CPU, memory, I/O)
- 📁 Categorization of syscalls: File I/O, Process, Memory, IPC, etc.
- 🤖 AI-generated optimization tips (Groq API)
- 🛠️ Rule-based fallback suggestions
- 🌐 Clean Flask web UI with auto-refresh
- 🔍 API endpoints for programmatic access

---

## ⚙️ System Requirements

- Linux with eBPF support (Kernel ≥ 4.1)
- Python 3.6+
- BCC (BPF Compiler Collection)

---

## 🛠️ Installation

### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/ai-system-call-optimizer.git
cd ai-system-call-optimizer
```

### 2. Install Python Dependencies
```bash
pip install -r requirements.txt
```

> 🔸 **Note**: The `bcc` Python package requires BCC system packages. Install them first.

### 3. Install BCC System Package

#### On Ubuntu:
```bash
sudo apt-get install bpfcc-tools linux-headers-$(uname -r)
```

#### On Other Distros:
Refer to the [official BCC installation guide](https://github.com/iovisor/bcc/blob/master/INSTALL.md).

---

## 🚀 Usage

### 1. Set the Groq API Key (Optional)
To enable AI optimization:
```bash
export GROQ_API_KEY=your_api_key_here
```

### 2. Start the Flask Application
```bash
python app.py
```

### 3. Run on a Different Port (Optional)
```bash
export PORT=8080
python app.py
```

### 4. Open the Web Interface
Visit: [http://localhost:5000](http://localhost:5000)
(The page auto-refreshes every 5 seconds.)

---

## 🔌 API Endpoints

| Endpoint                  | Description                                           |
|---------------------------|-------------------------------------------------------|
| `/performance`           | Get live syscall performance data                     |
| `/recommendations`       | Get AI-based or rule-based optimization suggestions   |
| `/categories`            | View syscall categories and groupings                 |
| `/syscall/<syscall>`     | Get detailed metrics for a specific syscall           |

Example:
```bash
curl http://localhost:5000/syscall/write
```

---

## 🛠️ Configuration

- **Groq API Key**: Set `GROQ_API_KEY` as an environment variable.
- **Performance Threshold**: Defined in `AISystemCallOptimizer` (default: `0.05s`)
- **Refresh Interval**: Modify `REFRESH_INTERVAL` (default: `5` seconds)

---

## ⚡ Performance Considerations

- eBPF overhead is minimal but can slightly impact very high-load systems.
- Groq API calls are async/lightweight and do not block real-time monitoring.

---

## 🔒 Security

- Requires **root** to attach eBPF probes:
```bash
sudo python app.py
```

- Ensure the host system is secure. eBPF can access kernel-level metrics.

---

## 🤝 Contributing

We love contributions! Here’s how to get started:

1. Fork the repo
2. Create a new branch (`git checkout -b feature-name`)
3. Commit your changes
4. Push to your branch (`git push origin feature-name`)
5. Open a Pull Request 🚀

You can also:
- Open Issues for bugs or feature suggestions
- Discuss ideas via GitHub Discussions

---

## 📄 License

This project is licensed under the **MIT License**.
See the `LICENSE` file for full details.

---

## 📝 Additional Notes

- 📷 **Screenshot Placeholder**: Replace `path/to/screenshot.png` above with your image file or a hosted URL.
- 📦 **requirements.txt**:
```
Flask
groq
psutil
bcc
numpy
python-dotenv
```
---