# AI System Call Optimizer

## Overview

The AI System Call Optimizer is a sophisticated Python-based application that provides real-time performance monitoring and intelligent optimization recommendations for system calls. Leveraging advanced machine learning techniques and system resource tracking, this tool helps developers and system administrators identify and mitigate performance bottlenecks.

## Features

- **Real-time Performance Tracking**: Continuously monitors system call performance metrics
- **AI-Powered Optimization Recommendations**:
  - Uses Groq's AI to generate intelligent optimization strategies
  - Fallback rule-based strategy when AI is unavailable
- **Resource Impact Analysis**:
  - Tracks CPU, memory, and disk I/O resource utilization
  - Identifies critical resource bottlenecks
- **Web Dashboard**:
  - Interactive visualization of performance metrics
  - Dynamic optimization recommendations
- **Flexible Configuration**:
  - Configurable performance thresholds
  - Supports custom learning rates

## Technologies Used

- **Backend**:
  - Python
  - Flask
  - Threading
  - NumPy
  - psutil
- **AI Integration**:
  - Groq API
  - Llama3-8b Model
- **Frontend**:
  - Tailwind CSS
  - Vanilla JavaScript
- **Environment**:
  - python-dotenv

## Prerequisites

- Python 3.8+
- Groq API Key (optional but recommended)
- pip package manager

## Installation

1. Clone the repository:
```bash
git clone https://github.com/CipherYuvraj/AI-Enhanced-System-Call-Optimization.git
cd AI-Enhanced-System-Call-Optimization
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Set up environment variables:
```bash
cp .env.example .env
# Edit .env and add your Groq API key
```

## Running the Application

```bash
python app.py
```

Navigate to `http://localhost:5001` to view the dashboard.

## Configuration

### Performance Threshold
Adjust the performance threshold in `AISystemCallOptimizer` initialization:
```python
syscall_optimizer = AISystemCallOptimizer(
    performance_threshold=0.05,  # Adjust as needed
    learning_rate=0.1
)
```

## Dashboard Screenshots

![Performance Metrics](./static/images/Screenshot%202025-03-28%20at%2012.14.00 PM.png)
![Optimization Recommendations](./static/images/Screenshot%202025-03-28%20at%2012.18.54 PM.png)

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

Distributed under the MIT License. See `LICENSE` for more information.

## Contact

Your Name - [parvaggarwal130@gmail.com](mailto:parvaggarwal130@gmail.com)

Project Link: [https://github.com/CipherYuvraj/AI-Enhanced-System-Call-Optimization.git](https://github.com/CipherYuvraj/AI-Enhanced-System-Call-Optimization.git)