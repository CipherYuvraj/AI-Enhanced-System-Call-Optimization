import os
import time
import threading
import numpy as np
from typing import Dict, List, Any
from dataclasses import dataclass, asdict
import psutil
from flask import Flask, jsonify, render_template, request
from groq import Groq
from dotenv import load_dotenv
import subprocess
import queue

# Load environment variables
load_dotenv()

# Flask app setup
app = Flask(__name__)

@dataclass
class SyscallPerformanceRecord:
    name: str
    average_time: float
    execution_count: int
    variance: float
    peak_performance: float
    last_optimized: float
    resource_impact: Dict[str, float]
    category: str

class AISystemCallOptimizer:
    def __init__(self, performance_threshold: float = 0.05, learning_rate: float = 0.1, groq_api_key: str = None):
        self.performance_records: Dict[str, SyscallPerformanceRecord] = {}
        self.optimization_history: List[Dict] = []
        self.recommendations_dict: Dict[str, str] = {}
        self.performance_threshold = performance_threshold
        self.learning_rate = learning_rate
        self.lock = threading.Lock()
        self.global_resource_baseline = self._capture_system_resources()
        self.syscall_queue = queue.Queue()

        self.syscall_categories = {
            "read": "File I/O",
            "write": "File I/O",
            "open": "File I/O",
            "close": "File I/O",
            "mmap": "Memory",
            "munmap": "Memory",
            "getpid": "Process",
            "fork": "Process",
            "execve": "Process",
            "exit": "Process",
            "gettimeofday": "Time",
            "clock_gettime": "Time",
            "fsync": "File I/O",
            "stat": "File I/O",
            "lstat": "File I/O",
            "fstat": "File I/O",
            "access": "File I/O",
            "pipe": "IPC",
            "dup": "File I/O",
            "fcntl": "File I/O",
            "kill": "Signal"
        }

        if groq_api_key:
            self.groq_client = Groq(api_key=groq_api_key)
            print(f"Groq client initialized with API key: {groq_api_key[:5]}...")
        else:
            self.groq_client = None
            print("No Groq API key provided, falling back to rule-based strategy.")

        threading.Thread(target=self.resource_monitoring_thread, daemon=True).start()
        threading.Thread(target=self.start_dtrace_monitoring, daemon=True).start()
        threading.Thread(target=self.process_syscall_queue, daemon=True).start()

        self.refresh_interval = 5
        print(f"Performance data will refresh every {self.refresh_interval} seconds")

    def _capture_system_resources(self) -> Dict[str, float]:
        return {
            'cpu_percent': psutil.cpu_percent(interval=0.1),
            'memory_percent': psutil.virtual_memory().percent,
            'disk_io_percent': psutil.disk_usage('/').percent
        }

    def resource_monitoring_thread(self):
        while True:
            self.global_resource_baseline = self._capture_system_resources()
            time.sleep(1)

    def start_dtrace_monitoring(self):
        """Run dtrace to monitor system calls on macOS with debugging output."""
        dtrace_script = """
        syscall:::entry
        {
            self->ts[probefunc] = timestamp;
        }
        syscall:::return
        /self->ts[probefunc]/
        {
            printf("%s %d\\n", probefunc, (timestamp - self->ts[probefunc]));
            self->ts[probefunc] = 0;
        }
        """
        with open("/tmp/syscall_trace.d", "w") as f:
            f.write(dtrace_script)

        cmd = ["sudo", "dtrace", "-s", "/tmp/syscall_trace.d"]
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        print("Started dtrace monitoring. Perform system actions (e.g., 'ls', 'cat') to see syscalls.")
        while True:
            line = process.stdout.readline().strip()
            if line:
                try:
                    syscall_name, duration_ns = line.split()
                    duration_sec = int(duration_ns) / 1e9
                    category = self.syscall_categories.get(syscall_name, "Unknown")
                    print(f"Captured syscall: {syscall_name}, Duration: {duration_sec:.6f}s, Category: {category}")
                    self.syscall_queue.put((syscall_name, duration_sec, category))
                except ValueError:
                    print(f"Failed to parse dtrace output: {line}")
                    continue

    def process_syscall_queue(self):
        while True:
            try:
                syscall_name, execution_time, category = self.syscall_queue.get(timeout=1)
                self.record_syscall_performance(syscall_name, execution_time, category)
                self.syscall_queue.task_done()
            except queue.Empty:
                time.sleep(0.1)

    def record_syscall_performance(self, syscall_name: str, execution_time: float, category: str = "Unknown"):
        with self.lock:
            current_resources = self._capture_system_resources()
            resource_impact = {
                k: max(0, current_resources[k] - self.global_resource_baseline.get(k, 0))
                for k in current_resources
            }

            if syscall_name not in self.performance_records:
                self.performance_records[syscall_name] = SyscallPerformanceRecord(
                    name=syscall_name,
                    average_time=execution_time,
                    execution_count=1,
                    variance=0,
                    peak_performance=execution_time,
                    last_optimized=time.time(),
                    resource_impact=resource_impact,
                    category=category
                )
            else:
                record = self.performance_records[syscall_name]
                total_executions = record.execution_count + 1
                new_average = (
                    record.average_time * record.execution_count + execution_time
                ) / total_executions
                variance = np.var([record.average_time, execution_time]) if total_executions > 1 else 0

                aggregated_impact = {
                    k: (record.resource_impact.get(k, 0) * record.execution_count +
                        resource_impact.get(k, 0)) / total_executions
                    for k in set(record.resource_impact) | set(resource_impact)
                }

                self.performance_records[syscall_name] = SyscallPerformanceRecord(
                    name=syscall_name,
                    average_time=new_average,
                    execution_count=total_executions,
                    variance=variance,
                    peak_performance=min(record.peak_performance, execution_time),
                    last_optimized=record.last_optimized,
                    resource_impact=aggregated_impact,
                    category=category
                )

    def generate_optimization_strategy(self) -> List[Dict[str, Any]]:
        recommendations = []
        with self.lock:
            for syscall, record in self.performance_records.items():
                if (record.average_time > self.performance_threshold or
                    any(impact > 50 for impact in record.resource_impact.values())):
                    recommendation = {
                        "syscall": syscall,
                        "current_performance": record.average_time,
                        "recommendation_type": self._get_recommendation_type(record),
                        "suggested_action": self._generate_mitigation_strategy(record),
                        "resource_impact": record.resource_impact,
                        "category": record.category
                    }
                    recommendations.append(recommendation)

            self.recommendations_dict = {rec['syscall']: rec['suggested_action'] for rec in recommendations}

            self.optimization_history.append({
                "timestamp": time.time(),
                "system_resources": self._capture_system_resources(),
                "recommendations": recommendations
            })
        return recommendations

    def _get_recommendation_type(self, record: SyscallPerformanceRecord) -> str:
        high_resource_impact = any(impact > 50 for impact in record.resource_impact.values())
        if high_resource_impact:
            return "CRITICAL_RESOURCE_BOTTLENECK"
        elif record.variance > record.average_time * 0.5:
            return "HIGH_VARIABILITY"
        elif record.average_time > self.performance_threshold * 2:
            return "SEVERE_PERFORMANCE_ISSUE"
        else:
            return "MODERATE_OPTIMIZATION"

    def _generate_mitigation_strategy(self, record: SyscallPerformanceRecord) -> str:
        if self.groq_client:
            prompt = f"""
You are an AI assistant specialized in system performance optimization. Based on the following performance data for a system call, suggest a specific and concise optimization strategy to improve its performance or reduce its resource usage. Provide a brief, actionable suggestion in plain text, in one or two sentences, without code or special formatting.

System Call: {record.name}
Category: {record.category}
Average Execution Time: {record.average_time:.4f} seconds
Variance: {record.variance:.4f}
Peak Performance: {record.peak_performance:.4f} seconds
Resource Impacts:
- CPU: {record.resource_impact.get('cpu_percent', 0):.2f}%
- Memory: {record.resource_impact.get('memory_percent', 0):.2f}%
- Disk I/O: {record.resource_impact.get('disk_io_percent', 0):.2f}%
"""
            try:
                response = self.groq_client.chat.completions.create(
                    model="llama3-8b-8192",
                    messages=[
                        {"role": "system", "content": "You are an AI assistant specialized in system performance optimization. Provide your suggestions in plain text without code or special formatting."},
                        {"role": "user", "content": prompt}
                    ],
                    max_tokens=75,
                    temperature=0.7
                )
                suggestion = response.choices[0].message.content.strip()
                if suggestion:
                    suggestion = ' '.join(suggestion.split())
                    return suggestion
                else:
                    print("AI returned empty suggestion, falling back to rule-based strategy.")
            except Exception as e:
                print(f"Error generating strategy with Groq API: {e}")

        category_strategies = {
            "File I/O": [
                f"Implement buffered I/O for {record.name} to reduce system call frequency",
                f"Use asynchronous I/O for {record.name} operations to avoid blocking",
                f"Consider memory-mapped files instead of direct {record.name} calls"
            ],
            "Memory": [
                f"Optimize memory allocation patterns around {record.name}",
                f"Consider using huge pages to reduce {record.name} overhead",
                f"Implement memory pooling to reduce fragmentation in {record.name}"
            ],
            "Process": [
                f"Minimize {record.name} calls through process reuse",
                f"Use thread pools instead of frequent {record.name} calls",
                f"Implement process caching for {record.name} operations"
            ],
            "Synchronization": [
                f"Reduce lock contention around {record.name}",
                f"Use lock-free algorithms when possible to avoid {record.name}",
                f"Implement batching to reduce {record.name} frequency"
            ],
            "IPC": [
                f"Use shared memory instead of pipes for {record.name}",
                f"Batch messages to reduce {record.name} overhead",
                f"Consider using zero-copy techniques for {record.name}"
            ],
            "Time": [
                f"Cache time values to reduce {record.name} frequency",
                f"Use monotonic clocks for performance-sensitive code around {record.name}",
                f"Batch operations that require timestamp from {record.name}"
            ]
        }

        if record.category in category_strategies:
            strategies = category_strategies[record.category]
        else:
            strategies = [
                f"Implement advanced caching for {record.name}",
                f"Optimize memory allocation for {record.name}",
                f"Implement adaptive batching for {record.name}"
            ]

        resource_weights = {
            'cpu_percent': record.resource_impact.get('cpu_percent', 0),
            'memory_percent': record.resource_impact.get('memory_percent', 0),
            'disk_io_percent': record.resource_impact.get('disk_io_percent', 0)
        }
        max_resource_type = max(resource_weights, key=resource_weights.get)
        strategy_index = min(int(resource_weights[max_resource_type] / 20), len(strategies) - 1)
        return strategies[strategy_index]

    def get_performance_data(self) -> Dict[str, Any]:
        with self.lock:
            data = {}
            for k, v in self.performance_records.items():
                record_dict = asdict(v)
                record_dict['recommendation'] = self.recommendations_dict.get(k, '')
                data[k] = record_dict
            return data

    def get_refresh_interval(self) -> int:
        return self.refresh_interval

    def get_syscall_categories(self) -> Dict[str, List[str]]:
        categories = {}
        with self.lock:
            for syscall, record in self.performance_records.items():
                category = record.category
                if category not in categories:
                    categories[category] = []
                categories[category].append(syscall)
        return categories

    def get_syscall_details(self, syscall_name: str) -> Dict[str, Any]:
        with self.lock:
            if syscall_name in self.performance_records:
                record_dict = asdict(self.performance_records[syscall_name])
                record_dict['recommendation'] = self.recommendations_dict.get(syscall_name, '')
                return record_dict
            return {"error": "System call not found"}

groq_api_key = os.environ.get("GROQ_API_KEY")
if not groq_api_key:
    print("Warning: GROQ_API_KEY not found in environment variables.")
syscall_optimizer = AISystemCallOptimizer(groq_api_key=groq_api_key)

@app.route('/')
def index():
    return render_template('index.html', refresh_interval=syscall_optimizer.get_refresh_interval())

@app.route('/performance')
def get_performance():
    return jsonify(syscall_optimizer.get_performance_data())

@app.route('/recommendations')
def get_recommendations():
    return jsonify(syscall_optimizer.generate_optimization_strategy())

@app.route('/categories')
def get_categories():
    return jsonify(syscall_optimizer.get_syscall_categories())

@app.route('/syscall/<syscall_name>')
def get_syscall_details(syscall_name):
    return jsonify(syscall_optimizer.get_syscall_details(syscall_name))

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5001))
    print("Note: This script requires sudo privileges to run dtrace on macOS.")
    app.run(host='0.0.0.0', port=port)