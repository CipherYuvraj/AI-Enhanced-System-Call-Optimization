import os
import time
import threading
import numpy as np
from typing import Dict, List, Any
from dataclasses import dataclass, asdict
import psutil
from flask import Flask, jsonify, render_template
from groq import Groq
from dotenv import load_dotenv

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

class AISystemCallOptimizer:
    def __init__(self, performance_threshold: float = 0.05, learning_rate: float = 0.1, groq_api_key: str = None):
        self.performance_records: Dict[str, SyscallPerformanceRecord] = {}
        self.optimization_history: List[Dict] = []
        self.performance_threshold = performance_threshold
        self.learning_rate = learning_rate
        self.lock = threading.Lock()
        self.global_resource_baseline = self._capture_system_resources()
        if groq_api_key:
            self.groq_client = Groq(api_key=groq_api_key)
            print(f"Groq client initialized with API key: {groq_api_key[:5]}...")
        else:
            self.groq_client = None
            print("No Groq API key provided, falling back to rule-based strategy.")

    def _capture_system_resources(self) -> Dict[str, float]:
        return {
            'cpu_percent': psutil.cpu_percent(interval=0.1),
            'memory_percent': psutil.virtual_memory().percent,
            'disk_io_percent': psutil.disk_usage('/').percent
        }

    def record_syscall_performance(self, syscall_name: str, execution_time: float):
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
                    resource_impact=resource_impact
                )
            else:
                record = self.performance_records[syscall_name]
                total_executions = record.execution_count + 1
                new_average = (
                    record.average_time * record.execution_count + execution_time
                ) / total_executions
                variance = np.var([record.average_time, execution_time])

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
                    resource_impact=aggregated_impact
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
                        "resource_impact": record.resource_impact
                    }
                    recommendations.append(recommendation)

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

        strategies = [
            f"Implement advanced caching for {record.name}",
            f"Optimize memory allocation for {record.name}",
            f"Implement adaptive batching for {record.name}",
            f"Create intelligent parallelization strategy for {record.name}",
            f"Apply machine learning-based optimization for {record.name}"
        ]
        resource_weights = {
            'cpu_percent': record.resource_impact.get('cpu_percent', 0),
            'memory_percent': record.resource_impact.get('memory_percent', 0),
            'disk_io_percent': record.resource_impact.get('disk_io_percent', 0)
        }
        max_resource_type = max(resource_weights, key=resource_weights.get)
        strategy_index = {
            'cpu_percent': 3,
            'memory_percent': 1,
            'disk_io_percent': 2
        }.get(max_resource_type, 0)
        return strategies[strategy_index]

    def get_performance_data(self) -> Dict[str, Any]:
        with self.lock:
            return {k: asdict(v) for k, v in self.performance_records.items()}

# Load API key and initialize optimizer
groq_api_key = os.environ.get("GROQ_API_KEY")
if not groq_api_key:
    print("Warning: GROQ_API_KEY not found in environment variables.")
syscall_optimizer = AISystemCallOptimizer(groq_api_key=groq_api_key)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/performance')
def get_performance():
    return jsonify(syscall_optimizer.get_performance_data())

@app.route('/recommendations')
def get_recommendations():
    return jsonify(syscall_optimizer.generate_optimization_strategy())

def simulation_thread():
    syscalls = ["read_file", "write_db", "compute_hash", "network_request"]
    while True:
        syscall = np.random.choice(syscalls)
        execution_time = np.random.uniform(0.01, 0.1)
        syscall_optimizer.record_syscall_performance(syscall, execution_time)
        time.sleep(np.random.uniform(0.5, 2))

# Start the simulation thread globally
threading.Thread(target=simulation_thread, daemon=True).start()

if __name__ == "__main__":
    # For local development only (Windows or otherwise)
    port = int(os.environ.get("PORT", 5001))  # Default to 5000 locally
    app.run(host='0.0.0.0', port=port)