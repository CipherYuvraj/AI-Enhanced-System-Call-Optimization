import os
import time
import threading
import numpy as np
from typing import Dict, List, Any
from dataclasses import dataclass, asdict
import psutil
from sklearn.cluster import KMeans
import pandas as pd
from flask import Flask, jsonify, render_template, request
from groq import Groq
from dotenv import load_dotenv
from bcc import BPF

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
    category: str  # Added category field for better organization

class AISystemCallOptimizer:
    def __init__(self, performance_threshold: float = 0.05, learning_rate: float = 0.1, groq_api_key: str = None):
        self.performance_records: Dict[str, SyscallPerformanceRecord] = {}
        self.optimization_history: List[Dict] = []
        self.recommendations_dict: Dict[str, str] = {}  # Store recommendations for each syscall
        self.performance_threshold = performance_threshold
        self.learning_rate = learning_rate
        self.lock = threading.Lock()
        self.global_resource_baseline = self._capture_system_resources()
        
        # Expanded syscall map with categories
        self.syscall_map = {
            # File operations
            0: {"name": "read", "category": "File I/O"},
            1: {"name": "write", "category": "File I/O"},
            2: {"name": "open", "category": "File I/O"},
            3: {"name": "close", "category": "File I/O"},
            4: {"name": "stat", "category": "File I/O"},
            5: {"name": "fstat", "category": "File I/O"},
            6: {"name": "lstat", "category": "File I/O"},
            8: {"name": "lseek", "category": "File I/O"},
            9: {"name": "mmap", "category": "Memory"},
            10: {"name": "mprotect", "category": "Memory"},
            11: {"name": "munmap", "category": "Memory"},
            13: {"name": "rt_sigaction", "category": "Signal"},
            14: {"name": "rt_sigprocmask", "category": "Signal"},
            21: {"name": "access", "category": "File I/O"},
            22: {"name": "pipe", "category": "IPC"},
            23: {"name": "select", "category": "I/O Multiplexing"},
            32: {"name": "dup", "category": "File I/O"},
            33: {"name": "dup2", "category": "File I/O"},
            39: {"name": "getpid", "category": "Process"},
            56: {"name": "clone", "category": "Process"},
            57: {"name": "fork", "category": "Process"},
            59: {"name": "execve", "category": "Process"},
            60: {"name": "exit", "category": "Process"},
            61: {"name": "wait4", "category": "Process"},
            62: {"name": "kill", "category": "Signal"},
            63: {"name": "uname", "category": "System"},
            72: {"name": "fcntl", "category": "File I/O"},
            78: {"name": "getdents", "category": "File I/O"},
            79: {"name": "getcwd", "category": "File I/O"},
            83: {"name": "mkdir", "category": "File I/O"},
            84: {"name": "rmdir", "category": "File I/O"},
            85: {"name": "creat", "category": "File I/O"},
            86: {"name": "link", "category": "File I/O"},
            87: {"name": "unlink", "category": "File I/O"},
            89: {"name": "readlink", "category": "File I/O"},
            90: {"name": "chmod", "category": "File I/O"},
            92: {"name": "chown", "category": "File I/O"},
            95: {"name": "umask", "category": "File I/O"},
            96: {"name": "gettimeofday", "category": "Time"},
            97: {"name": "getrlimit", "category": "Resource"},
            102: {"name": "getuid", "category": "User"},
            104: {"name": "getgid", "category": "User"},
            105: {"name": "setuid", "category": "User"},
            106: {"name": "setgid", "category": "User"},
            118: {"name": "fsync", "category": "File I/O"},
            137: {"name": "statfs", "category": "File System"},
            158: {"name": "arch_prctl", "category": "Architecture"},
            186: {"name": "gettid", "category": "Process"},
            202: {"name": "futex", "category": "Synchronization"},
            218: {"name": "set_tid_address", "category": "Process"},
            228: {"name": "clock_gettime", "category": "Time"},
            231: {"name": "exit_group", "category": "Process"},
            257: {"name": "openat", "category": "File I/O"},
            262: {"name": "newfstatat", "category": "File I/O"},
            293: {"name": "pipe2", "category": "IPC"}
        }

        if groq_api_key:
            self.groq_client = Groq(api_key=groq_api_key)
            print(f"Groq client initialized with API key: {groq_api_key[:5]}...")
        else:
            self.groq_client = None
            print("No Groq API key provided, falling back to rule-based strategy.")
        self.bpf = None
        self.start_ebpf_monitoring()
        threading.Thread(target=self.resource_monitoring_thread, daemon=True).start()
        
        # Set a consistent refresh interval (in seconds)
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
            time.sleep(1)  # Update baseline every second

    def start_ebpf_monitoring(self):
        bpf_code = """
        #include <uapi/linux/ptrace.h>

        struct syscall_data_t {
            u32 pid;        // Process ID
            u64 ts;         // Timestamp (nanoseconds)
            u32 syscall_nr; // System call number
        };

        BPF_HASH(start_times, u32, u64);         // Map to store start times
        BPF_PERF_OUTPUT(events);                 // Output buffer to user space

        int trace_sys_enter(struct bpf_raw_tracepoint_args *ctx) {
            u32 pid = bpf_get_current_pid_tgid() >> 32;
            u64 ts = bpf_ktime_get_ns();
            start_times.update(&pid, &ts);
            return 0;
        }

        int trace_sys_exit(struct bpf_raw_tracepoint_args *ctx) {
            u32 pid = bpf_get_current_pid_tgid() >> 32;
            u64 *start_ts = start_times.lookup(&pid);
            if (start_ts == 0) return 0;

            struct syscall_data_t data = {};
            data.pid = pid;
            data.ts = bpf_ktime_get_ns() - *start_ts;
            data.syscall_nr = ctx->args[1];
            events.perf_submit(ctx, &data, sizeof(data));
            start_times.delete(&pid);
            return 0;
        }
        """
        self.bpf = BPF(text=bpf_code)
        self.bpf.attach_raw_tracepoint(tp="sys_enter", fn_name="trace_sys_enter")
        self.bpf.attach_raw_tracepoint(tp="sys_exit", fn_name="trace_sys_exit")

        def process_event(cpu, data, size):
            event = self.bpf["events"].event(data)
            syscall_info = self.syscall_map.get(event.syscall_nr, {"name": f"unknown_{event.syscall_nr}", "category": "Unknown"})
            syscall_name = syscall_info["name"]
            syscall_category = syscall_info["category"]
            execution_time = event.ts / 1e9  # Convert ns to seconds
            self.record_syscall_performance(syscall_name, execution_time, syscall_category)

        self.bpf["events"].open_perf_buffer(process_event)
        threading.Thread(target=self.poll_ebpf_events, daemon=True).start()

    def poll_ebpf_events(self):
        while True:
            self.bpf.perf_buffer_poll()

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
                    resource_impact=aggregated_impact,
                    category=record.category
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
            
            # Update the recommendations dictionary
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

        # Category-based strategies
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
   

    def perform_kmeans_optimization(self, num_clusters=3):
        """
        Implements K-means clustering to identify and optimize system calls with similar performance characteristics.
        The function groups similar system calls together and applies targeted optimization strategies.
        
        Args:
            num_clusters (int): Number of clusters to create
            
        Returns:
            Dict: Cluster analysis and optimization recommendations
        """
        with self.lock:
            if len(self.performance_records) < num_clusters:
                return {"error": "Not enough system calls to perform clustering", "min_required": num_clusters}
            
            # Extract features for clustering
            syscalls = []
            features = []
            
            for syscall, record in self.performance_records.items():
                syscalls.append(syscall)
                # Create feature vector [avg_time, variance, cpu_impact, memory_impact, io_impact]
                feature_vector = [
                    record.average_time,
                    record.variance,
                    record.resource_impact.get('cpu_percent', 0),
                    record.resource_impact.get('memory_percent', 0),
                    record.resource_impact.get('disk_io_percent', 0)
                ]
                features.append(feature_vector)
            
            # Normalize features to prevent any single feature from dominating
            features_array = np.array(features)
            # Avoid division by zero
            std_devs = features_array.std(axis=0)
            std_devs[std_devs == 0] = 1
            normalized_features = (features_array - features_array.mean(axis=0)) / std_devs
            
            # Perform K-means clustering
            kmeans = KMeans(n_clusters=num_clusters, random_state=42)
            cluster_labels = kmeans.fit_predict(normalized_features)
            
            # Analyze clusters
            clusters = {}
            for i in range(num_clusters):
                cluster_syscalls = [syscalls[j] for j in range(len(syscalls)) if cluster_labels[j] == i]
                cluster_features = features_array[[j for j in range(len(syscalls)) if cluster_labels[j] == i]]
                
                # Calculate cluster characteristics
                avg_execution_time = np.mean(cluster_features[:, 0])
                avg_variance = np.mean(cluster_features[:, 1])
                avg_cpu_impact = np.mean(cluster_features[:, 2])
                avg_memory_impact = np.mean(cluster_features[:, 3])
                avg_io_impact = np.mean(cluster_features[:, 4])
                
                # Determine dominant resource constraints
                resource_impacts = [avg_cpu_impact, avg_memory_impact, avg_io_impact]
                resource_types = ['CPU', 'Memory', 'Disk I/O']
                dominant_resource = resource_types[np.argmax(resource_impacts)]
                
                # Generate cluster-specific optimization strategy
                if dominant_resource == 'CPU':
                    if avg_execution_time > self.performance_threshold * 2:
                        strategy = "Apply CPU-specific batching and parallelization for these syscalls"
                    else:
                        strategy = "Monitor and optimize CPU scheduler affinity for these syscalls"
                elif dominant_resource == 'Memory':
                    strategy = "Implement memory pooling and reduce allocation frequency for these syscalls"
                else:  # Disk I/O
                    strategy = "Apply I/O batching and asynchronous operations for these syscalls"
                
                # Store cluster analysis
                clusters[f"cluster_{i}"] = {
                    "syscalls": cluster_syscalls,
                    "avg_execution_time": avg_execution_time,
                    "avg_variance": avg_variance,
                    "dominant_resource": dominant_resource,
                    "resource_impacts": {
                        "cpu": avg_cpu_impact,
                        "memory": avg_memory_impact,
                        "io": avg_io_impact
                    },
                    "optimization_strategy": strategy
                }
                
                # Update recommendations for syscalls in this cluster
                for syscall in cluster_syscalls:
                    cluster_specific_rec = f"[Cluster {i} optimization] {strategy} (grouped with {len(cluster_syscalls)-1} similar syscalls)"
                    if syscall in self.recommendations_dict:
                        self.recommendations_dict[syscall] += f" Additionally: {cluster_specific_rec}"
                    else:
                        self.recommendations_dict[syscall] = cluster_specific_rec
            
            return {
                "num_clusters": num_clusters,
                "clusters": clusters,
                "analysis": "K-means clustering identified syscall patterns based on performance characteristics"
            }

# Load API key and initialize optimizer
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

@app.route('/kmeans_optimize', methods=['GET', 'POST'])
def kmeans_optimize():
    if request.method == 'POST':
        try:
            num_clusters = int(request.form.get('num_clusters', 3))
        except ValueError:
            num_clusters = 3
    else:
        num_clusters = int(request.args.get('num_clusters', 3))
         
    return jsonify(syscall_optimizer.perform_kmeans_optimization(num_clusters=num_clusters))

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))  # Default to 5000 locally
    app.run(host='0.0.0.0', port=port)