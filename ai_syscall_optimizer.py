import os
import time
import threading
import subprocess
from typing import Dict, List, Any, Tuple, Optional
from dataclasses import dataclass, asdict
import psutil
from flask import Flask, jsonify, render_template, request
from groq import Groq
from dotenv import load_dotenv
from bcc import BPF
from functools import lru_cache
from time import time
import numpy as np

# Add these variables before your routes
last_performance_update = 0
cached_performance_data = None

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
    optimization_applied: bool = False
    optimization_results: List[Dict[str, Any]] = None

@dataclass
class OptimizationStatus:
    syscall: str
    strategy: str
    status: str  # "pending", "applied", "failed"
    applied_at: float
    before_metrics: Dict[str, float]
    after_metrics: Dict[str, float] = None
    improvement_percentage: float = 0.0

class AISystemCallOptimizer:
    def __init__(self, performance_threshold: float = 0.05, learning_rate: float = 0.1, groq_api_key: str = None, 
                 auto_optimize: bool = True):
        self.performance_records: Dict[str, SyscallPerformanceRecord] = {}
        self.optimization_history: List[Dict] = []
        self.recommendations_dict: Dict[str, str] = {}
        self.performance_threshold = performance_threshold
        self.learning_rate = learning_rate
        self.lock = threading.Lock()
        self.queue_condition = threading.Condition(self.lock)
        self.global_resource_baseline = self._capture_system_resources()
        self.optimization_queue: List[OptimizationStatus] = []
        self.auto_optimize = auto_optimize
        self.optimization_in_progress = False
        
        # Expanded syscall map with categories
        self.syscall_map = {
            0: {"name": "read", "category": "File I/O"}, 1: {"name": "write", "category": "File I/O"},
            2: {"name": "open", "category": "File I/O"}, 3: {"name": "close", "category": "File I/O"},
            4: {"name": "stat", "category": "File I/O"}, 5: {"name": "fstat", "category": "File I/O"},
            6: {"name": "lstat", "category": "File I/O"}, 8: {"name": "lseek", "category": "File I/O"},
            9: {"name": "mmap", "category": "Memory"}, 10: {"name": "mprotect", "category": "Memory"},
            11: {"name": "munmap", "category": "Memory"}, 13: {"name": "rt_sigaction", "category": "Signal"},
            14: {"name": "rt_sigprocmask", "category": "Signal"}, 21: {"name": "access", "category": "File I/O"},
            22: {"name": "pipe", "category": "IPC"}, 23: {"name": "select", "category": "I/O Multiplexing"},
            32: {"name": "dup", "category": "File I/O"}, 33: {"name": "dup2", "category": "File I/O"},
            39: {"name": "getpid", "category": "Process"}, 56: {"name": "clone", "category": "Process"},
            57: {"name": "fork", "category": "Process"}, 59: {"name": "execve", "category": "Process"},
            60: {"name": "exit", "category": "Process"}, 61: {"name": "wait4", "category": "Process"},
            62: {"name": "kill", "category": "Signal"}, 63: {"name": "uname", "category": "System"},
            72: {"name": "fcntl", "category": "File I/O"}, 78: {"name": "getdents", "category": "File I/O"},
            79: {"name": "getcwd", "category": "File I/O"}, 83: {"name": "mkdir", "category": "File I/O"},
            84: {"name": "rmdir", "category": "File I/O"}, 85: {"name": "creat", "category": "File I/O"},
            86: {"name": "link", "category": "File I/O"}, 87: {"name": "unlink", "category": "File I/O"},
            89: {"name": "readlink", "category": "File I/O"}, 90: {"name": "chmod", "category": "File I/O"},
            92: {"name": "chown", "category": "File I/O"}, 95: {"name": "umask", "category": "File I/O"},
            96: {"name": "gettimeofday", "category": "Time"}, 97: {"name": "getrlimit", "category": "Resource"},
            102: {"name": "getuid", "category": "User"}, 104: {"name": "getgid", "category": "User"},
            105: {"name": "setuid", "category": "User"}, 106: {"name": "setgid", "category": "User"},
            118: {"name": "fsync", "category": "File I/O"}, 137: {"name": "statfs", "category": "File System"},
            158: {"name": "arch_prctl", "category": "Architecture"}, 186: {"name": "gettid", "category": "Process"},
            202: {"name": "futex", "category": "Synchronization"}, 218: {"name": "set_tid_address", "category": "Process"},
            228: {"name": "clock_gettime", "category": "Time"}, 231: {"name": "exit_group", "category": "Process"},
            257: {"name": "openat", "category": "File I/O"}, 262: {"name": "newfstatat", "category": "File I/O"},
            293: {"name": "pipe2", "category": "IPC"}
        }

        # System-level optimization config by category
        self.optimization_configs = {
            "File I/O": {"sysctl_params": {"vm.dirty_ratio": 10, "vm.dirty_background_ratio": 5, "vm.vfs_cache_pressure": 50}, "io_scheduler": "deadline"},
            "Memory": {"sysctl_params": {"vm.swappiness": 10, "vm.min_free_kbytes": 65536, "vm.zone_reclaim_mode": 0}, "transparent_hugepages": "madvise"},
            "Process": {"sysctl_params": {"kernel.sched_migration_cost_ns": 5000000, "kernel.sched_autogroup_enabled": 0}, "nice_level": -10},
            "Synchronization": {"sysctl_params": {"kernel.sched_min_granularity_ns": 10000000, "kernel.sched_wakeup_granularity_ns": 15000000}},
            "IPC": {"sysctl_params": {"fs.pipe-max-size": 1048576, "kernel.msgmax": 65536}},
            "Time": {"sysctl_params": {"kernel.timer_migration": 0}, "clocksource": "tsc"}
        }

        # Category-specific optimization strategies
        self.category_strategies = {
            "File I/O": [
                "Implement buffered I/O to reduce system call frequency",
                "Use asynchronous I/O for operations to avoid blocking",
                "Consider memory-mapped files instead of direct calls",
                "Batch small reads/writes into larger operations",
                "Use direct I/O for large sequential operations"
            ],
            "Memory": [
                "Optimize memory allocation patterns to reduce fragmentation",
                "Consider using huge pages to reduce overhead",
                "Implement memory pooling for frequent allocations/deallocations",
                "Preallocate memory when possible to avoid runtime allocations",
                "Use shared memory for inter-process communication"
            ],
            "Process": [
                "Minimize fork/clone calls through process reuse",
                "Use thread pools instead of frequent process creation",
                "Implement process caching for recurring operations",
                "Consider using lightweight threads where applicable",
                "Optimize scheduling priorities for critical processes"
            ],
            "Synchronization": [
                "Reduce lock contention through finer-grained locking",
                "Use lock-free algorithms when possible",
                "Implement batching to reduce synchronization frequency",
                "Consider using RCU (Read-Copy-Update) for read-heavy workloads",
                "Optimize futex usage with adaptive waiting strategies"
            ],
            "IPC": [
                "Use shared memory instead of pipes for large data transfers",
                "Batch messages to reduce overhead",
                "Consider using zero-copy techniques for efficiency",
                "Use vectored I/O for multiple data segments",
                "Implement message coalescing for small messages"
            ],
            "Time": [
                "Cache time values to reduce syscall frequency",
                "Use monotonic clocks for performance-sensitive code",
                "Batch operations that require timestamps",
                "Consider using coarse-grained timers when precision isn't critical",
                "Implement timer wheels for efficient event scheduling"
            ],
            "Unknown": [
                "Implement advanced caching mechanisms",
                "Optimize memory allocation patterns",
                "Implement adaptive batching strategies",
                "Create intelligent parallelization strategies",
                "Apply machine learning-based optimization techniques"
            ]
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
        
        if self.auto_optimize:
            threading.Thread(target=self.optimization_worker_thread, daemon=True).start()
            print("Auto-optimization enabled. Optimization worker thread started.")
        
        self.refresh_interval = 5
        print(f"Performance data will refresh every {self.refresh_interval} seconds")

    def _capture_system_resources(self) -> Dict[str, float]:
        return {
            'cpu_percent': psutil.cpu_percent(),
            'memory_percent': psutil.virtual_memory().percent,
            'disk_io_percent': psutil.disk_usage('/').percent
        }

    def resource_monitoring_thread(self):
        while True:
            try:
                self.global_resource_baseline = self._capture_system_resources()
                time.sleep(10)  # Increased from 5 to 10 seconds
            except Exception as e:
                print(f"Resource monitoring error: {e}")
                time.sleep(5)  # Reduced frequency on error

    def optimization_worker_thread(self):
        while True:
            optimization_task = None
            try:
                with self.queue_condition:
                    # Wait until there's work or a timeout occurs
                    while not self.optimization_queue or self.optimization_in_progress:
                        if not self.queue_condition.wait(timeout=2.0):
                            break  # Exit the inner loop on timeout
                    
                    if self.optimization_queue and not self.optimization_in_progress:
                        # Prioritize task with highest average time
                        optimization_task = max(self.optimization_queue, key=lambda t: t.before_metrics['average_time'])
                        self.optimization_queue.remove(optimization_task)
                        self.optimization_in_progress = True
                
                # Only process if we got a task
                if optimization_task:
                    success, after_metrics = self._apply_optimization(optimization_task)
                    
                    with self.lock:
                        # Update task status based on optimization results
                        if success and after_metrics:
                            optimization_task.status = "applied"
                            optimization_task.after_metrics = after_metrics
                            # Calculate improvement percentage
                            if optimization_task.before_metrics['average_time'] > 0:
                                improvement = ((optimization_task.before_metrics['average_time'] - after_metrics['average_time']) / 
                                            optimization_task.before_metrics['average_time']) * 100
                            else:
                                improvement = 0
                            optimization_task.improvement_percentage = improvement
                            
                            if optimization_task.syscall in self.performance_records:
                                record = self.performance_records[optimization_task.syscall]
                                if not record.optimization_results:
                                    record.optimization_results = []
                                record.optimization_applied = True
                                record.optimization_results.append({
                                    "applied_at": optimization_task.applied_at,
                                    "strategy": optimization_task.strategy,
                                    "before_metrics": optimization_task.before_metrics,
                                    "after_metrics": after_metrics,
                                    "improvement_percentage": improvement
                                })
                                print(f"Optimized {optimization_task.syscall}: {improvement:.2f}% improvement")
                        else:
                            optimization_task.status = "failed"
                            print(f"Optimization failed for {optimization_task.syscall}")
                    
                    self.optimization_in_progress = False
                    with self.queue_condition:
                        self.queue_condition.notify_all()
                else:
                    # No task to process, sleep to avoid CPU spinning
                    time.sleep(1)
                    
            except Exception as e:
                print(f"Optimization worker error: {e}")
                self.optimization_in_progress = False
                time.sleep(2)  # Recovery delay

    def _apply_optimization(self, task: OptimizationStatus) -> Tuple[bool, Optional[Dict[str, float]]]:
        syscall_name = task.syscall
        print(f"Optimizing {syscall_name}: {task.strategy}")
        
        try:
            with self.lock:
                if syscall_name not in self.performance_records:
                    return False, None
                record = self.performance_records[syscall_name]
                before_metrics = {
                    'average_time': record.average_time,
                    'variance': record.variance,
                    'resource_impact': record.resource_impact
                }
            
            category = record.category
            success = self._apply_category_optimization(category)
            
            # Reduced waiting time, but still give system time to apply changes
            time.sleep(3)
            
            with self.lock:
                if syscall_name in self.performance_records:
                    record = self.performance_records[syscall_name]
                    after_metrics = {
                        'average_time': record.average_time,
                        'variance': record.variance,
                        'resource_impact': record.resource_impact
                    }
                    return success, after_metrics
            return success, None
        except Exception as e:
            print(f"Error during optimization of {syscall_name}: {e}")
            return False, None

    def _apply_category_optimization(self, category: str) -> bool:
        if os.geteuid() != 0:
            print(f"Root privileges required to optimize {category}")
            return False
        
        config = self.optimization_configs.get(category, {})
        success = True
        
        if "sysctl_params" in config:
            for param, value in config["sysctl_params"].items():
                try:
                    subprocess.run(["sysctl", "-w", f"{param}={value}"], check=True)
                    print(f"Set {param}={value}")
                except subprocess.CalledProcessError as e:
                    success = False
                    print(f"Failed to set {param}: {e}")
        
        if category == "File I/O" and "io_scheduler" in config:
            try:
                disks = [d for d in os.listdir("/sys/block") if d.startswith(("sd", "hd", "nvme"))]
                for disk in disks:
                    scheduler_path = f"/sys/block/{disk}/queue/scheduler"
                    if os.path.exists(scheduler_path):
                        with open(scheduler_path, "w") as f:
                            f.write(config["io_scheduler"])
                            print(f"Set {disk} scheduler to {config['io_scheduler']}")
            except Exception as e:
                success = False
                print(f"Failed to set I/O scheduler: {e}")
        
        return success

    def _apply_syscall_specific_optimization(self, syscall_name: str) -> bool:
        # Placeholder for syscall-specific eBPF optimizations
        if syscall_name in ["read", "stat", "getdents", "clock_gettime"]:
            print(f"Simulated eBPF optimization for {syscall_name}")
            return True
        return False

    def start_ebpf_monitoring(self):
        bpf_code = """
        #include <uapi/linux/ptrace.h>
        BPF_HASH(start_times, u32, u64);
        BPF_HASH(read_cache, u64, u64, 1024);
        BPF_PERF_OUTPUT(events);

        struct syscall_data_t {
            u32 pid;
            u64 ts;
            u32 syscall_nr;
        };

        int trace_sys_enter(struct bpf_raw_tracepoint_args *ctx) {
            u32 pid = bpf_get_current_pid_tgid() >> 32;
            u64 ts = bpf_ktime_get_ns();
            u32 syscall_nr = ctx->args[1];
            if (syscall_nr == 0) {  // Optimize read syscall
                u64 key = pid;
                u64 *cached = read_cache.lookup(&key);
                if (cached) {}
            }
            start_times.update(&pid, &ts);
            return 0;
        }

        int trace_sys_exit(struct bpf_raw_tracepoint_args *ctx) {
            u32 pid = bpf_get_current_pid_tgid() >> 32;
            u64 *start_ts = start_times.lookup(&pid);
            if (!start_ts) return 0;

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
            self.record_syscall_performance(syscall_info["name"], event.ts / 1e9, syscall_info["category"])

        self.bpf["events"].open_perf_buffer(process_event)
        threading.Thread(target=self.poll_ebpf_events, daemon=True).start()

    def poll_ebpf_events(self):
        while True:
            try:
                self.bpf.perf_buffer_poll(timeout=100)  # Add timeout in milliseconds
                time.sleep(0.1)  # Increase sleep time to reduce CPU usage
            except Exception as e:
                print(f"eBPF polling error: {e}")
                time.sleep(1)

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
                    last_optimized=0,
                    resource_impact=resource_impact,
                    category=category,
                    optimization_applied=False,
                    optimization_results=[]
                )
            else:
                record = self.performance_records[syscall_name]
                total_executions = record.execution_count + 1
                
                # Welford's online algorithm for mean and variance
                delta = execution_time - record.average_time
                new_average = record.average_time + delta / total_executions
                delta2 = execution_time - new_average
                new_variance = (record.variance * (total_executions - 1) + delta * delta2) / total_executions

                aggregated_impact = {
                    k: (record.resource_impact.get(k, 0) * record.execution_count + resource_impact.get(k, 0)) / total_executions
                    for k in set(record.resource_impact) | set(resource_impact)
                }

                self.performance_records[syscall_name] = SyscallPerformanceRecord(
                    name=syscall_name,
                    average_time=new_average,
                    execution_count=total_executions,
                    variance=new_variance,
                    peak_performance=max(record.peak_performance, execution_time),
                    last_optimized=record.last_optimized,
                    resource_impact=aggregated_impact,
                    category=category,
                    optimization_applied=record.optimization_applied,
                    optimization_results=record.optimization_results
                )

    def generate_optimization_strategy(self) -> List[Dict[str, Any]]:
        recommendations = []
        with self.lock:
            for syscall, record in self.performance_records.items():
                # Define thresholds for critical and warning levels
                is_critical = (record.average_time > self.performance_threshold or 
                              any(impact > 50 for impact in record.resource_impact.values()))
                is_warning = (record.average_time > 0.02 or 
                             any(impact > 30 for impact in record.resource_impact.values())) and not is_critical
                
                if is_critical or is_warning:
                    # Generate appropriate recommendation
                    suggestion = self._generate_mitigation_strategy(record)
                    
                    recommendation = {
                        "syscall": syscall,
                        "current_performance": record.average_time,
                        "recommendation_type": "CRITICAL" if is_critical else "WARNING",
                        "suggested_action": suggestion,
                        "resource_impact": record.resource_impact,
                        "category": record.category,
                        "optimization_applied": record.optimization_applied
                    }
                    recommendations.append(recommendation)
                    
                    # Update recommendations dictionary
                    self.recommendations_dict[syscall] = suggestion
                    
                    # Queue for optimization if not already applied or queued
                    if not record.optimization_applied and not any(t.syscall == syscall for t in self.optimization_queue):
                        task = OptimizationStatus(
                            syscall=syscall,
                            strategy=suggestion,
                            status="pending",
                            applied_at=time.time(),
                            before_metrics={
                                'average_time': record.average_time,
                                'variance': record.variance,
                                'resource_impact': record.resource_impact
                            }
                        )
                        self.optimization_queue.append(task)
                        with self.queue_condition:
                            self.queue_condition.notify_all()
                        print(f"Queued optimization for {syscall}: {suggestion}")
        
            # Record optimization history
            self.optimization_history.append({
                "timestamp": time.time(),
                "system_resources": self._capture_system_resources(),
                "recommendations": recommendations
            })
        return recommendations

    def _generate_mitigation_strategy(self, record: SyscallPerformanceRecord) -> str:
        """Generate an optimization strategy based on the syscall record"""
        # First try to use Groq API if available
        if self.groq_client:
            prompt = f"""
System Call: {record.name}
Category: {record.category}
Average Execution Time: {record.average_time:.4f} seconds
Variance: {record.variance:.4f}
Resource Impacts: CPU: {record.resource_impact.get('cpu_percent', 0):.2f}%, Memory: {record.resource_impact.get('memory_percent', 0):.2f}%, Disk I/O: {record.resource_impact.get('disk_io_percent', 0):.2f}%
Suggest a concise optimization strategy in one sentence.
"""
            try:
                from concurrent.futures import ThreadPoolExecutor, TimeoutError
                
                def call_api():
                    return self.groq_client.chat.completions.create(
                        model="llama3-8b-8192",
                        messages=[
                            {"role": "system", "content": "You are an AI assistant specialized in system performance optimization. Provide your suggestions in plain text without code or special formatting."},
                            {"role": "user", "content": prompt}
                        ],
                        max_tokens=75,
                        temperature=0.7
                    )
                
                with ThreadPoolExecutor() as executor:
                    future = executor.submit(call_api)
                    try:
                        response = future.result(timeout=5)  # 5 second timeout
                        suggestion = response.choices[0].message.content.strip()
                        if suggestion:
                            return suggestion
                    except TimeoutError:
                        print(f"Groq API timeout for {record.name}")
            except Exception as e:
                print(f"Error with Groq API: {e}")
        
        # Fallback to rule-based strategy
        # Get strategies for this category
        strategies = self.category_strategies.get(record.category, self.category_strategies["Unknown"])
        
        # Select strategy based on resource impact and execution time
        resource_weights = {
            'cpu_percent': record.resource_impact.get('cpu_percent', 0),
            'memory_percent': record.resource_impact.get('memory_percent', 0),
            'disk_io_percent': record.resource_impact.get('disk_io_percent', 0)
        }
        
        # Find which resource is most impacted
        max_resource_type = max(resource_weights, key=resource_weights.get)
        
        # Select strategy index based on impact (higher impact → more aggressive strategy)
        strategy_index = min(int(resource_weights[max_resource_type] / 20), len(strategies) - 1)
        
        # For high execution times, prioritize more aggressive strategies
        if record.average_time > self.performance_threshold * 2:
            strategy_index = min(strategy_index + 1, len(strategies) - 1)
            
        # Get the selected strategy and personalize it with the syscall name
        strategy = strategies[strategy_index]
        if "{record.name}" not in strategy:
            strategy = f"{strategy} for {record.name}"
        else:
            strategy = strategy.format(record=record)
            
        return strategy

    def get_performance_data(self) -> Dict[str, Any]:
        with self.lock:
            result = {}
            for k, v in self.performance_records.items():
                record_dict = asdict(v)
                record_dict['recommendation'] = self.recommendations_dict.get(k, "")
                result[k] = record_dict
            return result

    def get_refresh_interval(self) -> int:
        return self.refresh_interval

    def get_syscall_categories(self) -> Dict[str, List[str]]:
        with self.lock:
            categories = {}
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
                record_dict['recommendation'] = self.recommendations_dict.get(syscall_name, "")
                return record_dict
            return {"error": "System call not found"}

    def apply_optimization(self, syscall_name: str) -> Dict[str, Any]:
        with self.lock:
            if syscall_name not in self.performance_records:
                return {"error": "System call not found"}
            record = self.performance_records[syscall_name]
            task = OptimizationStatus(
                syscall=syscall_name,
                strategy=self.recommendations_dict.get(syscall_name, "Apply category-specific optimization"),
                status="pending",
                applied_at=time.time(),
                before_metrics={'average_time': record.average_time, 'variance': record.variance, 'resource_impact': record.resource_impact}
            )
            self.optimization_queue.append(task)
            with self.queue_condition:
                self.queue_condition.notify_all()
            print(f"Queued manual optimization for {syscall_name}")
            return {"success": True, "message": f"Optimization for {syscall_name} queued successfully"}

# Load API key and initialize optimizer
groq_api_key = os.environ.get("GROQ_API_KEY")
if not groq_api_key:
    print("Warning: GROQ_API_KEY not found in environment variables.")
syscall_optimizer = AISystemCallOptimizer(groq_api_key=groq_api_key, auto_optimize=True)

@app.route('/')
def index():
    return render_template('index.html', refresh_interval=syscall_optimizer.get_refresh_interval())

@app.route('/performance')
def get_performance():
    global last_performance_update, cached_performance_data
    current_time = time()
    
    # Only update cache every 2 seconds
    if cached_performance_data is None or current_time - last_performance_update > 2:
        cached_performance_data = syscall_optimizer.get_performance_data()
        last_performance_update = current_time
        
    return jsonify(cached_performance_data)

@app.route('/recommendations')
def get_recommendations():
    return jsonify(syscall_optimizer.generate_optimization_strategy())

@app.route('/categories')
def get_categories():
    return jsonify(syscall_optimizer.get_syscall_categories())

@app.route('/syscall/<syscall_name>')
def get_syscall_details(syscall_name):
    return jsonify(syscall_optimizer.get_syscall_details(syscall_name))

@app.route('/optimize/<syscall_name>', methods=['POST'])
def apply_optimization(syscall_name):
    return jsonify(syscall_optimizer.apply_optimization(syscall_name))

@app.route('/optimization-status')
def get_optimization_status():
    with syscall_optimizer.lock:
        return jsonify({
            "optimization_in_progress": syscall_optimizer.optimization_in_progress,
            "queue": [asdict(task) for task in syscall_optimizer.optimization_queue]
        })
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug_mode = os.environ.get("DEBUG", "False").lower() == "true"
    app.run(host='0.0.0.0', port=port, debug=debug_mode, threaded=True)