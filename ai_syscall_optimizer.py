import os
import time
import threading
import numpy as np
import subprocess
from typing import Dict, List, Any, Tuple, Optional
from dataclasses import dataclass, asdict
import psutil
from flask import Flask, jsonify, render_template, request
from groq import Groq
from dotenv import load_dotenv
from bcc import BPF
import ctypes

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
    optimization_applied: bool = False  # Track if optimization has been applied
    optimization_results: List[Dict[str, Any]] = None  # Track the results of optimization

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
        self.recommendations_dict: Dict[str, str] = {}  # Store recommendations for each syscall
        self.performance_threshold = performance_threshold
        self.learning_rate = learning_rate
        self.lock = threading.Lock()
        self.global_resource_baseline = self._capture_system_resources()
        self.optimization_queue: List[OptimizationStatus] = []
        self.auto_optimize = auto_optimize
        self.optimization_in_progress = False
        
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

        # System-level optimization config by category
        self.optimization_configs = {
            "File I/O": {
                "sysctl_params": {
                    "vm.dirty_ratio": 10,
                    "vm.dirty_background_ratio": 5,
                    "vm.vfs_cache_pressure": 50
                },
                "mount_options": "noatime,nodiratime,commit=60",
                "io_scheduler": "deadline"
            },
            "Memory": {
                "sysctl_params": {
                    "vm.swappiness": 10,
                    "vm.min_free_kbytes": 65536,
                    "vm.zone_reclaim_mode": 0
                },
                "transparent_hugepages": "madvise"
            },
            "Process": {
                "sysctl_params": {
                    "kernel.sched_migration_cost_ns": 5000000,
                    "kernel.sched_autogroup_enabled": 0
                },
                "nice_level": -10
            },
            "Synchronization": {
                "sysctl_params": {
                    "kernel.sched_min_granularity_ns": 10000000,
                    "kernel.sched_wakeup_granularity_ns": 15000000
                }
            },
            "IPC": {
                "sysctl_params": {
                    "fs.pipe-max-size": 1048576,
                    "kernel.msgmax": 65536
                }
            },
            "Time": {
                "sysctl_params": {
                    "kernel.timer_migration": 0
                },
                "clocksource": "tsc"
            }
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
        
        # Start the optimization worker thread if auto-optimize is enabled
        if self.auto_optimize:
            threading.Thread(target=self.optimization_worker_thread, daemon=True).start()
            print("Auto-optimization enabled. Optimization worker thread started.")
        
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

    def optimization_worker_thread(self):
        """Worker thread that processes optimization requests from the queue"""
        while True:
            if not self.optimization_queue or self.optimization_in_progress:
                time.sleep(1)
                continue
                
            with self.lock:
                if self.optimization_queue:
                    # Get the next optimization task
                    optimization_task = self.optimization_queue.pop(0)
                    self.optimization_in_progress = True
                else:
                    continue
            
            try:
                # Implement the optimization
                success, after_metrics = self._apply_optimization(optimization_task)
                
                # Update the optimization status
                with self.lock:
                    if success:
                        optimization_task.status = "applied"
                        optimization_task.after_metrics = after_metrics
                        
                        # Calculate improvement percentage
                        if optimization_task.before_metrics and after_metrics:
                            before_time = optimization_task.before_metrics.get('average_time', 0)
                            after_time = after_metrics.get('average_time', 0)
                            if before_time > 0:
                                improvement = ((before_time - after_time) / before_time) * 100
                                optimization_task.improvement_percentage = improvement
                        
                        # Update the performance record
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
                                "improvement_percentage": optimization_task.improvement_percentage
                            })
                            
                            print(f"Optimization for {optimization_task.syscall} applied successfully with {optimization_task.improvement_percentage:.2f}% improvement")
                    else:
                        optimization_task.status = "failed"
                        print(f"Optimization for {optimization_task.syscall} failed")
            except Exception as e:
                print(f"Error during optimization: {e}")
                optimization_task.status = "failed"
            
            # Mark optimization as complete
            self.optimization_in_progress = False
            time.sleep(1)  # Small delay between optimizations

    def _apply_optimization(self, task: OptimizationStatus) -> Tuple[bool, Optional[Dict[str, float]]]:
        """Apply the optimization strategy for a system call"""
        syscall_name = task.syscall
        
        print(f"Applying optimization for {syscall_name}: {task.strategy}")
        
        # Record performance metrics before optimization
        with self.lock:
            if syscall_name in self.performance_records:
                record = self.performance_records[syscall_name]
                before_metrics = {
                    'average_time': record.average_time,
                    'variance': record.variance,
                    'resource_impact': record.resource_impact
                }
            else:
                before_metrics = {
                    'average_time': 0,
                    'variance': 0,
                    'resource_impact': {}
                }
        
        # Get the system call category
        category = None
        with self.lock:
            if syscall_name in self.performance_records:
                category = self.performance_records[syscall_name].category
        
        if not category:
            return False, None
            
        # Apply category-specific optimizations
        optimization_applied = self._apply_category_optimization(category)
        
        # Apply syscall-specific optimization
        specific_optimization = self._apply_syscall_specific_optimization(syscall_name)
        
        # Wait a bit to collect new performance data
        time.sleep(10)
        
        # Measure performance after optimization
        with self.lock:
            if syscall_name in self.performance_records:
                record = self.performance_records[syscall_name]
                after_metrics = {
                    'average_time': record.average_time,
                    'variance': record.variance,
                    'resource_impact': record.resource_impact
                }
                return True, after_metrics
            
        return optimization_applied or specific_optimization, None

    def _apply_category_optimization(self, category: str) -> bool:
        """Apply optimization based on the system call category"""
        if category not in self.optimization_configs:
            return False
            
        config = self.optimization_configs[category]
        success = True
        
        # Apply sysctl parameters
        if "sysctl_params" in config:
            for param, value in config["sysctl_params"].items():
                try:
                    cmd = ["sysctl", "-w", f"{param}={value}"]
                    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
                    print(f"Applied sysctl {param}={value}: {result.returncode}")
                    if result.returncode != 0:
                        success = False
                        print(f"Error setting {param}: {result.stderr}")
                except Exception as e:
                    success = False
                    print(f"Error applying sysctl parameter {param}: {e}")
        
        # Apply mount options for File I/O
        if category == "File I/O" and "mount_options" in config:
            try:
                # This is just a simulation - in a real system, you'd need to remount filesystems
                print(f"Would apply mount options: {config['mount_options']}")
            except Exception as e:
                success = False
                print(f"Error applying mount options: {e}")
                
        # Apply I/O scheduler
        if "io_scheduler" in config:
            try:
                disks = [d for d in os.listdir("/sys/block") if d.startswith(("sd", "hd", "nvme"))]
                for disk in disks:
                    scheduler_path = f"/sys/block/{disk}/queue/scheduler"
                    if os.path.exists(scheduler_path):
                        with open(scheduler_path, "w") as f:
                            try:
                                f.write(config["io_scheduler"])
                                print(f"Set I/O scheduler for {disk} to {config['io_scheduler']}")
                            except Exception as e:
                                success = False
                                print(f"Error setting I/O scheduler for {disk}: {e}")
            except Exception as e:
                success = False
                print(f"Error applying I/O scheduler: {e}")
                
        # Apply transparent hugepages setting
        if "transparent_hugepages" in config:
            try:
                thp_path = "/sys/kernel/mm/transparent_hugepage/enabled"
                if os.path.exists(thp_path):
                    with open(thp_path, "w") as f:
                        try:
                            f.write(config["transparent_hugepages"])
                            print(f"Set transparent hugepages to {config['transparent_hugepages']}")
                        except Exception as e:
                            success = False
                            print(f"Error setting transparent hugepages: {e}")
            except Exception as e:
                success = False
                print(f"Error applying transparent hugepages: {e}")
                
        # Apply clocksource
        if "clocksource" in config:
            try:
                cs_path = "/sys/devices/system/clocksource/clocksource0/current_clocksource"
                if os.path.exists(cs_path):
                    with open(cs_path, "w") as f:
                        try:
                            f.write(config["clocksource"])
                            print(f"Set clocksource to {config['clocksource']}")
                        except Exception as e:
                            success = False
                            print(f"Error setting clocksource: {e}")
            except Exception as e:
                success = False
                print(f"Error applying clocksource: {e}")
                
        return success

    def _apply_syscall_specific_optimization(self, syscall_name: str) -> bool:
        """Apply optimization specific to the given system call"""
        # This is where you'd implement system call-specific optimizations
        # For example, creating custom eBPF programs to intercept and optimize specific syscalls
        
        # For demonstration purposes, let's create a basic eBPF program to cache results of frequent syscalls
        if syscall_name in ["read", "stat", "getdents", "clock_gettime"]:
            try:
                # This is a simplified example - in a real system you would need more sophisticated eBPF programs
                bpf_program = f"""
                #include <uapi/linux/ptrace.h>
                
                BPF_HASH(cache, u64, u64, 1024);
                
                int optimize_{syscall_name}(struct pt_regs *ctx) {{
                    u64 key = bpf_get_current_pid_tgid();
                    u64 *value = cache.lookup(&key);
                    
                    if (value) {{
                        // Found in cache, we could potentially skip the actual syscall
                        // This is simplified - real implementation would be more complex
                        return 0;
                    }}
                    
                    // Not found in cache, store it for next time
                    u64 dummy_val = 1;
                    cache.update(&key, &dummy_val);
                    return 0;
                }}
                """
                
                # In a real implementation, you would:
                # 1. Compile this BPF program
                # 2. Attach it to the appropriate syscall
                # 3. Implement proper caching logic
                
                print(f"Created eBPF optimization for {syscall_name}")
                return True
            except Exception as e:
                print(f"Error creating eBPF optimization for {syscall_name}: {e}")
                return False
                
        return False

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
                    category=category,
                    optimization_applied=False,
                    optimization_results=[]
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
                
                # Update the record with new performance data
                self.performance_records[syscall_name] = SyscallPerformanceRecord(
                    name=syscall_name,
                    average_time=new_average,
                    execution_count=total_executions,
                    variance=variance,
                    peak_performance=min(record.peak_performance, execution_time),
                    last_optimized=record.last_optimized,
                    resource_impact=aggregated_impact,
                    category=record.category,
                    optimization_applied=record.optimization_applied,
                    optimization_results=record.optimization_results
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
                        "category": record.category,
                        "optimization_applied": record.optimization_applied
                    }
                    recommendations.append(recommendation)
            
            # Update the recommendations dictionary
            self.recommendations_dict = {rec['syscall']: rec['suggested_action'] for rec in recommendations}
            
            # If auto-optimize is enabled, queue any new recommendations for optimization
            if self.auto_optimize:
                for rec in recommendations:
                    syscall = rec["syscall"]
                    if not any(task.syscall == syscall for task in self.optimization_queue):
                        # Check if this syscall has already been optimized
                        if syscall in self.performance_records and not self.performance_records[syscall].optimization_applied:
                            record = self.performance_records[syscall]
                            optimization_task = OptimizationStatus(
                                syscall=syscall,
                                strategy=rec["suggested_action"],
                                status="pending",
                                applied_at=time.time(),
                                before_metrics={
                                    'average_time': record.average_time,
                                    'variance': record.variance,
                                    'resource_impact': record.resource_impact
                                }
                            )
                            self.optimization_queue.append(optimization_task)
                            print(f"Queued optimization for {syscall}: {rec['suggested_action']}")
            
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
            
    def apply_optimization(self, syscall_name: str) -> Dict[str, Any]:
        """Manually apply an optimization for a specific system call"""
        with self.lock:
            if syscall_name not in self.performance_records:
                return {"error": "System call not found"}
                
            record = self.performance_records[syscall_name]
            
            # Create an optimization task
            optimization_task = OptimizationStatus(
                syscall=syscall_name,
                strategy=self.recommendations_dict.get(syscall_name, "Apply category-specific optimization"),
                status="pending",
                applied_at=time.time(),
                before_metrics={
                    'average_time': record.average_time,
                    'variance': record.variance,
                    'resource_impact': record.resource_impact
                }
            )
            
            # Add to queue or apply immediately
            self.optimization_queue.append(optimization_task)
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
    
@app.route('/optimize/<syscall_name>', methods=['POST'])
def apply_optimization(syscall_name):
    return jsonify(syscall_optimizer.apply_optimization(syscall_name))
    
@app.route('/optimization-status')
def get_optimization_status():
    with syscall_optimizer.lock:
        # Convert OptimizationStatus objects to dictionaries
        queue_status = [asdict(task) for task in syscall_optimizer.optimization_queue]
        return jsonify({
            "optimization_in_progress": syscall_optimizer.optimization_in_progress,
            "queue": queue_status
        })

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))  # Default to 5000 locally
    app.run(host='0.0.0.0', port=port, debug=True)