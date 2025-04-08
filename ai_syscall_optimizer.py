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
        self.queue_condition = threading.Condition(self.lock)  # Added for efficient queue waiting
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

        self.groq_client = Groq(api_key=groq_api_key) if groq_api_key else None
        if groq_api_key:
            print(f"Groq client initialized with API key: {groq_api_key[:5]}...")
        else:
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
            self.global_resource_baseline = self._capture_system_resources()
            time.sleep(5)  # Reduced frequency

    def optimization_worker_thread(self):
        while True:
            with self.queue_condition:
                if not self.optimization_queue or self.optimization_in_progress:
                    self.queue_condition.wait()
                    continue
                task = max(self.optimization_queue, key=lambda t: t.before_metrics['average_time'])
                self.optimization_queue.remove(task)
                self.optimization_in_progress = True
            
            try:
                success, after_metrics = self._apply_optimization(task)
                with self.lock:
                    if success and after_metrics:
                        task.status = "applied"
                        task.after_metrics = after_metrics
                        improvement = ((task.before_metrics['average_time'] - after_metrics['average_time']) / 
                                      task.before_metrics['average_time']) * 100 if task.before_metrics['average_time'] > 0 else 0
                        task.improvement_percentage = improvement
                        if task.syscall in self.performance_records:
                            record = self.performance_records[task.syscall]
                            if not record.optimization_results:
                                record.optimization_results = []
                            record.optimization_applied = True
                            record.optimization_results.append({
                                "applied_at": task.applied_at,
                                "strategy": task.strategy,
                                "before_metrics": task.before_metrics,
                                "after_metrics": after_metrics,
                                "improvement_percentage": improvement
                            })
                            print(f"Optimized {task.syscall}: {improvement:.2f}% improvement")
                    else:
                        task.status = "failed"
                        print(f"Optimization failed for {task.syscall}")
            except Exception as e:
                print(f"Optimization error for {task.syscall}: {e}")
                task.status = "failed"
            
            self.optimization_in_progress = False
            with self.queue_condition:
                self.queue_condition.notify_all()

    def _apply_optimization(self, task: OptimizationStatus) -> Tuple[bool, Optional[Dict[str, float]]]:
        syscall_name = task.syscall
        print(f"Optimizing {syscall_name}: {task.strategy}")
        
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
        
        time.sleep(2)  # Reduced delay for quicker feedback
        
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
            self.bpf.perf_buffer_poll()
            time.sleep(0.01)

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
                is_critical = (record.average_time > self.performance_threshold or 
                              any(impact > 50 for impact in record.resource_impact.values()))
                is_warning = (record.average_time > 0.02 or 
                             any(impact > 30 for impact in record.resource_impact.values())) and not is_critical
                
                if is_critical or is_warning:
                    recommendation = {
                        "syscall": syscall,
                        "current_performance": record.average_time,
                        "recommendation_type": "CRITICAL" if is_critical else "WARNING",
                        "suggested_action": self._generate_mitigation_strategy(record),
                        "resource_impact": record.resource_impact,
                        "category": record.category,
                        "optimization_applied": record.optimization_applied
                    }
                    recommendations.append(recommendation)
                    self.recommendations_dict[syscall] = recommendation["suggested_action"]
                    
                    if not record.optimization_applied and not any(t.syscall == syscall for t in self.optimization_queue):
                        task = OptimizationStatus(
                            syscall=syscall,
                            strategy=recommendation["suggested_action"],
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
                        print(f"Queued optimization for {syscall}: {recommendation['suggested_action']}")
        
            self.optimization_history.append({
                "timestamp": time.time(),
                "system_resources": self._capture_system_resources(),
                "recommendations": recommendations
            })
        return recommendations

    def _generate_mitigation_strategy(self, record: SyscallPerformanceRecord) -> str:
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
                response = self.groq_client.chat.completions.create(
                    model="llama3-8b-8192",
                    messages=[{"role": "user", "content": prompt}],
                    max_tokens=50,
                    temperature=0.7
                )
                suggestion = response.choices[0].message.content.strip()
                if suggestion:
                    return suggestion
            except Exception as e:
                print(f"Error with Groq API: {e}")
        
        category_strategies = {
            "File I/O": f"Use asynchronous I/O for {record.name} to reduce blocking.",
            "Memory": f"Optimize memory allocation for {record.name} with huge pages.",
            "Process": f"Minimize {record.name} calls via thread pooling.",
            "Synchronization": f"Reduce lock contention around {record.name}.",
            "IPC": f"Use shared memory for {record.name} to lower overhead.",
            "Time": f"Cache results of {record.name} to reduce frequency."
        }
        return category_strategies.get(record.category, f"Implement caching for {record.name}.")

    def get_performance_data(self) -> Dict[str, Any]:
        with self.lock:
            return {k: asdict(v) | {"recommendation": self.recommendations_dict.get(k, "")} for k, v in self.performance_records.items()}

    def get_refresh_interval(self) -> int:
        return self.refresh_interval

    def get_syscall_categories(self) -> Dict[str, List[str]]:
        with self.lock:
            categories = {}
            for syscall, record in self.performance_records.items():
                categories.setdefault(record.category, []).append(syscall)
            return categories

    def get_syscall_details(self, syscall_name: str) -> Dict[str, Any]:
        with self.lock:
            if syscall_name in self.performance_records:
                return asdict(self.performance_records[syscall_name]) | {"recommendation": self.recommendations_dict.get(syscall_name, "")}
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
        return jsonify({
            "optimization_in_progress": syscall_optimizer.optimization_in_progress,
            "queue": [asdict(task) for task in syscall_optimizer.optimization_queue]
        })

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=True)