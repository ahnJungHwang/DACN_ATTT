"""Process-specific resource samples; unavailable measurements remain null."""
import os
import shutil
import subprocess
import threading
import psutil


def sample_processes():
    result={'service_rss_bytes':None,'ollama_rss_bytes':None,'ollama_vram_bytes':None,'reasons':{}}
    try: result['service_rss_bytes']=psutil.Process(os.getpid()).memory_info().rss
    except psutil.Error as exc: result['reasons']['service_rss_bytes']=type(exc).__name__
    processes={}
    try:
        for proc in psutil.process_iter(['pid','name']):
            if (proc.info['name'] or '').lower() in ('ollama','ollama.exe'):
                processes[proc.pid]=proc
                for child in proc.children(recursive=True): processes[child.pid]=child
        if processes: result['ollama_rss_bytes']=sum(p.memory_info().rss for p in processes.values())
        else: result['reasons']['ollama_rss_bytes']='No identifiable Ollama process'
    except psutil.Error as exc: result['reasons']['ollama_rss_bytes']=type(exc).__name__
    executable=shutil.which('nvidia-smi')
    if not executable: result['reasons']['ollama_vram_bytes']='nvidia-smi unavailable'
    elif not processes: result['reasons']['ollama_vram_bytes']='No identifiable Ollama PID'
    else:
        try:
            response=subprocess.run([executable,'--query-compute-apps=pid,used_gpu_memory','--format=csv,noheader,nounits'],
                capture_output=True,text=True,timeout=.18,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
            if response.returncode: raise ValueError('nvidia-smi failed')
            values=[]
            for line in response.stdout.splitlines():
                pid,value=[part.strip() for part in line.split(',',1)]
                if int(pid) in processes: values.append(int(value)*1024*1024)
            if values: result['ollama_vram_bytes']=sum(values)
            else: result['reasons']['ollama_vram_bytes']='No per-PID GPU measurement (including WDDM/unsupported GPU)'
        except (ValueError,subprocess.SubprocessError,OSError) as exc:
            result['reasons']['ollama_vram_bytes']=type(exc).__name__+': per-PID VRAM unavailable'
    return result


class ResourceMonitor:
    def __init__(self,sampler=sample_processes):
        self.sampler=sampler; self.stop=threading.Event(); self.thread=None; self.samples=[]
    def __enter__(self):
        def loop():
            import time
            while not self.stop.is_set():
                started=time.monotonic(); self.samples.append(self.sampler())
                self.stop.wait(max(0,.2-(time.monotonic()-started)))
        self.thread=threading.Thread(target=loop,daemon=True); self.thread.start(); return self
    def __exit__(self,*args):
        self.stop.set(); self.thread.join(timeout=2)
    def report(self):
        report={'sample_interval_ms':200,'sample_count':len(self.samples),'metrics':{}}
        for key in ('service_rss_bytes','ollama_rss_bytes','ollama_vram_bytes'):
            values=[s[key] for s in self.samples if s.get(key) is not None]
            reasons=sorted({s.get('reasons',{}).get(key) for s in self.samples if s.get('reasons',{}).get(key)})
            report['metrics'][key]={'peak':max(values) if values else None,'valid_samples':len(values),
                'reasons':reasons or ([] if values else ['No sample captured'])}
        return report
