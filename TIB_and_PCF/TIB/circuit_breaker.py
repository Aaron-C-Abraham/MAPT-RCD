import time
import threading
import statistics
from TIB_and_PCF.TIB.TIB_structures import TIBConfig,TIBState,CircuitBreakerStatus,ExploitIntensity

class TIBViolation(Exception):
    """
    Raised when an action violates a TIB constraint
    """
    pass
class TIBExhausted(TIBViolation):
    """
    Raised when the device's weighted TIB budget is fully spent.
    """
    pass
class CircuitBreaker:
    """
    Per-device circuit breaker that enforces TIB limits at runtime
    """
    MIN_RATE_FRACTION=0.1
    def __init__(self,device_ip:str,config:TIBConfig,state:TIBState):
        self.device_ip=device_ip
        self.config=config
        self.state=state
        self.lock=threading.Lock()
        self.packet_timestamps:list[float]=[]
        if state.current_rate_limit==0:
            state.current_rate_limit=float(config.max_packets_per_second)
    def request_packet_permission(self,count:int=1,probe_type:str="tcp_syn")->None:
        """
        Checks breaker status, budget sufficiency, inter-packet delay, 
        and dynamic rate limit to see if action is possible or not
        """
        with self.lock:
            if self.state.circuit_breaker_status==CircuitBreakerStatus.EXHAUSTED:
                raise TIBExhausted(
                    f"[{self.device_ip}] Budget exhausted "
                    f"({self.state.budget_spent:.1f} / "
                    f"{self.config.max_budget_points} points spent)"
                )
            if self.state.circuit_breaker_status==CircuitBreakerStatus.TRIPPED:
                raise TIBViolation(f"[{self.device_ip}] Circuit breaker tripped: {self.state.trip_reason}")
            
            if self.state.circuit_breaker_status==CircuitBreakerStatus.PAUSED:
                wait_sec=(self.state.pause_for_ms)/1000
                self.lock.release()  
                time.sleep(wait_sec)   
                self.lock.acquire()   
                self.state.circuit_breaker_status=CircuitBreakerStatus.ACTIVE

            probe_cost=self.config.get_probe_cost(probe_type)*count
            if (self.config.max_budget_points>0.0 and self.state.budget_spent+probe_cost>self.config.max_budget_points):
                # self.state.circuit_breaker_status=CircuitBreakerStatus.EXHAUSTED
                raise TIBViolation(
                    f"[{self.device_ip}] Probe '{probe_type}' costs {probe_cost:.1f} points "
                    f"but only {self.config.max_budget_points-self.state.budget_spent:.1f} "
                    f"remain of {self.config.max_budget_points:.0f} budget"
                )
            # Enforcing the minimum delay between consecutive packets
            if self.config.min_inter_packet_delay_ms>0:
                now_ms=time.time()*1000
                elapsed_ms=now_ms-self.state.last_packet_time_ms
                if elapsed_ms<self.config.min_inter_packet_delay_ms:
                    wait_sec=(self.config.min_inter_packet_delay_ms-elapsed_ms)/1000
                    self.lock.release()   
                    time.sleep(wait_sec)  
                    self.lock.acquire() 
            # Dynamic rate limit check
            now=time.time()
            self.packet_timestamps=[t for t in self.packet_timestamps if now-t<1]
            live_rate=self.state.current_rate_limit
            while len(self.packet_timestamps)+count>live_rate:
                oldest=self.packet_timestamps[0]
                wait_sec=1-(now-oldest)+0.001  
                self.lock.release()
                time.sleep(max(wait_sec,0.001))  
                self.lock.acquire()
                now=time.time()
                self.packet_timestamps=[t for t in self.packet_timestamps if now-t<1]
                live_rate=self.state.current_rate_limit 
            # To record packets and deduct budget
            for _ in range(count):
                self.packet_timestamps.append(now)
            self.state.budget_spent+=probe_cost
            self.state.budget_spent_by_type[probe_type]=self.state.budget_spent_by_type.get(probe_type, 0.0) + probe_cost
            self.state.packets_sent_total+=count
            self.state.last_packet_time_ms=time.time()*1000
    def record_rtt(self,rtt_ms:float)->None:
        """
        Record a new RTT measurement and update the live rate limit.
        """
        with self.lock:
            self.state.current_rtt_ms=rtt_ms
            self.state.rtt_samples.append(rtt_ms)
            if len(self.state.rtt_samples)>20:
                self.state.rtt_samples=self.state.rtt_samples[-20:]
            # Establishing baseline using first 5 samples
            if self.state.baseline_rtt_ms is None and len(self.state.rtt_samples)>=5:
                self.state.baseline_rtt_ms=statistics.mean(self.state.rtt_samples[:5])
                self.state.current_rate_limit=float(self.config.max_packets_per_second)
                return
            if self.state.baseline_rtt_ms is None or self.state.baseline_rtt_ms<=0:
                return  # Not enough samples yet to compute ratio
            ratio=rtt_ms/self.state.baseline_rtt_ms
            max_rate=float(self.config.max_packets_per_second)
            min_rate=max_rate*self.MIN_RATE_FRACTION
            pause_mult=self.config.rtt_pause_multiplier          
            trip_mult=self.config.rtt_trip_multiplier
            # Trip the circuit breaker to halt any actions on that device and now requires manual reset
            if ratio>=trip_mult:
                self.state.stress_events+=1
                self.state.circuit_breaker_status=CircuitBreakerStatus.TRIPPED
                self.state.trip_reason=(
                    f"RTT {rtt_ms:.1f}ms is {ratio:.2f}x baseline "
                    f"{self.state.baseline_rtt_ms:.1f}ms "
                    f"(trip threshold: {trip_mult}x)"
                )
                return
            #Continuous Scaling
            if ratio>=pause_mult:
                self.state.circuit_breaker_status=CircuitBreakerStatus.PAUSED 
                stress_progress=(ratio-pause_mult)/(trip_mult-pause_mult)
                stress_progress=max(0,min(1,stress_progress))
                new_rate=max_rate-stress_progress*(max_rate-min_rate)
                new_rate=max(min_rate,new_rate)
                if new_rate<self.state.current_rate_limit:
                    self.state.stress_events+=1
                self.state.current_rate_limit=new_rate
            else:
                # Device is responding within accepted latency
                recovery_progress=(ratio-1)/max(pause_mult-1,0.001)
                recovery_progress=max(0,min(1,recovery_progress))
                new_rate=max_rate-recovery_progress*(max_rate-min_rate)*0.2
                new_rate=max(min_rate,min(max_rate,new_rate))
                self.state.consecutive_timeouts=0

    def record_timeout(self)->None:
        """
        Record a probe timeout. When consecutive timeouts reach the config
        limit, trip the circuit breaker to halt all further probing.
        """
        with self.lock:
            self.state.consecutive_timeouts+=1
            if self.state.consecutive_timeouts>=self.config.consecutive_timeout_limit:
                self.state.circuit_breaker_status=CircuitBreakerStatus.TRIPPED
                self.state.trip_reason=(
                    f"{self.state.consecutive_timeouts} consecutive timeouts — "
                    f"device may be unresponsive or crashed"
                )

    def record_response(self)->None:
        """
        Device responded to a probe — reset consecutive timeout counter.
        """
        with self.lock:
            self.state.consecutive_timeouts=0
    
    def request_connection_permission(self)->None:
        """
        Block until a TCP connection slot is available (respects max_concurrent_connections).
        Raises TIBExhausted or TIBViolation if the breaker is in a non-recoverable state.
        """
        with self.lock:
            self.check_not_stopped()
            while self.state.active_connections>=self.config.max_concurrent_connections:
                self.lock.release()
                time.sleep(0.1)
                self.lock.acquire()
                self.check_not_stopped()
            self.state.active_connections+=1
            self.state.total_connections_opened+=1

    def release_connection(self)->None:
        """
        Signal that a TCP connection has been closed.
        """
        with self.lock:
            self.state.active_connections=max(0,self.state.active_connections-1)
    
    def request_service_probe_permission(self)->None:
        """
        Check if an application-layer service probe is allowed within the
        per-device service probe limit. Raises TIBViolation if limit reached.
        """
        with self.lock:
            self.check_not_stopped()
            if self.state.service_probes_sent>=self.config.max_service_probes:
                raise TIBViolation(
                    f"[{self.device_ip}] Service probe limit reached "
                    f"({self.config.max_service_probes} allowed)"
                )
            self.state.service_probes_sent+=1
    def request_exploit_permission(self,exploit_name:str,intensity:ExploitIntensity)->None:
        """
        Check if an exploit attempt is permitted given the device's tier policy,
        intensity level, and remaining exploit budget. Raises TIBViolation if blocked.
        """
        with self.lock:
            self.check_not_stopped()
            if self.config.exploit_intensity==ExploitIntensity.NONE:
                raise TIBViolation(
                    f"[{self.device_ip}] Exploitation not permitted for this device tier."
                )
            if intensity.value>self.config.exploit_intensity.value:
                raise TIBViolation(
                    f"[{self.device_ip}] Exploit {exploit_name} intensity {intensity.name} exceeds "
                    f"device limit of {self.config.exploit_intensity.name}"
                )
            if (self.config.weighted_exploit_attempts_budget > 0 and self.state.exploit_attempts >= self.config.weighted_exploit_attempts_budget):
                raise TIBViolation(
                    f"[{self.device_ip}] Exploit attempt limit reached"
                )
            self.state.exploit_attempts+=1
    def get_status(self)->CircuitBreakerStatus:
        """
        Return the current circuit breaker status
        """
        with self.lock:
            return self.state.circuit_breaker_status
    def is_operational(self)->bool:
        """
        Check if the breaker allows probing (ACTIVE or PAUSED states).
        Returns False if TRIPPED or EXHAUSTED.
        """
        status=self.get_status()
        return status in (CircuitBreakerStatus.ACTIVE,CircuitBreakerStatus.PAUSED)
    def reset_trip(self,user_note:str="")->None:
        """
        Manual reset of circuit breaker after it trips
        """
        with self.lock:
            if self.state.circuit_breaker_status==CircuitBreakerStatus.TRIPPED:
                self.state.circuit_breaker_status=CircuitBreakerStatus.ACTIVE
                self.state.consecutive_timeouts=0
                self.state.trip_reason=user_note
                self.state.current_rate_limit=float(self.config.max_packets_per_second)
    def get_rtt_stats(self)->dict:
        """
        Return RTT statistics for reporting and dashboard display.
        """
        with self.lock:
            samples=self.state.rtt_samples
            if not samples:
                return {"samples":0}
            return {
                "samples":len(samples),
                "baseline_ms":self.state.baseline_rtt_ms,
                "current_ms":self.state.current_rtt_ms,     
                "mean_ms":statistics.mean(samples),         
                "stddev_ms":statistics.stdev(samples) if len(samples)>1 else 0.0,
                "cv":(statistics.stdev(samples)/statistics.mean(samples) if len(samples)>1 and statistics.mean(samples)>0 else 0.0),
                "stress_events":self.state.stress_events,
                "current_rate_limit":self.state.current_rate_limit,    
                "config_rate_max":self.config.max_packets_per_second,  
                "rate_utilisation_pct":round(self.state.current_rate_limit/max(self.config.max_packets_per_second, 1)*100,1),
            }
    def get_budget_stats(self)->dict:
        """
        Return weighted budget consumption breakdown for reporting.
        """
        with self.lock:
            return {
                "budget_spent":round(self.state.budget_spent,2),
                "budget_total":self.config.max_budget_points,
                "budget_remaining":round(self.config.max_budget_points-self.state.budget_spent,2) if self.config.max_budget_points>0 else "unlimited",
                "budget_pct_used":round(self.state.budget_spent/self.config.max_budget_points*100,1) if self.config.max_budget_points>0 else 0.0,
                "breakdown_by_type":dict(self.state.budget_spent_by_type),
            }

    # Helper functions
    def check_not_stopped(self)->None:
        """
        Guard method — raises if the breaker is in a non-recoverable state.
        """
        if self.state.circuit_breaker_status==CircuitBreakerStatus.EXHAUSTED:
            raise TIBExhausted(f"[{self.device_ip}] Budget exhausted")
        if self.state.circuit_breaker_status==CircuitBreakerStatus.TRIPPED:
            raise TIBViolation(
                f"[{self.device_ip}] Circuit breaker tripped: {self.state.trip_reason}"
            )
