import csv
import os
import statistics
from dataclasses import dataclass,field
from typing import Optional,Callable
from TIB_and_PCF.TIB.TIB_structures import DeviceTier
from utils.constants import DEFAULT_OUI_DB_PATH

SIGNAL_WEIGHTS={
    "oui_vendor_name":1,
    "ttl_bucket":2, 
    "tcp_window_size":3, 
    "tcp_options":2,
    "snmp_sysdescr":5,
    "banner_keywords":4,
    "industrial_port":5,
    "icmp_RTT_cv":2,
    "mdns_service":3,
    "dhcp_fingerprint":3,
}

CRITICAL_VENDOR_KEYWORDS = [
    "siemens","schneider electric","rockwell", "allen-bradley",
    "beckhoff", "wago", "phoenix contact", "omron", "mitsubishi electric",
    "fanuc", "keyence", "yokogawa", "honeywell", "emerson", "abb",
    "moxa", "advantech", "kontron",
]

FRAGILE_VENDOR_KEYWORDS = [
    "espressif", "arduino", "tuya", "shelly",
    "particle", "nordic semi", "microchip", "silicon labs",
    "realtek semiconductor", "actions semiconductor",
]

MODERATE_VENDOR_KEYWORDS = [
    # Networking / consumer electronics
    "tp-link", "netgear", "d-link", "asus", "belkin", "linksys",
    "ubiquiti", "mikrotik", "synology", "qnap", "western digital","raspberry pi",
    # Printers
    "canon", "epson", "brother", "lexmark", "xerox", "ricoh",
    # Smart home / cameras
    "hikvision", "dahua", "axis", "nest", "ring", "sonos",
    # Phones / tablets
    "samsung", "lg electronics", "oneplus", "xiaomi", "oppo", "vivo",
    "huawei", "motorola", "google", "realme", "nothing",
    "honor", "zte", "tcl",
    # Smart TVs / streaming
    "roku", "amazon technologies", "fire tv",
    "sony", "vizio", "hisense", "tcl",
    "chromecast", "nvidia",
]

ROBUST_VENDOR_KEYWORDS = [
    # Laptops / desktops / workstations
    "intel corporate", "dell", "hewlett packard", "hp inc", "lenovo",
    "apple", "microsoft", "vmware", "supermicro", "ibm",
    "acer", "toshiba", "msi",
    # Network infrastructure
    "juniper", "cisco systems", "arista networks", "palo alto",
]

FRAGILE_BANNER_KEYWORDS = [
    "lwip", "uip", "freertos", "vxworks", "uclinux", "threadx",
    "nucleus rtos", "rtems", "esp-idf", "micropython", "circuitpython",
    "goahead", "rompager", "dropbear", "busybox",
    "openwrt", "dd-wrt", "tomato",
]

ROBUST_BANNER_KEYWORDS = [
    "ubuntu", "debian", "centos", "red hat", "rhel", "fedora",
    "windows server", "openssh", "apache", "nginx", "iis",
    "microsoft-iis", "jetty", "tomcat",
]

FRAGILE_MDNS_SERVICES = [
    "_hap._tcp", "_matter._tcp", "_miio._udp", "_tuya._tcp",
    "_esphomelib._tcp",
]

MODERATE_MDNS_SERVICES = [
    # Printers
    "_ipp._tcp", "_ipps._tcp", "_pdl-datastream._tcp",
    # Streaming / media devices
    "_googlecast._tcp", "_airplay._tcp",
    # Phones / tablets / laptops
    "_companion-link._tcp", "_rdlink._tcp",         
    "_sleep-proxy._udp",                            
    "_spotify-connect._tcp",                        
    # Smart TVs
    "_androidtvremote._tcp", "_androidtvremote2._tcp",
    "_roku-rcp._tcp",                                 
    "_amzn-wplay._tcp",                               
]

# Maps mDNS service types to device categories for device_type classification.
MDNS_DEVICE_TYPE_HINTS = {
    # Phones / tablets
    "_companion-link._tcp": "Phone",
    "_rdlink._tcp": "Phone",
    # Apple devices (could be phone, tablet, or laptop)
    "_airplay._tcp": "Apple Device",
    "_homekit._tcp": "Apple Device",
    "_hap._tcp": "Smart Home Device",
    # Smart TVs / streaming
    "_googlecast._tcp": "Smart TV / Chromecast",
    "_androidtvremote._tcp": "Smart TV (Android)",
    "_androidtvremote2._tcp": "Smart TV (Android)",
    "_roku-rcp._tcp": "Smart TV (Roku)",
    "_amzn-wplay._tcp": "Smart TV (Fire TV)",
    # Printers
    "_ipp._tcp": "Printer",
    "_ipps._tcp": "Printer",
    "_pdl-datastream._tcp": "Printer",
    # IoT
    "_matter._tcp": "Smart Home Device",
    "_miio._udp": "Smart Home Device (Xiaomi)",
    "_tuya._tcp": "Smart Home Device (Tuya)",
    "_esphomelib._tcp": "IoT Device (ESPHome)",
    "_mqtt._tcp": "IoT Device",
    # Media / speakers
    "_spotify-connect._tcp": "Media Player",
    # General
    "_smb._tcp": "Desktop / NAS",
    "_afpovertcp._tcp": "Mac / NAS",
    "_ssh._tcp": "Server / Workstation",
}

#https://www.embedded.com/reworking-the-tcp-ip-stack-for-use-on-embedded-iot-devices/
# 5840 tends to be the typical tcp window for embedded systems 
EMBEDDED_TCP_WINDOW_THRESHOLD=5840
HIGH_ICMP_RTT_CV_THRESHOLD=0.25
CRITICAL_OT_PORTS={
    502:"Modbus/TCP",
    102:"S7/ISO-TSAP (Siemens)",
    44818:"EtherNet/IP",
    20000:"DNP3",
    4840:"OPC-UA",
    9600:"Omron FINS",
    1962:"PCWorx (Phoenix Contact)",
    20547:"ProConOS",
}

MQTT={
    1883:"MQTT",
    8883:"MQTT/TLS",
}

INDUSTRIAL_PORTS={**CRITICAL_OT_PORTS, **MQTT}

class DeviceSignals:
    def __init__(self,ip:str,mac:str):
        self.ip=ip
        self.mac=mac
        self.on_change_callback:Optional[Callable]=None
        self.ttl:Optional[int]=None
        self.hops_for_ttl:Optional[int]=None
        self.icmp_rtt_samples:list=[]
        self.tcp_isn_entropy:Optional[float]=None
        self.reverse_dns:str=""
        self.oui_vendor:str="Unknown"
        self.mdns_services:list=[]
        self.mdns_device_name:str="" # Device name extracted from mDNS 
        self.device_type:str="" # Inferred device type
        self.dhcp_fingerprint:str=""
        self.netbios_present:bool=False
        self.tcp_window_size:Optional[int]=None
        self.tcp_options:list=[]
        self.open_ports:list=[]
        self.banners:dict={}
        self.snmp_sysdescr:list=[]
        self.nmap_os_guess:str=""
    
    def register_callback(self,callback:Callable[[str,object],None])->None:
        """
        Register a callback invoked whenever any signal update function is called.
        """
        self.on_change_callback=callback

    def notify(self,field_name:str,value:object)->None:
        """
        Invoke the registered callback with the updated field name and value.
        """
        if self.on_change_callback is not None:
            self.on_change_callback(field_name,value)
    
    # Signal update functions
    def update_oui_vendor(self,value:str)->None:
        self.oui_vendor=value
        self.notify("oui_vendor",value)
    
    def update_open_ports(self,value:list)->None:
        self.open_ports=value
        self.notify("open_ports",value)
    def update_banners(self,value:dict)->None:
        self.banners=value
        self.notify("banners",value)

    def update_snmp_sysdescr(self,value:str)->None:
        self.snmp_sysdescr=value
        self.notify("snmp_sysdescr",value)

    def update_tcp_window_size(self,value:int)->None:
        self.tcp_window_size=value
        self.notify("tcp_window_size",value)

    def update_tcp_options(self,value:list)->None:
        self.tcp_options=value
        self.notify("tcp_options",value)

    def update_mdns_services(self,value:list)->None:
        self.mdns_services=value
        self.notify("mdns_services",value)

    def update_dhcp_fingerprint(self,value:str)->None:
        self.dhcp_fingerprint=value
        self.notify("dhcp_fingerprint",value)

    def update_netbios_present(self,value:bool)->None:
        self.netbios_present=value
        self.notify("netbios_present",value)

    def update_nmap_os_guess(self,value:str)->None:
        self.nmap_os_guess=value
        self.notify("nmap_os_guess",value)

    def update_mdns_device_name(self,value:str)->None:
        self.mdns_device_name=value
        self.notify("mdns_device_name",value)

    def update_device_type(self,value:str)->None:
        self.device_type=value
        self.notify("device_type",value)

    def update_icmp_rtt_samples(self,value:list)->None:
        self.icmp_rtt_samples=value
        self.notify("icmp_rtt_samples",value)
    
class OUIDatabase:
    def __init__(self,path=DEFAULT_OUI_DB_PATH):
        self.db:dict[str,str]={}
        self.load_OUI_csv(path)
    def load_OUI_csv(self,path:str)->None:
        if not os.path.exists(path):
            raise FileExistsError("OUI csv file not found")
        with open(path,newline='',encoding='utf-8') as f:
            reader=csv.DictReader(f)
            for row in reader:
                mac_address=row.get("Mac_Prefix").strip().upper()
                vendor=row.get("Vendor_Name").strip().lower()
                self.db[mac_address]=vendor

    @staticmethod
    def is_randomized_mac(mac_address: str) -> bool:
        """
        Detect locally-administered (randomized) MAC addresses.
        Bit 1 of the first octet is set (the "locally administered" bit).
        Common first-octet values: x2, x6, xA, xE (where x is any nibble).
        """
        mac_hex = mac_address.replace("-", "").replace(":", "").replace(".", "")
        if len(mac_hex)<2:
            return False
        first_byte=int(mac_hex[:2],16)
        return bool(first_byte&0x02)  

    def lookup(self,mac_address:str)->str:
        """
        Look up vendor by MAC prefix.
        """
        mac_address_hex_only=mac_address.replace("-", "").replace(":", "").replace(".", "")
        if len(mac_address_hex_only)<6:
            return "Unknown"
        if self.is_randomized_mac(mac_address):
            return "Unknown (Randomized MAC)"
        prefix=f"{mac_address_hex_only[0:2]}:{mac_address_hex_only[2:4]}:{mac_address_hex_only[4:6]}".upper()
        return self.db.get(prefix,"Unknown")

@dataclass
class ClassificationResult:
    """
    Stores the results of the device classification
    """
    tier:DeviceTier
    confidence:float
    score:float
    reasons:list
    override_signals:list
    signal_count:int

class DeviceClassifier:
    """
    Scores device signals using weighted heuristics and maps the cumulative
    score to a DeviceTier. Industrial port presence overrides all other signals.
    """
    ROBUST_THRESHOLD=6 
    MODERATE_THRESHOLD=2 
    FRAGILE_THRESHOLD=-4

    def classify(self,signals:DeviceSignals)->ClassificationResult:
        """
        Run all signal scoring checks and return a ClassificationResult.
        """
        score=0
        reasons=[]
        overrides=[]
        signal_count=0
        for port in signals.open_ports:
            if port in CRITICAL_OT_PORTS:
                overrides.append(f"Port {port} ({CRITICAL_OT_PORTS[port]}) is open - reclassify as critical")
        if overrides:
            return ClassificationResult(
                tier=DeviceTier.CRITICAL,
                confidence=1.0,
                score=-999,
                reasons=overrides,
                override_signals=overrides,
                signal_count=1
            )
        for port in signals.open_ports:
            if port in MQTT:
                c=-SIGNAL_WEIGHTS["industrial_port"]
                score+=c
                signal_count+=1
                reasons.append(f"IoT protocol port {port} ({MQTT[port]}) open (score {c:+.0f})")
        vendor_lower=signals.oui_vendor
        if any(kw in vendor_lower for kw in CRITICAL_VENDOR_KEYWORDS):
            c=-SIGNAL_WEIGHTS["oui_vendor_name"]*3   
            score+=c
            signal_count+=1
            reasons.append(f"Vendor '{signals.oui_vendor}' -> industrial (score {c:+.0f})")
        elif any(kw in vendor_lower for kw in FRAGILE_VENDOR_KEYWORDS):
            c=-SIGNAL_WEIGHTS["oui_vendor_name"]*2   
            score+=c
            signal_count+=1
            reasons.append(f"Vendor '{signals.oui_vendor}' -> IoT/embedded (score {c:+.0f})")
        elif any(kw in vendor_lower for kw in MODERATE_VENDOR_KEYWORDS):
            c=-SIGNAL_WEIGHTS["oui_vendor_name"]       
            score+=c
            signal_count+=1
            reasons.append(f"Vendor '{signals.oui_vendor}' -> consumer (score {c:+.0f})")
        elif any(kw in vendor_lower for kw in ROBUST_VENDOR_KEYWORDS):
            c=+SIGNAL_WEIGHTS["oui_vendor_name"]*2   
            score+=c
            signal_count+=1
            reasons.append(f"Vendor '{signals.oui_vendor}' -> enterprise (score {c:+.0f})")
        
        if signals.ttl is not None:
            initial_ttl, os_hint=self.infer_initial_ttl(signals.ttl,signals.hops_for_ttl)
            c=self.score_ttl(initial_ttl)
            score+=c
            signal_count+=1
            reasons.append(f"TTL={signals.ttl} -> initial={initial_ttl} ({os_hint}) (score {c:+.1f})")
        
        if signals.tcp_window_size is not None:
            c=self.score_tcp_window(signals.tcp_window_size)
            score+=c
            signal_count+=1
            reasons.append(f"TCP window={signals.tcp_window_size}B (score {c:+.1f})")
        if signals.tcp_options:
            c=self.score_tcp_options(signals.tcp_options)
            score+=c
            signal_count+=1
            reasons.append(f"TCP options={signals.tcp_options} (score {c:+.1f})")
        if signals.snmp_sysdescr:
            c,reason=self.score_snmp(signals.snmp_sysdescr)
            score+=c
            signal_count+=1
            reasons.append(
                f"SNMP sysDescr: '{signals.snmp_sysdescr[:60]}' -> {reason} (score {c:+.1f})"
            )
        all_banners=" ".join(signals.banners.values()).lower()
        if all_banners:
            c,reason=self.score_banner(all_banners)
            score+=c
            signal_count+=1
            reasons.append(f"Banner analysis: {reason} (score {c:+.1f})")
        # if len(signals.icmp_rtt_samples)>=5:
        #     c,reason=self.score_icmp_cv(signals.icmp_rtt_samples)
        #     score+=c
        #     signal_count+=1
        #     reasons.append(f"ICMP CV: {reason} (score {c:+.1f})")
        if signals.mdns_services:
            c,reason=self.score_mdns(signals.mdns_services)
            score+=c
            signal_count+=1
            reasons.append(f"mDNS {signals.mdns_services}: {reason} (score {c:+.1f})")
        if signals.netbios_present:
            c=+SIGNAL_WEIGHTS["dhcp_fingerprint"]   
            score+=c
            signal_count+=1
            reasons.append(f"NetBIOS broadcasts -> Windows host (score {c:+.1f})")
        tier=self.score_to_tier(score)
        confidence=min(1,signal_count/4)
        if signal_count == 0:
            tier=DeviceTier.UNKNOWN
            reasons.append("No classifiable signals — defaulting to UNKNOWN")
        return ClassificationResult(
            tier=tier,confidence=confidence, score=score,
            reasons=reasons,override_signals=overrides,
            signal_count=signal_count,
        )

    def infer_initial_ttl(self,received_ttl:int,hops:int)->tuple:
        """
        Infer the original TTL value before hop decrements.
        """
        initial_ttl=received_ttl+hops
        if initial_ttl<=64:
            return 64,"Linux/Unix/Embedded"
        if initial_ttl<=128:
            return 128,"Windows/Linux"
        return 255,"Network device/BSD"
    def score_ttl(self,initial_ttl:int)->float:
        """
        Score based on inferred initial TTL.
        """
        w=SIGNAL_WEIGHTS["ttl_bucket"]
        if initial_ttl==64:
            return -w         
        if initial_ttl==128:
            return +w*0.5  
        return +w       
    def score_tcp_window(self, window: int) -> float:
        """
        Score based on TCP window size from SYN-ACK.
        """
        w=SIGNAL_WEIGHTS["tcp_window_size"]
        if window<=1460:
            return -w*2   
        if window<=EMBEDDED_TCP_WINDOW_THRESHOLD:
            return -w  
        if window<=16384:
            return 0
        if window<=32768:
            return +w   
        return +w*2              
    def score_tcp_options(self, options: list) -> float:
        """
        Score based on which TCP options the device negotiates.
        """
        w=SIGNAL_WEIGHTS["tcp_options"]
        has_ws=any(o in options for o in ["WS","Window Scale"])
        has_sack=any(o in options for o in ["SACK","SACK Permitted"])
        has_ts=any(o in options for o in ["TS","Timestamps"])
        if has_ws and has_sack and has_ts: 
            return +w       
        if has_ws and has_sack:
            return +w*0.5  
        if has_sack:
            return 0.0       
        return -w    
    def score_snmp(self, sysdescr_list: str) -> tuple:
        """
        Score SNMP sysDescr against known keyword lists.
        """
        w = SIGNAL_WEIGHTS["snmp_sysdescr"]  
        for sysdescr in sysdescr_list:
            d = sysdescr.lower()
            for kw in ["simatic","s7-","contrologix","modicon","plc","scada","hmi"]:
                if kw in d:
                    return -w*3, f"industrial keyword '{kw}'" 
            for kw in FRAGILE_BANNER_KEYWORDS:
                if kw in d: 
                    return -w*2, f"embedded stack keyword '{kw}'"
            for kw in ROBUST_BANNER_KEYWORDS:
                if kw in d: 
                    return +w*2, f"server OS keyword '{kw}'"      
        return 0.0, "no distinctive keywords"
    def score_banner(self,banner:str)->tuple:
        """
        Scores the service banners against keyword lists.
        """
        w=SIGNAL_WEIGHTS["banner_keywords"] 
        for kw in FRAGILE_BANNER_KEYWORDS:
            if kw in banner: 
                return -w*2,f"fragile stack keyword '{kw}'"  
        for kw in ROBUST_BANNER_KEYWORDS:
            if kw in banner: 
                return +w,f"robust OS keyword '{kw}'"         
        return 0.0,"no distinctive keywords"
    # def score_icmp_cv(self,samples:list)->tuple:
    #     w=SIGNAL_WEIGHTS["icmp_RTT_cv"]
    #     mean=statistics.mean(samples)
    #     if mean==0:
    #         return 0.0,"zero mean RTT" 
    #     cv=statistics.stdev(samples)/mean
    #     if cv>HIGH_ICMP_RTT_CV_THRESHOLD*2:
    #         return -w*2,f"CV={cv:.2f} — very high RTT variance"  
    #     if cv>HIGH_ICMP_RTT_CV_THRESHOLD:
    #         return -w,f"CV={cv:.2f} — elevated RTT variance"                     
    #     return +w*0.5,f"CV={cv:.2f} — consistent RTT"
    def score_mdns(self, services: list)->tuple:
        """
        Score mDNS service types against known IoT and consumer service lists.
        """
        w=SIGNAL_WEIGHTS["mdns_service"] 
        for svc in services:
            if any(f in svc for f in FRAGILE_MDNS_SERVICES):
                return -w*2,f"IoT mDNS service '{svc}'"              
            if any(f in svc for f in MODERATE_MDNS_SERVICES):
                return -w,f"consumer device mDNS service '{svc}'"         
        return 0.0,"no distinctive mDNS services"
    def score_to_tier(self,score:float)->DeviceTier:
        """
        Map a cumulative score to a DeviceTier using threshold comparison.
        """
        if score>=self.ROBUST_THRESHOLD:
            return DeviceTier.ROBUST
        if score>=self.MODERATE_THRESHOLD:
            return DeviceTier.MODERATE 
        if score>=self.FRAGILE_THRESHOLD:
            return DeviceTier.FRAGILE   
        return DeviceTier.CRITICAL 