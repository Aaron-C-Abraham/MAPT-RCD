import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional

class EvidenceApproach(Enum):
    """
    How the evidence was obtained.
    """
    PASSIVE='passive'
    ACTIVE='active'
    INFERRED='inferred'

class NodeType(Enum):
    """
    Category of evidence stored in a PCF node
    """
    SESSION="session" 
    DISCOVERY="discovery" 
    PASSIVE="passive"
    PROBE= "probe"
    PORT_SCAN="port_scan"
    SERVICE_PROBE="service_probe"
    OS_ID="os_id" 
    TIER_ID="tier_id"
    RETIER="retier" 
    EXPLOIT="exploit"
    POST_EXPLOIT="post_exploit"
    SESSION_EVENT="session_event"
    FLEET_INFERENCE="fleet_inference"
    POLICY_DECISION="policy_decision"
    TOOL_CONTRACT="tool_contract_check"
    VALIDATION="validation"
    SAFETY_REVIEW="safety_review"

@dataclass
class PCFEvidenceNode:
    """
    Single node in the PCF Evidence DAG. Contains the evidence payload,
    parent links, a SHA-256 content hash for integrity verification,
    and metadata (timestamp, phase, device IP).
    """
    node_id:str
    node_type:NodeType
    phase:str
    timestamp:str
    data_hash:str
    parent_ids:List[str]=field(default_factory=list)
    payload:Dict=field(default_factory=dict)
    evidence_approach:EvidenceApproach=EvidenceApproach.PASSIVE
    device_ip:str=""

    def to_dict(self)->dict:
        """
        Serialize the evidence node to a dict for JSON export, reporting,
        and database storage.
        """
        return {
            "node_id":      self.node_id,
            "node_type":    self.node_type.value,     
            "phase":        self.phase,
            "timestamp":    self.timestamp,
            "data_hash":    self.data_hash,
            "parent_ids":   self.parent_ids,
            "payload":      self.payload,
            "oracle_level": self.evidence_approach.value,
            "device_ip":    self.device_ip,
        }
    @classmethod
    def from_dict(cls,d:dict)->"PCFEvidenceNode":
        """
        Deserialize a dict back into a PCFEvidenceNode instance.
        """
        return cls(
            node_id      = d["node_id"],
            node_type    = NodeType(d["node_type"]),
            phase        = d["phase"],
            timestamp    = d["timestamp"],
            data_hash    = d["data_hash"],
            parent_ids   = d.get("parent_ids", []),
            payload      = d.get("payload", {}),
            evidence_approach = EvidenceApproach(d.get("oracle_level", "passive")),
            device_ip    = d.get("device_ip", ""),
        )

class PCFDAG:
    def __init__(self):
        self.nodes:Dict[str,PCFEvidenceNode]={}
        self.root_ids:List[str]=[]
        self.device_index: Dict[str, List[str]]={}
        import threading
        self.lock=threading.Lock()

    def add_node(
            self,
            node_type:NodeType,
            phase:str,
            payload:dict,
            parent_ids:Optional[List[str]]=None,
            evidence_approaches:EvidenceApproach=EvidenceApproach.PASSIVE,
            device_ip:str=""
    )->str:
        """
        Add a new evidence node to the DAG. 
        """
        with self.lock:
            node_id=f"pcf-{uuid.uuid4().hex[:12]}"
            parent_ids=parent_ids or []
            parent_hashes=[
                self.nodes[pid].data_hash 
                for pid in parent_ids
                if pid in self.nodes
            ]
            hash_input={
                "payload":payload,
                "parent_hashes":sorted(parent_hashes),
            }
            data_hash=hashlib.sha256(
                json.dumps(
                    hash_input,
                    sort_keys=True,
                    default=str
                ).encode()
            ).hexdigest()

            node = PCFEvidenceNode(
                node_id=node_id,
                node_type=node_type,
                phase=phase,
                timestamp=datetime.now().isoformat(),  
                data_hash=data_hash,
                parent_ids=parent_ids,
                payload=payload,
                evidence_approach=evidence_approaches,
                device_ip=device_ip,
            )

            self.nodes[node_id]=node
            if not parent_ids:
                self.root_ids.append(node_id)
            
            if device_ip:
                if device_ip not in self.device_index:
                    self.device_index[device_ip]=[]
                self.device_index[device_ip].append(node_id)

            return node_id

    def get_node(self,node_id:str)->Optional["PCFEvidenceNode"]:
        """Look up a single evidence node by its ID. Returns None if not found."""
        return self.nodes.get(node_id)
    
    def get_all_nodes(self)->List[dict]:
        """Return all nodes as dicts."""
        with self.lock:
            return [n.to_dict() for n in self.nodes.values()]
    def get_device_nodes(self,device_ip:str)->List[Dict]:
        """Return all nodes associated with a specific device IP as dicts."""
        with self.lock:
            ids=self.device_index.get(device_ip, [])
            return [self.nodes[i].to_dict() for i in ids if i in self.nodes]
    def get_nodes_by_type(self,node_type:NodeType)->List[dict]:
        """Return all nodes of a specific NodeType as dicts."""
        with self.lock:
            return [
                n.to_dict()
                for n in self.nodes.values()
                if n.node_type == node_type
            ]
    def get_phase_nodes(self,phase:str)->List[dict]:
        """Return all nodes belonging to a specific phase as dicts."""
        with self.lock:
            return [
                n.to_dict()
                for n in self.nodes.values()
                if n.phase == phase
            ]
    def get_path(self,node_id:str)->List[dict]:
        """
        Trace the evidence chain from a node back to the root using BFS.
        """
        with self.lock:
            path=[]
            visited=set()
            queue=[node_id]
            while queue:
                current_id=queue.pop(0)
                if current_id in visited:
                    continue
                visited.add(current_id)
                node=self.nodes.get(current_id)
                if node:
                    path.append(node.to_dict())
                    queue.extend(node.parent_ids)
            return path
    def get_children(self,node_id:str)->List[dict]:
        """
        Return the immediate children of a node.
        """
        with self.lock:
            return [
                n.to_dict() for n in self.nodes.values()
                if node_id in n.parent_ids
            ]
    
    def integrity_verification(self)->tuple:
        """
        Verify the hash chain integrity of every node in the DAG.
        """
        errors=[]
        for node_id,node in self.nodes.items():
            for pid in node.parent_ids:
                if pid not in self.nodes:
                    errors.append(f"Node {pid}, parent of {node_id}, does not exist in the node list")
            parent_hashes=[
                self.nodes[pid].data_hash
                for pid in node.parent_ids
                if pid in self.nodes
            ]
            hash_input={
                "payload":node.payload,
                "parent_hashes":sorted(parent_hashes)
            }
            expected_hash=hashlib.sha256(
                    json.dumps(hash_input, sort_keys=True, default=str).encode()
                ).hexdigest()
            if expected_hash!=node.data_hash:
                errors.append(
                    f"Node {node_id} ({node.node_type.value} / {node.phase}): "
                    f"hash mismatch. Expected {expected_hash[:16]}... "
                    f"got {node.data_hash[:16]}..."
                )
        return (len(errors)==0,errors)
    
    def save(self, path: str) -> None:
        """
        Serialise the entire DAG to a JSON file.
        """
        with self.lock:
            data={
                "version":2,                                      
                "root_ids":self.root_ids,                         
                "nodes":[n.to_dict() for n in self.nodes.values()],
            }
        with open(path,"w",encoding="utf-8") as f:
            json.dump(data,f,indent=2)

    def load(self, path: str) -> None:
        """
        Load a previously saved DAG from a JSON file.
        """
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        with self.lock:
            for node_dict in data.get("nodes",[]):
                node=PCFEvidenceNode.from_dict(node_dict)
                if node.node_id not in self.nodes:
                    self.nodes[node.node_id]=node
                    if node.device_ip:
                        if node.device_ip not in self.device_index:
                            self.device_index[node.device_ip]=[]
                        self.device_index[node.device_ip].append(node.node_id)
            # Merge root IDs — avoid duplicates
            for root_id in data.get("root_ids",[]):
                if root_id not in self.root_ids:
                    self.root_ids.append(root_id)

    def summary(self) -> dict:
        """
        Return a high-level summary of the DAG contents.
        """
        with self.lock:
            type_counts:Dict[str,int]={}
            evidence_approach_counts:Dict[str,int]={}
            for node in self.nodes.values():
                type_counts[node.node_type.value]=type_counts.get(node.node_type.value,0)+1
                evidence_approach_counts[node.evidence_approach.value] = evidence_approach_counts.get(node.evidence_approach.value, 0)+1
            return {
                "total_nodes":len(self.nodes),    
                "root_nodes":len(self.root_ids),  
                "devices_tracked":len(self.device_index),
                "by_type":type_counts,                 
                "by_oracle_level":evidence_approach_counts,
            }

    
    



