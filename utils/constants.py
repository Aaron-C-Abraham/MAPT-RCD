import os

# Default file / directory paths
# All paths are derived from PROJECT_ROOT so that the project can be moved
# to any directory and everything still resolves correctly.
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# CSV export of IEEE OUI (Organizationally Unique Identifier) data. 
DEFAULT_OUI_DB_PATH = os.path.join(PROJECT_ROOT, "database", "mac-vendors-export.csv")

# Nmap's OS fingerprint database.Parsed to correlate TCP/IP stack
DEFAULT_NMAP_OS_DB_PATH = os.path.join(PROJECT_ROOT, "database", "nmap-os-db.txt")

# Persistent JSON file for the PCF.
DEFAULT_PCF_PATH = os.path.join(PROJECT_ROOT, "pcf_evidence.json")

# Final aggregated results exported at the end of a session.
DEFAULT_RESULTS_PATH = os.path.join(PROJECT_ROOT, "results.json")

# Upper bound on the number of host addresses in a subnet that will be
# scanned. 
MAX_SUBNET_SIZE = 1024

# Number of concurrent threads used by the active scanner.  
DEFAULT_SCAN_THREADS = 10

# Duration (in seconds) to listen during a passive-recon phase before
# moving on.
DEFAULT_PASSIVE_WAIT_SEC = 60


# Minimum Jaccard / cosine similarity score (0–1) two device fingerprints
# must reach to be placed in the same cluster. 
FLEET_SIMILARITY_THRESHOLD = 0.75

# A cluster must contain at least this many members; singletons are not
# worth creating a cluster for because there is no probe-work to save.
FLEET_MIN_CLUSTER_SIZE = 2

# Maximum number of probe results from the cluster representative that are
# propagated back to the other members.
FLEET_MAX_REPRESENTATIVE_PROBES = 3

# Discount factor (gamma)
CMDP_DISCOUNT_FACTOR = 0.99

# Adam optimiser learning rate for the policy/value networks. 
CMDP_LEARNING_RATE = 3e-4

# Acceptable constraint violation tolerance
CMDP_CONSTRAINT_TOLERANCE = 0.01

# Dimensionality of the state vector fed into the policy network
CMDP_STATE_DIM = 20

# Width of the hidden layers in the policy and value MLPs.
CMDP_HIDDEN_DIM = 128
