import hashlib
import random
import time
import timeit
import secrets
import numpy as np
from numpy.polynomial import Chebyshev

shared_x = 0.9   # Shared value, Value between [-1, 1]

# Function to compute Chebyshev polynomials and simulate authentication and key agreement
def chebyshev_polynomial(u, x):
    # Create Chebyshev polynomial of degree u using NumPy
    u = 160
    Tn = Chebyshev.basis(u)
    # Evaluate the Chebyshev polynomial at x
    result = Tn(x)
    # Apply modulo p operation to simulate cryptographic behavior
    return result
    
def sym_encryption(key, data):
    return 0

def hash_function(data):
    return hashlib.sha256(data.encode()).digest()

def is_fresh(t):
    current = time.time()
    # not later than 1 min
    if (t + 60 >= current):
        return True
    
    return False

class CloudServer:
    def __init__(self, server_id):
        self.server_id = server_id
        self.s = secrets.randbits(30)
        self.user_data = []
        self.fog_data = []
        self.session_key = None

    def register_user(self, id, rid):
        o = secrets.randbits(30)
        r = int.from_bytes(hash_function(f"{id}{self.s}{o}")) ^ rid
        nid = sym_encryption(self.s, f"{id}{o}")
        self.user_data.append({"id": id, "o": o})
        return (nid, r)
    
    def register_fog(self, id):
        n = secrets.randbits(30)
        r = hash_function(f"{id}{self.s}{n}")
        nid = sym_encryption(self.s, f"{id}{n}")
        self.fog_data.append({"id": id, "n": n})
        return (nid, r)
    
    def compute_shared_key(self):
        t_3 = time.time()

        v_i = hash_function("mock vi")
        v_j = hash_function("mock vj")
        au_i = hash_function("mock au_i")
        au_j = hash_function("mock au_j")

        w = secrets.randbits(30)

        b = chebyshev_polynomial(w, -0.5)
        c = chebyshev_polynomial(w, -0.5)

        ms_3 = (v_i, v_j, au_i, au_j, b, c, t_3)
        return ms_3

class FogNode:
    def __init__(self, node_id):
        self.node_id = node_id
        self.cloud = None
        self.r = None
        self.nid = None

        self.v = None
        self.a = None
        self.pid_i = None
        self.session_key = None

    def register(self, cloud: CloudServer):
        self.cloud = cloud
        (self.nid, self.r) = self.cloud.register_fog(self.node_id)

    def request(self, ms_1):
        (_, pid, w, t_1, t_u_x) = ms_1

        if (is_fresh(t_1) == False):
            # raise Exception("Timestamp t_1 not fresh")
            pass
        
        t_2 = time.time()
        self.v = secrets.randbits(30)
        t_v_x = chebyshev_polynomial(self.v, shared_x)
        self.a = chebyshev_polynomial(self.v, t_u_x)
        self.pid_i = pid

        w = hash_function(f"{self.pid_i}{self.node_id}{self.a}{t_v_x}{w}{t_2}")

        ms_2 = (self.nid, self.a, t_v_x, w, t_2)
        return ms_2

    def receive_sk(self, ms_3):
        (v_i, v_j, au_i, au_j, b, c, t_3) = ms_3

        if (is_fresh(t_3) == False):
            # raise Exception("Timestamp t_3 not fresh")
            pass
        
        t_v_b = chebyshev_polynomial(self.v, b)

        hid_prime = int.from_bytes(hash_function(f"{self.r}{self.node_id}")) ^ int.from_bytes(v_j)
        self.sk = hash_function(f"{self.a}{b}{c}{t_v_b}")
        au_prime = hash_function(f"{self.pid_i}{self.node_id}{self.nid}{hid_prime}{b}{self.sk}{t_3}")

        if (au_prime != au_j):
            # raise Exception("au_prime is not equal to au")
            pass
        
        # print("sk of fog node is", self.sk)

        ms_4 = (v_i, au_i, self.a, b, c, t_3)
        return ms_4


class User:
    def __init__(self, user_id, password):
        self.user_id = user_id
        self.password = password
        self.fog = None
        self.cloud = None
        self.r_star = None
        self.nid = None

        self.u = None
        self.m = None
        self.session_key = None

    def register(self, fog: FogNode, cloud: CloudServer):
        self.fog = fog
        self.cloud = cloud

        a = secrets.randbits(30)
        rid = int.from_bytes(hash_function(f"{self.user_id}{self.password}")) ^ a
        (nid, r) = self.cloud.register_user(self.user_id, rid)
        self.r_star = r ^ a
        self.nid = nid

    def request(self):
        t_1 = time.time()
        self.u = secrets.randbits(30)
        t_u_x = chebyshev_polynomial(self.u, shared_x)

        pid = hash_function(f"{user.user_id}{user.password}{self.nid}")
        self.m = int.from_bytes(hash_function(f"{self.user_id, self.password}")) ^ self.r_star
        w = hash_function(f"{id}{t_u_x}{self.m}{self.nid}{t_1}")

        ms_1 = (self.nid, pid, w, t_1, t_u_x)
        return ms_1

    def receive_sk(self, ms_4):
        (v, au, a, b, c, t_3) = ms_4

        if (is_fresh(t_3) == False):
            # raise Exception("Timestamp t_3 not fresh")
            pass
        
        t_u_c = chebyshev_polynomial(self.u, c)

        self.sk = hash_function(f"{a}{b}{c}{t_u_c}")
        hid_prime = int.from_bytes(hash_function(f"{self.m}{self.user_id}")) ^ int.from_bytes(v)
        au_prime = hash_function(f"{self.user_id}{self.nid}{hid_prime}{c}{self.sk}{t_3}")

        if (au_prime != au):
            # raise Exception("au_prime is not equal to au")
            pass
        
        # print("sk of user is", self.sk)

# ALAKAP Protocol Implementation
def ALAKAP(user: User, fog_node: FogNode, cloud_server: CloudServer):
    total_time = 0
    start_time = timeit.default_timer()

    # 01 - user to fog
    ms_1 = user.request()
    
    # 02 - fog to cloud
    ms_2 = fog_node.request(ms_1)
    
    end_time = timeit.default_timer()
    # print(f"user to cloud took {(end_time - start_time)*1000:.5f} ms (user->fog->)")
    total_time += end_time - start_time

    # 03 - cloud computes vals that will to be used to obtain sk
    ms_3 = cloud_server.compute_shared_key()

    # 04 - fog computes sk
    start_time = timeit.default_timer()
    ms_4 = fog_node.receive_sk(ms_3)

    # 04 - user computes sk
    user.receive_sk(ms_4)

    end_time = timeit.default_timer()
    # print(f"cloud to user took {(end_time - start_time)*1000:.5f} ms (->fog->user)")
    total_time += end_time - start_time

    return total_time
    
if __name__ == "__main__":

    cloud_server = CloudServer(server_id="CloudServer1")
    fog_node = FogNode(node_id="FogNode1")
    user = User(user_id="User1", password="SecurePassword")

    
    user.register(fog=fog_node, cloud=cloud_server)
    fog_node.register(cloud=cloud_server)

    print("Registered successfully")

    r = 100
    total_time = 0
    for i in range(r):
        total_time += ALAKAP(user, fog_node, cloud_server)

    print("Shared keys successfully")

    total_time = total_time / r
    print(f"total time taken {(total_time*1000):.5f} ms, {r} rounds")