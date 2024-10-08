from leader_rasppi import LeaderPi
from iot_rasppi import IoTPi
from server import LocalServer
from fog import Fog
from pypuf.io import random_inputs
import os
from typing import List
from threading import Thread
import random
import string
from utils.measurement import measure_computation_cost


def initialize_group(
    fog_nodes: int, devices_per_node: int, server: LocalServer, IoTs: List[List[IoTPi]]
):
    for g in range(fog_nodes):
        # Add Leader
        group: List[IoTPi] = []

        # Add IoT members
        for i in range(1, devices_per_node + 1):
            id = (g * devices_per_node) + i
            gid = g + 1
            data = f"sample data from IoT device {id} {''.join(random.choices(string.ascii_letters,k=73))}"
            # data = f"sample data from IoT device {id}"

            iot = IoTPi(id, gid, id, data)
            if i == 1:
                iot = LeaderPi(id, gid, id, data)

            challenge = random_inputs(64, 256, id)
            challenge = (1 - challenge) // 2
            response = iot.genResponse(challenge)
            server.registerCRP(id, gid, challenge, response)

            group.append(iot)

        IoTs.append(group)


def authen_leader_fog(leader: LeaderPi, fog: Fog):
    leader_proof = leader.genProof(leader.data)
    (PKL, id, gid, M, V, r) = leader_proof

    fog_proof = fog.genProof()

    return fog.verifyProof(leader_proof) and leader.verifyProof(fog_proof)


def authen_iot_fog(group: List[IoTPi], fog: Fog):
    threads: List[Thread] = []

    for iot in group:
        t = Thread(target=lambda: fog.recvData(iot.createPacket()))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    fog.verifyToken(group)

def main(fog_nodes, devices_per_node):
    fog_nodes = fog_nodes
    devices_per_node = devices_per_node

    IoTs: List[List[IoTPi]] = []
    server = LocalServer()
    fogs: List[Fog] = [Fog() for _ in range(fog_nodes)]

    # Reset the table
    server.dropCRP()

    # PHASE 1: System Initialization
        # Create IoT groups and register CRP into the LocalServer
    print(
        " \n###################################### Initialization ######################################\n "
    )
    print(f"    no. of groups: {fog_nodes}")
    print(f"    no. of devices per group: {devices_per_node}")

    initialize_group(fog_nodes, devices_per_node, server, IoTs)
    
    # Generate pair key between Leader and Device
    for group, fog in zip(IoTs, fogs):
        device_crps = []
        for iot in group:
            # CRP retrieval
            device_crps.append(server.sendCRP(iot.id))
            
        # Pair Key and Nonces Generation + 
        # Device Key Generation +
        # Secret Generation
        fog.deriveDeviceKey(device_crps, group)

    # PHASE 3: Group Authentication and Secure Channel Establishment with Fog Node
    for group, fog in zip(IoTs, fogs):
        leader: LeaderPi = group[0]
        
        is_verified = authen_leader_fog(leader, fog)
        if is_verified:
            print(f"Verified")
        else:
            print("Not verified")

        ssk_salt = os.urandom(32)
        leader.deriveSSK(fog.PK, ssk_salt)
        fog.deriveSSK(leader.PK, ssk_salt)

    # PHASE 4: Data Authentication and Integrity Verification
    for group, fog in zip(IoTs, fogs):
        leader = group[0]
        group_key_to_fog = leader.sendGK()
        
        # Secret Generation +
        # AES Key Encryption and Key Splitting
        messages_to_leader = fog.genSec(group_key_to_fog, group)
        
        # Secret distribution
        leader.distributeSecret(messages_to_leader, group)

    # Data Authentication
    for group, fog in zip(IoTs, fogs):
        leader = group[0]
        
        def test_data_authentication():
            authen_leader_fog(leader, fog)
            ssk_salt = os.urandom(32)
            leader.deriveSSK(fog.PK, ssk_salt)
            fog.deriveSSK(leader.PK, ssk_salt)
            group_key_to_fog = leader.sendGK()
            messages_to_leader = fog.genSec(group_key_to_fog, group)   
            leader.distributeSecret(messages_to_leader, group)          
            authen_iot_fog(group, fog)
    
        measure_computation_cost(test_data_authentication, "Data Authentication", 1000)
        
        def test_throughput():
            authen_leader_fog(leader, fog)
            ssk_salt = b'\x91\x8a\xb7\xf8\x05\xea{\x93\x04;\x83wJ\x9ef89\xf3\x95\xa3\x94\x8d\xbb\x18\x01j\xde\xcbN\x8e\x04\xa2'
            leader.deriveSSK(fog.PK, ssk_salt)
            fog.deriveSSK(leader.PK, ssk_salt)
            group_key_to_fog = leader.sendGK()
            messages_to_leader = fog.genSec(group_key_to_fog, group)
            leader.distributeSecret(messages_to_leader, group)
            authen_iot_fog(group, fog)

        # r = 10
        # batch_size = 50
        # print(f"Our - Throughput")
        # for no_request in [1, 2, 4, 10, 50, 100, 200, 500, 1000, 5000, 10000]:
        #     threads = []
        #     throughput = 0
        #     for _ in range(r):
        #         no_group = math.ceil(no_request/batch_size)
        #         start_time = timeit.default_timer()
        #         for _ in range(no_group):
        #             t = Thread(target=lambda: test_throughput())
        #             threads.append(t)
        #             t.start()
        #         for t in threads:
        #             t.join()
        #         end_time = timeit.default_timer()
        #         total_time = end_time - start_time
        #         try:
        #             throughput += no_request / total_time
        #         except:
        #             throughput += no_request
        #     print(f"Concurrent devices: {no_request}, Throughput: {throughput/r:.2f} transactions/sec")
        
        # measure_computation_cost(authen_iot_fog, "Authen IoT-Fog", 100, group, fog)

        # print(f"All {devices_per_node} IoTs data authen success")

    # Cloud Uploading
    for group, fog in zip(IoTs, fogs):
        gid = group[0].gid
        fog_id = gid
        upload_threads = []

        t = Thread(
            target=fog.uploadToCloud, args=(len(fogs), devices_per_node, fog_id, gid)
        )
        upload_threads.append(t)
        t.start()

        for t in upload_threads:
            t.join()

    return 0


if __name__ == "__main__":
    for n in [1,5,10,50,100,200,500,1000]:
        main(1,n)
