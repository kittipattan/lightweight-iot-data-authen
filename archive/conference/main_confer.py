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
import time

aggregated_data_dict = {}

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

    # print(f"    Leader {leader.id} Private key (prkL) = {str(leader.prk.d)[:10]}...")
    # print(
    #     f"    Leader {leader.id} Public key (PKL) = ({str(leader.PK.W.x)[:10]}..., {str(leader.PK.W.y)[:10]}...)"
    # )

    # print(f"""Data sent to Fog
    # PK: {leader.PK.W}
    # id: {leader.id}
    # gid: {leader.gid}
    # Message: {leader.data[:30]}...
    # V: {V.W}
    # r: {r}""")

    fog_proof = fog.genProof()
    # print(f"    Fog Private key (prkF) = {str(fog.prk.d)[:10]}...")
    # print(
    #     f"    Fog Public key (PKF) = ({str(fog.PK.W.x)[:10]}..., {str(fog.PK.W.y)[:10]}...)"
    # )

    return fog.verifyProof(leader_proof) and leader.verifyProof(fog_proof)


def authen_iot_fog(group: List[IoTPi], fog: Fog):
    threads: List[Thread] = []

    for iot in group:
        # t = Thread(target=lambda: fog.recvData(iot.createPacket()))
        # threads.append(t)
        # t.start()
        fog.recvData(iot.createPacket())

    for t in threads:
        # t.join()
        pass

    # measure_computation_cost(fog.verifyToken, "Token verification", 1, group)
    aggregated_data_dict[group[0].gid] = []
    fog.verifyToken(group, aggregated_data_dict[group[0].gid])

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

    # print(f"Initialization successful within {timeit.default_timer() - start_time} s")
    
    # for group in IoTs:
    #     leader = group[0]  # first member is Leader
    #     puf_based_authen(group, leader, server)

    # print(
    #     " \n##################################### Sending Group Key #####################################\n "
    # )
    # # Send packet to each IoT
    # for group in IoTs:
    #     leader = group[0]
    #     print(f"Starting Group {leader.gid} sending group key...")

    #     for iot in group:
    #         if isinstance(iot, Leader):
    #             iot.genGroupKey()
    #             continue
    #         pkt = leader.sendGroupKey(iot.id)
    #         iot.recvGroupKey(pkt)
    #         # print(f"    Group Key: {iot.gk}")

    #     print(f"Group {leader.gid} sending group key successful")
    ############################## End of PUF-based Authentication ##############################

    # print(
    #     " \n####################################### Leader - Fog ########################################\n "
    # )

    # PHASE 3: Group Authentication and Secure Channel Establishment with Fog Node
    for group, fog in zip(IoTs, fogs):
        leader: LeaderPi = group[0]

        # print(
        #     f" ---------------------- Group {leader.gid} Group Authentication (Leader-Fog) phase ---------------------- "
        # )

        is_verified = authen_leader_fog(leader, fog)
        if is_verified:
            print(f"Verified")
        else:
            print("Not verified")

        ssk_salt = os.urandom(32)
        leader.deriveSSK(fog.PK, ssk_salt)
        fog.deriveSSK(leader.PK, ssk_salt)

        # print(f"Leader-Fog: {(timeit.default_timer() - start_time)*1000} ms")

        # print("Leader-Fog:")
        # print(f"    shared symmetric key: {leader.ssk}")
        # print(f"    shared symmetric key: {fog.ssk}")
    ####################################### End of NIZKP #######################################

    # print(
    #     " \n######################################### IoT - Fog #########################################\n "
    # )

    # PHASE 4: Data Authentication and Integrity Verification
    for group, fog in zip(IoTs, fogs):
        leader = group[0]
        group_key_to_fog = leader.sendGK()
        
        # Secret Generation +
        # AES Key Encryption and Key Splitting
        messages_to_leader = fog.genSec(group_key_to_fog, group)
        
        # Secret distribution
        leader.distributeSecret(messages_to_leader, group)
        
        # enc_packet = fog.sendSecToLeader(group)
        # (secret, ciphered_keys) = leader.recvSecFromFog(enc_packet)
        # leader.secret = secret
        # leader.partialKey = ciphered_keys[0]
        # # print(f"leader secret and pck: {leader.secret} |||| {leader.partialKey} |||| {len(leader.partialKey)}")

        # for iot, pck in zip(group, ciphered_keys):
        #     if isinstance(iot, Leader):
        #         continue
        #     enc_pkt = leader.sendSecToIoT(iot.id, secret, pck)
        #     iot.recvSecFromLeader(leader.id, enc_pkt)
        #     # print(f"iot secret and pck: {iot.secret} |||| {iot.partialKey} |||| {len(iot.partialKey)}")

    # Data Authentication
    for group, fog in zip(IoTs, fogs):
        leader = group[0]
        # print(
        #     f" ---------------------- Group {leader.gid} Data Authentication (IoT-Fog) phase -------------------------- "
        # )
        
        def test_lightpuf():
            authen_leader_fog(leader, fog)
            ssk_salt = os.urandom(32)
            leader.deriveSSK(fog.PK, ssk_salt)
            fog.deriveSSK(leader.PK, ssk_salt)
            group_key_to_fog = leader.sendGK()
            messages_to_leader = fog.genSec(group_key_to_fog, group)   
            leader.distributeSecret(messages_to_leader, group)          
            authen_iot_fog(group, fog)
        
        def test_throughput():
            authen_leader_fog(leader, fog)
            ssk_salt = b'\x91\x8a\xb7\xf8\x05\xea{\x93\x04;\x83wJ\x9ef89\xf3\x95\xa3\x94\x8d\xbb\x18\x01j\xde\xcbN\x8e\x04\xa2'
            leader.deriveSSK(fog.PK, ssk_salt)
            fog.deriveSSK(leader.PK, ssk_salt)
            group_key_to_fog = leader.sendGK()
            messages_to_leader = fog.genSec(group_key_to_fog, group)
            leader.distributeSecret(messages_to_leader, group)
            authen_iot_fog(group, fog)
            
        # measure_computation_cost(test_data_authentication, "Device Authentication By Group Size", 1000)
        measure_computation_cost(authen_iot_fog, "Data Authentication per group size in one Fog node", 1000, group, fog)

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

    # print(
    #     " \n######################################## Fog - Cloud ########################################\n "
    # )

    # Cloud Uploading
    start_time = time.time()
    
    for group, fog in zip(IoTs, fogs):
        gid = group[0].gid
        fog_id = gid
        upload_threads = []

        # print(
        #     f" ---------------------- Group {gid} Cloud uploading (Fog-Cloud) phase ---------------------------- "
        # )

        # t = Thread(
        #     target=fog.uploadToCloud, args=(len(fogs), devices_per_node, fog_id, gid)
        # )
        # upload_threads.append(t)
        # t.start()
        fog.uploadToCloud(len(fogs), devices_per_node, fog_id, gid, aggregated_data_dict[gid])

    # for t in upload_threads:
    #     t.join()
        
    end_time = time.time()

    print(f"Fog cloud uploading success within {end_time - start_time} s")

    #################################### End of Our Scheme ####################################

    return 0


if __name__ == "__main__":
    for n in [500]:
        main(1,n)
