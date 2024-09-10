from leader import Leader
from iot import IoT
from server import LocalServer
from fog import Fog
from random import randbytes
from pypuf.io import random_inputs
import secrets
from typing import List
import timeit
from threading import Thread, Barrier
from utils.aes256 import AESCipher
from hashlib import sha256
import random
import string


def initialize_group(
    fog_nodes: int, devices_per_node: int, server: LocalServer, IoTs: List[List[IoT]]
):
    for g in range(fog_nodes):
        # Add Leader
        group: List[IoT] = []

        # Add IoT members
        for i in range(1, devices_per_node + 1):
            id = (g * devices_per_node) + i
            gid = g + 1
            data = f"sample data from IoT device {id} {''.join(random.choices(string.ascii_letters,k=73))}"
            # data = f"sample data from IoT device {id}"

            iot = IoT(id, gid, id, data)
            if i == 1:
                iot = Leader(id, gid, id, data)

            challenge = random_inputs(64, 128, id)
            challenge = (1 - challenge) // 2
            response = iot.genResponse(challenge)
            server.registerCRP(id, gid, challenge, response)

            group.append(iot)

        IoTs.append(group)


def enroll_group(leader: Leader, iot: IoT, server: LocalServer):

    leader_req = server.genEnrollReq(leader.id, iot.id)
    req = server.genEnrollReq(iot.id, leader.id)

    # Each device receives request and responds back with AUTH
    (leader_auth, m) = leader.recvEnrollReq(leader_req)
    (auth, n) = iot.recvEnrollReq(req)

    # LocalServer responds to each AUTH and sends back X for both devices
    (X, pairing_X) = server.resToAuth(leader.id, iot.id, leader_auth, auth, m, n)

    # Each device adds the pairing device information to its local database
    leader.addPairingInfo(X)
    iot.addPairingInfo(pairing_X)


def mutual_authen_group(leader: Leader, iot: IoT):
    leader_req = leader.reqMutAuth(iot.id)
    iot_PROOF = iot.resMutAuth(leader_req)

    if not (leader.verifyMutAuthProof(iot_PROOF)):
        raise Exception("MutAuth failed: Leader failed to verify IoT device")

    # Leader authen IoT device successfully
    # swap role
    leader_PROOF = leader.resMutAuth()

    if not (iot.verifyMutAuthProof(leader_PROOF)):
        raise Exception("MutAuth failed: IoT failed to verify Leader device")


def puf_based_authen(group: List[IoT], leader: Leader, server: LocalServer):
    # Enrollment phase
    print(f"\nStarting Group {leader.gid} Enrollment phase...")
    start_time = timeit.default_timer()
    for iot in group:
        # LocalServer send Request to Leader and pairing IoT
        if isinstance(iot, Leader):
            continue

        enroll_group(leader, iot, server)

    print(
        f"Group {leader.gid} Enrollment successful within {timeit.default_timer() - start_time} s"
    )

    # Mutual Authentication and Key Exchange phase
    print(f"\nStarting Group {leader.gid} Mutual Authentication phase...")
    start_time = timeit.default_timer()
    for iot in group:
        if isinstance(iot, Leader):
            continue

        mutual_authen_group(leader, iot)

        # Key Exchange
        leader.exchangeKey()
        iot.exchangeKey()

        # print(f"KeyEx between:")
        # print(f"    Leader {leader.id}: {leader.localDatabase[iot.id]}")
        # print(f"       IoT {iot.id}: {iot.localDatabase[leader.id]}")

    print(
        f"Group {leader.gid} MutAuth and KeyEx successful within {timeit.default_timer() - start_time} s"
    )


def authen_leader_fog(leader: Leader, fog: Fog):
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


def authen_iot_fog(group: List[IoT], fog: Fog):
    threads: List[Thread] = []

    for iot in group:
        t = Thread(target=lambda: fog.recvData(iot.createPacket()))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    fog.verifyToken(group)


def main():
    fog_nodes = 1
    devices_per_node = 10

    IoTs: List[List[IoT]] = []
    server = LocalServer()
    fogs: List[Fog] = [Fog() for _ in range(fog_nodes)]

    ################################# PUF-based Authentication #################################
    # Reset the table
    server.dropCRP()

    # Initialization phase
    # Create IoT groups and register CRP into the LocalServer
    print("Initializing...")
    print(f"    no. of groups: {fog_nodes}")
    print(f"    no. of devices per group: {devices_per_node}")
    start_time = timeit.default_timer()

    initialize_group(fog_nodes, devices_per_node, server, IoTs)

    print(f"Initialization successful within {timeit.default_timer() - start_time} s")

    for group in IoTs:
        leader = group[0]  # first member is Leader
        puf_based_authen(group, leader, server)
    ############################## End of PUF-based Authentication ##############################

    print("\n")

    ########################################### NIZKP ###########################################
    for group, fog in zip(IoTs, fogs):
        leader: Leader = group[0]

        print(
            f"\nStarting Group {leader.gid} Group Authentication (Leader-Fog) phase..."
        )
        start_time = timeit.default_timer()

        is_verified = authen_leader_fog(leader, fog)

        if is_verified:
            print(f"Verified within {timeit.default_timer() - start_time}")
        else:
            print("Not verified")

        ssk_salt = secrets.token_bytes(16)
        leader.deriveSSK(fog.PK, ssk_salt)
        fog.deriveSSK(leader.PK, ssk_salt)

        # print("Leader-Fog:")
        # print(f"    shared symmetric key: {leader.ssk}")
        # print(f"    shared symmetric key: {fog.ssk}")
    ####################################### End of NIZKP #######################################

    print("\n")

    ######################################## Our Scheme ########################################

    # Initialization
    # Before begin our scheme, Fog node needs to send
    # a secret and ciphered partial keys to associating groups
    for group, fog in zip(IoTs, fogs):
        leader = group[0]
        enc_packet = fog.sendSecToLeader(group)
        (secret, ciphered_keys) = leader.recvSecFromFog(enc_packet)
        leader.secret = secret
        leader.partialKey = ciphered_keys[0]
        # print(f"leader secret and pck: {leader.secret} |||| {leader.partialKey} |||| {len(leader.partialKey)}")

        for iot, pck in zip(group, ciphered_keys):
            if isinstance(iot, Leader):
                continue
            enc_pkt = leader.sendSecToIoT(iot.id, secret, pck)
            iot.recvSecFromLeader(leader.id, enc_pkt)
            # print(f"iot secret and pck: {iot.secret} |||| {iot.partialKey} |||| {len(iot.partialKey)}")

    # Data Authentication
    # Once the secret and partial ciphered keys are successfully distributed,
    # each IoT device can start sending the data to Fog node
    for group, fog in zip(IoTs, fogs):
        leader = group[0]
        print(f"\nStarting Group {leader.gid} Data Authentication (IoT-Fog) phase...")
        start_time = timeit.default_timer()

        authen_iot_fog(group, fog)

        print(
            f"All {devices_per_node} IoTs data authen success within {timeit.default_timer() - start_time}"
        )

    # Cloud Uploading
    for group, fog in zip(IoTs, fogs):
        gid = group[0].gid
        fog_id = gid
        upload_threads = []

        print(f"\nStarting Group {gid} Cloud uploading (Fog-Cloud) phase...")
        start_time = timeit.default_timer()

        t = Thread(
            target=fog.uploadToCloud, args=(len(fogs), devices_per_node, fog_id, gid)
        )
        upload_threads.append(t)
        t.start()

        for t in upload_threads:
            t.join()

        print(
            f"Fog {gid} cloud uploading success within {timeit.default_timer() - start_time}"
        )

    #################################### End of Our Scheme ####################################

    return 0


if __name__ == "__main__":
    main()
