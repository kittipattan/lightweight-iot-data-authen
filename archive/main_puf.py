from puf.iot import IoT, GroupIoT
from puf.server import LocalServer
from puf.leader import Leader, GroupLeader
from puf.fog import Fog
import timeit
from typing import List, Type
import random
import string
from pypuf.io import random_inputs
import secrets
from utils.measurement import measure_computation_cost

# backup
# Peer-to-Peer method
def enroll_group(leader: LeaderPi, iot: IoTPi, server: LocalServer):
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

def mutual_authen_group(leader: LeaderPi, iot: IoTPi):
    leader_req = leader.reqMutAuth(iot.id)
    iot_PROOF = iot.resMutAuth(leader_req)

    if not (leader.verifyMutAuthProof(iot_PROOF)):
        raise Exception("MutAuth failed: Leader failed to verify IoT device")

    # Leader authen IoT device successfully
    # swap role
    leader_PROOF = leader.resMutAuth()

    if not (iot.verifyMutAuthProof(leader_PROOF)):
        raise Exception("MutAuth failed: IoT failed to verify Leader device")

def puf_based_authen(group: List[IoTPi], leader: LeaderPi, server: LocalServer):
    # Enrollment phase
    # print(f"\nStarting Group {leader.gid} Enrollment phase...")
    start_time = timeit.default_timer()

    for iot in group:
        # LocalServer send Request to Leader and pairing IoT
        if isinstance(iot, Leader):
            continue

        enroll_group(leader, iot, server)

    # print(
    #     f"Group {leader.gid} Enrollment successful within {timeit.default_timer() - start_time} s"
    # )

    # Mutual Authentication and Key Exchange phase
    # print(f"\nStarting Group {leader.gid} Mutual Authentication phase...")
    # start_time = timeit.default_timer()

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

    # print(
    #     f"Group {leader.gid} MutAuth and KeyEx successful within {timeit.default_timer() - start_time} s"
    # )


def initialize_group(
    fog_nodes: int,
    devices_per_node: int,
    server: LocalServer,
    IoTs: List[List[IoT]],
    iot_constructor: Type[IoT | GroupIoT],
    leader_constructor,
):
    for g in range(fog_nodes):
        # Add Leader
        group: List[iot_constructor] = []

        # Add IoT members
        for i in range(1, devices_per_node + 1):
            id = (g * devices_per_node) + i
            gid = g + 1
            data = f"sample data from IoT device {id} {''.join(random.choices(string.ascii_letters,k=73))}"
            # data = f"sample data from IoT device {id}"

            iot = iot_constructor(id, gid, id, data)
            if i == 1:
                iot = leader_constructor(id, gid, id, data)

            challenge = random_inputs(64, 256, id)
            challenge = (1 - challenge) // 2
            response = iot.genResponse(challenge)
            server.registerCRP(id, gid, challenge, response)

            group.append(iot)

        IoTs.append(group)


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


# Peer-to-Peer method
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
    # print(f"\nStarting Group {leader.gid} Enrollment phase...")
    start_time = timeit.default_timer()

    for iot in group:
        # LocalServer send Request to Leader and pairing IoT
        if isinstance(iot, Leader):
            continue

        enroll_group(leader, iot, server)

    # print(
    #     f"Group {leader.gid} Enrollment successful within {timeit.default_timer() - start_time} s"
    # )

    # Mutual Authentication and Key Exchange phase
    # print(f"\nStarting Group {leader.gid} Mutual Authentication phase...")
    # start_time = timeit.default_timer()
    
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

    # print(
    #     f"Group {leader.gid} MutAuth and KeyEx successful within {timeit.default_timer() - start_time} s"
    # )


def main(n: int):
    fog_nodes = 1
    devices_per_node = n

    #################################### P2P initialization ####################################

    P2PIoTs: List[List[IoT]] = []
    server = LocalServer()
    fogs: List[Fog] = [Fog() for _ in range(fog_nodes)]

    # Reset the table
    server.dropCRP()

    # Initialization phase
    # Create IoT groups and register CRP into the LocalServer
    print("Initializing...")
    print(f"    no. of groups: {fog_nodes}")
    print(f"    no. of devices per group: {devices_per_node}")
            
    initialize_group(fog_nodes, devices_per_node, server, P2PIoTs, IoT, Leader)

    # print(f"Initialization successful")

    for group in P2PIoTs:
        leader = group[0]  # first member is Leader
        puf_based_authen(group, leader, server)

    ################################### GROUP initialization ####################################
    print()

    GroupIoTs: List[List[GroupIoT]] = []
    server = LocalServer()
    fogs: List[Fog] = [Fog() for _ in range(fog_nodes)]

    # Reset the table
    server.dropCRP()

    # Initialization phase
    # Create IoT groups and register CRP into the LocalServer
    # print("Initializing...")
    # print(f"    no. of groups: {fog_nodes}")
    # print(f"    no. of devices per group: {devices_per_node}")

    initialize_group(
        fog_nodes, devices_per_node, server, GroupIoTs, GroupIoT, GroupLeader
    )

    # print(f"Initialization successful")
    
    for group in GroupIoTs:
        leader = group[0]  # first member is Leader
        puf_based_authen(group, leader, server)

    # Send packet to each IoT
    for group in GroupIoTs:
        leader: GroupLeader = group[0]
        # print(f"\nStarting Group {leader.gid} sending group key...")

        for iot in group:
            if isinstance(iot, GroupLeader):
                iot.genGroupKey()
                continue
            pkt = leader.sendGroupKey(iot.id)
            iot.recvGroupKey(pkt)
            # print(f"    Group Key: {iot.gk}")

        # print(f"Group {leader.gid} sending group key successful")

    ######################################## COMPARISON #########################################

    # Sending secret time comparison
    for method, iots in (("P2P", P2PIoTs), ("Group", GroupIoTs)):
        print(
            f"################################### {method} ####################################"
        )

        for group, fog in zip(iots, fogs):
            leader: Leader = group[0]

            # print(
            #     f"\nStarting Group {leader.gid} Group Authentication (Leader-Fog) phase..."
            # )

            is_verified = authen_leader_fog(leader, fog)

            # if is_verified:
            #     print(f"Verified")
            # else:
            #     print("Not verified")

            ssk_salt = secrets.token_bytes(16)
            leader.deriveSSK(fog.PK, ssk_salt)
            fog.deriveSSK(leader.PK, ssk_salt)

        for group, fog in zip(iots, fogs):
            leader: Leader = group[0]
            enc_packet = fog.sendSecToLeader(group)
            (secret, ciphered_keys) = leader.recvSecFromFog(enc_packet)
            # print(f"leader secret and pck: {leader.secret} |||| {leader.partialKey} |||| {len(leader.partialKey)}")

            # print(f"{method}: Starting Group {leader.gid} sending secret...")

            def sec_iot_leader():
                for iot, pck in zip(group, ciphered_keys):
                    if isinstance(iot, Leader):
                        continue
                    pkt = leader.sendSecToIoT(iot.id, secret, pck)
                    iot.recvSecFromLeader(leader.id, pkt)

            measure_computation_cost(sec_iot_leader, "Sending secret", 100)

            # print(f"{method}: Sending secret successful")

    print(
        f"##############################################################################"
    )


if __name__ == "__main__":
    for n in [2, 10, 100, 200, 400]:
        main(n)
