import threading
import json
import time
import secrets
import iot
import utils.utils as utils
from utils.aes256 import AESCipher
from base64 import b64encode, b64decode
from ecpy.keys   import ECPublicKey, ECPrivateKey
from ecpy.curves import Curve
from ecpy.ecdsa  import ECDSA
from azure.storage.blob import BlobServiceClient, BlobClient, ContainerClient

# IoT Data
gid = []    # m groups, same as fog_node_id
id = []     # n devices
data = []

partial_ciphered_key_leader = []    # store partial secret from fog nodes to Leader
partial_ciphered_key_iot = []       # store partial secret for each devices from Leader
partial_ciphered_key_fog = []       # store partial secret for fog nodes to verify their devices
s = []                              # n secrets for m groups, sent to IoT devices
ciphered_s = []                     # n secrets for m groups, stored in database

not_verified_device = []

sk_puf = []                         # assume this is from PUF key exchange
secret_cipher_puf = []              # key to encrypt secret and exchange between Leader and IoT devices
ciphered_s_puf = []

def reset_scheme():
    global gid
    global id
    global data
    global partial_ciphered_key_leader
    global partial_ciphered_key_iot
    global partial_ciphered_key_fog
    global s
    global ciphered_s
    global ciphered_s_puf
    global sk_puf
    global secret_cipher_puf
    global not_verified_device

    gid = [] 
    id = []  
    data = []

    partial_ciphered_key_leader = [] 
    partial_ciphered_key_iot = []
    partial_ciphered_key_fog = [] 
    s = [] 
    ciphered_s = [] 
    ciphered_s_puf = []
    not_verified_device = []

    sk_puf = []                 
    secret_cipher_puf = []      

def setup_our_scheme(fog_nodes, devices_per_node):

    # reset previous settings
    reset_scheme()

    # IoT Data
    for i in range(fog_nodes):
        gid.append(i+1) 
    
    for group_index in range(len(gid)):
        id.append([(group_index*devices_per_node)+i for i in range(1, devices_per_node+1)])
    
    for i in id:   
        data.append([f"sample data from IoT device {i[j]}" for j in range(devices_per_node)])
  
    for _ in gid:
        partial_ciphered_key_iot.append([])

    for i in range(len(gid)):
        
        # generated Secret by Fog
        s.append(str(secrets.randbits(128)))  # to send to IoT devices

        # Fog node AES key
        fog_key = secrets.token_bytes(32)

        # Encrypted secret
        secret_cipher = AESCipher(fog_key)    # key to encrypt secret
        ciphered_s.append(secret_cipher.encrypt(s[i])) # store in database

        # Encrypted secret for PUF-based authentication and key exchange
        sk_puf.append(secrets.token_bytes(32))
        secret_cipher_puf.append(AESCipher(sk_puf[i]))
        ciphered_s_puf.append(secret_cipher_puf[i].encrypt(s[i]))  # sent to each device in the group

        # Encrypted AES key
        hashed_gid = utils.hash_sha256(str(gid[i])) # encrypt key with hash value of GID
        key_cipher = AESCipher(hashed_gid)
        encoded_fog_key = b64encode(fog_key).decode("utf-8")
        ciphered_fog_key = key_cipher.encrypt(encoded_fog_key) # -> to partition

        # partition AES_cipher
        index_to_split = round(len(ciphered_fog_key)*0.8)
        partial_ciphered_key_leader.append(ciphered_fog_key[:index_to_split]) # send to leader
        
        for device_id in range(len(id)):
            first = round((device_id*len(ciphered_fog_key))/len(id))       
            last = round(((device_id+1)*len(ciphered_fog_key))/len(id))
            partial_ciphered_key_iot[i].append(partial_ciphered_key_leader[i][first:last]) 

        partial_ciphered_key_fog.append(ciphered_fog_key[index_to_split:])    # store in database

# simulate IoT device data and IoT token
def simulate_iot_data(device_index, group_index):
    # print(f"ciphered secret PUF;  iot {id[group_index][device_index]}, group {gid[group_index]}: {ciphered_s_puf[group_index]}")
    secret_puf = secret_cipher_puf[group_index].decrypt(ciphered_s_puf[group_index])
    # print(f"secret PUF;           iot {id[group_index][device_index]}, group {gid[group_index]}: {secret_puf}")
    # print(f"sk_puf group {gid[group_index]}: {sk_puf[group_index]}")
    
    return iot.generate_token(str(gid[group_index]), str(id[group_index][device_index]), secret_puf, data[group_index][device_index]), data[group_index][device_index]

# function to verify an IoT device
def verify_iot_device(token, group_index, device_index, barrier):
  try:
      # wait until every thread has reached  
      barrier.wait()

      ciphered_fog_key = ""
      for c in partial_ciphered_key_iot[group_index]:
          ciphered_fog_key += c
      ciphered_fog_key += partial_ciphered_key_fog[group_index]

      # Encrypted AES key
      hashed_gid = utils.hash_sha256(str(gid[group_index])) # encrypt key with hash value of GID
      key_cipher = AESCipher(hashed_gid)
      encoded_fog_key = key_cipher.decrypt(ciphered_fog_key) # to decrypt the ciphered secret
      fog_key = b64decode(encoded_fog_key.encode("utf-8"))

      secret_cipher = AESCipher(fog_key)
      s = secret_cipher.decrypt(ciphered_s[group_index])

      concat_data = str(gid[group_index]) + str(id[group_index][device_index]) + s + data[group_index][device_index]

      if (token == utils.hash_sha256(concat_data)):
          return True
      
      return False

  except Exception as e:
      # print(f"verify_iot_device: {e}")
      return False

# function to send data to fog node
def send_data_to_fog_node(group_index, device_index, device_token, device_data, fog_data_store, barrier):
    # verify IoT devices
    # check if the device is verified
    if verify_iot_device(device_token, group_index, device_index, barrier): # not passed?
      fog_data_store[group_index].append(device_data)
      # print(f"Device data sent to fog node {gid[group_index]}: {device_data}")
      return

    not_verified_device.append(f"device {id[group_index][device_index]} from group {gid[group_index]}")

# function to aggregate data at a fog node
def aggregate_data(group_index, fog_data_store):
    aggregated_data = {"fog_node_id": gid[group_index], "aggregated_data": fog_data_store[group_index]}
    # print(f"Aggregated data at fog node {gid[group_index]}: {aggregated_data}")
    return aggregated_data

# function to upload data to Azure Blob Storage
def upload_to_azure(fog_node_index, aggregated_data, fog_nodes, devices_per_node):
    try:
        # initialize a connection to Azure Blob Storage
        connect_str = ""    # to add connection
        blob_service_client = BlobServiceClient.from_connection_string(connect_str)
        container_name = "iiot-data-authentication-to-cloud"
        blob_name = f"our_scheme/fog_no_{fog_nodes}/device_no_{devices_per_node}/aggregated_data_{gid[fog_node_index]}.json"
        
        # convert aggregated data to JSON
        data = json.dumps(aggregated_data)
        
        # upload data
        blob_client = blob_service_client.get_blob_client(container=container_name, blob=blob_name)
        blob_client.upload_blob(data, overwrite=True)
        # print(f"Uploaded aggregated data of fog node {gid[fog_node_index]} to Azure Blob Storage.")
    
    except Exception as e:
        # print(f"Error uploading data for fog node {gid[fog_node_index]}: {e}")
        pass

# main function
def main():

    # measure iot
    time_taken_iot_increase = []
    for d in [40, 100, 500, 900]:
        
        # IoT Data
        fog_nodes = 1
        devices_per_node = d

        setup_our_scheme(fog_nodes, devices_per_node)

        start_time = time.time()
        fog_data_store = {i: [] for i in range(fog_nodes)}

        # initialize barriers for each group/fog node to wait until every IoT device has reached
        barriers = {i: threading.Barrier(devices_per_node) for i in range(fog_nodes)}

        threads = []

        # step 1_OUR: simulate IoT devices sending data to fog nodes
        for fog_node_index in range(fog_nodes):
            for device_index in range(devices_per_node):
                device_token, device_data = simulate_iot_data(device_index, fog_node_index)
                t = threading.Thread(target=send_data_to_fog_node, args=(fog_node_index, device_index, device_token, device_data, fog_data_store, barriers[fog_node_index]))
                threads.append(t)
                t.start()
        
        for t in threads:
            t.join()
        
        # step 2: aggregate data at fog nodes
        aggregated_data_store = {}
        for group_index in range(fog_nodes):
            aggregated_data_store[group_index] = aggregate_data(group_index, fog_data_store)

        # step 3: upload aggregated data to Azure Blob Storage
        upload_threads = []
        for group_index in range(fog_nodes):
            aggregated_data = aggregated_data_store[group_index]
            t = threading.Thread(target=upload_to_azure, args=(group_index, aggregated_data, fog_nodes, devices_per_node))
            upload_threads.append(t)
            t.start()

        for t in upload_threads:
            t.join()

        end_time = time.time()
        elapsed_time = end_time - start_time  # calculate elapsed time

        time_taken_iot_increase.append((f"{d} devices", elapsed_time))

    print(f"Our scheme: {time_taken_iot_increase}")

    # measure fog
    time_taken_fog_increase = []
    for f in [5, 15, 50]:

        # IoT Data
        fog_nodes = f
        devices_per_node = 50

        setup_our_scheme(fog_nodes, devices_per_node)

        start_time = time.time()
        fog_data_store = {i: [] for i in range(fog_nodes)}

        # initialize barriers for each group/fog node to wait until every IoT device has reached
        barriers = {i: threading.Barrier(devices_per_node) for i in range(fog_nodes)}

        threads = []

        # step 1_OUR: simulate IoT devices sending data to fog nodes
        for fog_node_index in range(fog_nodes):
            for device_index in range(devices_per_node):
                device_token, device_data = simulate_iot_data(device_index, fog_node_index)
                t = threading.Thread(target=send_data_to_fog_node, args=(fog_node_index, device_index, device_token, device_data, fog_data_store, barriers[fog_node_index]))
                threads.append(t)
                t.start()
        
        for t in threads:
            t.join()

        # step 2: aggregate data at fog nodes
        aggregated_data_store = {}
        for group_index in range(fog_nodes):
            aggregated_data_store[group_index] = aggregate_data(group_index, fog_data_store)

        # step 3: upload aggregated data to Azure Blob Storage
        upload_threads = []
        for group_index in range(fog_nodes):
            aggregated_data = aggregated_data_store[group_index]
            t = threading.Thread(target=upload_to_azure, args=(group_index, aggregated_data, fog_nodes, devices_per_node))
            upload_threads.append(t)
            t.start()

        for t in upload_threads:
            t.join()

        end_time = time.time()
        elapsed_time = end_time - start_time  # calculate elapsed time

        time_taken_fog_increase.append((f"{f} fog no", elapsed_time))
    
    print(f"Our scheme: {time_taken_fog_increase}")

    # start_time = time.time()

    # fog_data_store = {i: [] for i in range(fog_nodes)}

    # barriers = {i: threading.Barrier(devices_per_node) for i in range(fog_nodes)}
    # threads = []

    # Step 1_OUR: Simulate IoT devices sending data to fog nodes
    # for fog_node_index in range(fog_nodes):
    #     for device_index in range(devices_per_node):
    #         device_token, device_data = simulate_iot_data(device_index, fog_node_index)
    #         t = threading.Thread(target=send_data_to_fog_node, args=(fog_node_index, device_index, device_token, device_data, fog_data_store, barriers[fog_node_index]))
    #         threads.append(t)
    #         t.start()

    # Step 1.1: Test if secret is not correct
    # for fog_node_id in range(fog_nodes):
    #     for device_id in range(devices_per_node):
    #           device_token, device_data = simulate_iot_data(device_id, fog_node_id)
    #           if (device_id == 4):
    #               device_token = iot.generate_token(str(gid[fog_node_id]), str(id[device_id]), s[fog_node_id-1], data[device_id])
    #           t = threading.Thread(target=send_data_to_fog_node, args=(fog_node_id, device_id, device_token, device_data, fog_data_store))
    #           threads.append(t)
    #           t.start()

    # Step 1.2: Test if partial ciphered key is not correct
    # for fog_node_index in range(fog_nodes):
    #     for device_index in range(devices_per_node):
    #         if(id[fog_node_index][device_index] == 1 and gid[fog_node_index] == 1):
    #           partial_ciphered_key_iot[fog_node_index][device_index] = 'GQPuM11PangkCj1KykpjGPbBOhJovHz'
    #         device_token, device_data = simulate_iot_data(device_index, fog_node_index)
    #         t = threading.Thread(target=send_data_to_fog_node, args=(fog_node_index, device_index, device_token, device_data, fog_data_store, barriers[fog_node_index]))
    #         threads.append(t)
    #         t.start()
    
    # for t in threads:
    #     t.join()

    # # Step 2: Aggregate data at fog nodes
    # aggregated_data_store = {}
    # for group_index in range(fog_nodes):
    #     aggregated_data_store[group_index] = aggregate_data(group_index, fog_data_store)

    # # Step 3: Upload aggregated data to Azure Blob Storage
    # upload_threads = []
    # for group_index in range(fog_nodes):
    #     aggregated_data = aggregated_data_store[group_index]
    #     t = threading.Thread(target=upload_to_azure, args=(group_index, aggregated_data))
    #     upload_threads.append(t)
    #     t.start()

    # for t in upload_threads:
    #     t.join()

    # end_time = time.time() 
    # elapsed_time = end_time - start_time  # Calculate elapsed time

    # if (not_verified_device):
    #     print(f"Not verified devices: ")
    #     for d in not_verified_device:
    #         print(d)

    # print(f"Our scheme: {len(gid)} groups {devices_per_node} devices each")
    # print(f"Total time taken: {elapsed_time} seconds")
    # print(f"Topic: normal operation")
    # print(f"Total unverified devices: {len(not_verified_device)} devices")

if __name__ == "__main__":
    main()

