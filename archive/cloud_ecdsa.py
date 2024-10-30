import threading
import json
import time
import secrets
from ecpy.keys   import ECPublicKey, ECPrivateKey
from ecpy.curves import Curve
from ecpy.ecdsa  import ECDSA
from azure.storage.blob import BlobServiceClient, BlobClient, ContainerClient

# Public data
curve_name = "Curve25519"
curve = Curve.get_curve(curve_name) # known to Fog already
G = curve.generator
n = curve.order

# IoT Data
gid = []   # 3 groups, same as fog_node_id
id = []  # 5 devices
data = []

# IoT ECDSA
cv = Curve.get_curve(curve_name)
pu_keys = []
pv_keys = []
signer = ECDSA()

# collect unverified devices
not_verified_device = []

def reset_scheme():
    global gid
    global id
    global data
    global pu_keys
    global pv_keys
    global not_verified_device

    gid = [] 
    id = []  
    data = []
    pu_keys = []
    pv_keys = []

    not_verified_device = []

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

    for _ in id:
        pv_keys.append([ECPrivateKey(secrets.randbits(256), cv) for _ in range(devices_per_node)])
    
    for pv_key in pv_keys:
        pu_keys.append([pv_key[device_index].get_public_key() for device_index in range(devices_per_node)])     

# simulate IoT device data and IoT token
def simulate_iot_data(fog_node_index, device_index):
    pv_key = pv_keys[fog_node_index][device_index]
    pu_key = pu_keys[fog_node_index][device_index]
    sig = signer.sign(str.encode(data[fog_node_index][device_index]), pv_key)

    return sig, pu_key, data[fog_node_index][device_index]

def verify_iot_device(sig, pu_key, device_index, fog_node_index):
    return signer.verify(str.encode(data[fog_node_index][device_index]), sig, pu_key)

# function to send data to fog node
def send_data_to_fog_node(fog_node_index, device_index, sig, pu_key, device_data, fog_data_store):
    # verify IoT devices
    # check if the device is verified
    if verify_iot_device(sig, pu_key, device_index, fog_node_index):
      fog_data_store[fog_node_index].append(device_data)
      # print(f"Device data sent to fog node {gid[fog_node_index]}: {device_data}")
      return

    not_verified_device.append(f"device {id[fog_node_index][device_index]} from group {gid[fog_node_index]}")

# function to aggregate data at a fog node
def aggregate_data(fog_node_index, fog_data_store):
    aggregated_data = {"fog_node_id": gid[fog_node_index], "aggregated_data": fog_data_store[fog_node_index]}
    # print(f"Aggregated data at fog node {gid[fog_node_index]}: {aggregated_data}")
    return aggregated_data

# function to upload data to Azure Blob Storage
def upload_to_azure(fog_node_index, aggregated_data, fog_nodes, devices_per_node):
    try:
        # initialize a connection to Azure Blob Storage
        # connect_str = ""    # to add connection
        # blob_service_client = BlobServiceClient.from_connection_string(connect_str)
        # container_name = "iiot-data-authentication-to-cloud"
        # blob_name = f"ecdsa/fog_no_{fog_nodes}/device_no_{devices_per_node}/ecdsa_aggregated_data_{gid[fog_node_index]}.json"
        
        # # convert aggregated data to JSON
        # data = json.dumps(aggregated_data)
        
        # # upload data
        # blob_client = blob_service_client.get_blob_client(container=container_name, blob=blob_name)
        # blob_client.upload_blob(data, overwrite=True)
        # # print(f"Uploaded aggregated data of fog node {gid[fog_node_index]} to Azure Blob Storage.")
        pass
    
    except Exception as e:
        # print(f"Error uploading data for fog node {gid[fog_node_index]}: {e}")
        pass

# main function
def main():
    
    # measure IoT
    time_taken = []
    for d in [40, 100, 500, 900]:

        # IoT Data
        fog_nodes = 1
        devices_per_node = d

        setup_our_scheme(fog_nodes, devices_per_node)
        
        start_time = time.time()
        fog_data_store = {i: [] for i in range(fog_nodes)}

        threads = []

        # step 1_ECDSA: simulate IoT devices sending data to fog nodes
        for fog_node_index in range(fog_nodes):
            for device_index in range(d):
                sig, pu_key, device_data = simulate_iot_data(fog_node_index, device_index)
                t = threading.Thread(target=send_data_to_fog_node, args=(fog_node_index, device_index, sig, pu_key, device_data, fog_data_store))
                threads.append(t)
                t.start()
        
        for t in threads:
            t.join()

        # step 2: aggregate data at fog nodes
        aggregated_data_store = {}
        for fog_node_index in range(fog_nodes):
            aggregated_data_store[fog_node_index] = aggregate_data(fog_node_index, fog_data_store)

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
        elapsed_time = end_time - start_time  # Calculate elapsed time

        time_taken.append((f"{d} devices", elapsed_time))

    print(f"Traditional scheme: {time_taken}")

    # measure fog
    # time_taken_fog_increase = []
    # for f in [5, 15, 50]:
        
    #     # IoT Data
    #     fog_nodes = f
    #     devices_per_node = 50

    #     setup_our_scheme(fog_nodes, devices_per_node)

    #     start_time = time.time()
    #     fog_data_store = {i: [] for i in range(fog_nodes)}

    #     threads = []

    #     # step 1_OUR: simulate IoT devices sending data to fog nodes
    #     for fog_node_index in range(fog_nodes):
    #         for device_index in range(devices_per_node):
    #             sig, pu_key, device_data = simulate_iot_data(fog_node_index, device_index)
    #             t = threading.Thread(target=send_data_to_fog_node, args=(fog_node_index, device_index, sig, pu_key, device_data, fog_data_store))
    #             threads.append(t)
    #             t.start()

    #     for t in threads:
    #         t.join()

    #     # step 2: aggregate data at fog nodes
    #     aggregated_data_store = {}
    #     for group_index in range(fog_nodes):
    #         aggregated_data_store[group_index] = aggregate_data(group_index, fog_data_store)
        
    #     # step 3: upload aggregated data to Azure Blob Storage
    #     upload_threads = []
    #     for group_index in range(fog_nodes):
    #         aggregated_data = aggregated_data_store[group_index]
    #         t = threading.Thread(target=upload_to_azure, args=(group_index, aggregated_data, devices_per_node, fog_nodes))
    #         upload_threads.append(t)
    #         t.start()

    #     for t in upload_threads:
    #         t.join()

    #     end_time = time.time()
    #     elapsed_time = end_time - start_time  # calculate elapsed time

    #     time_taken_fog_increase.append((f"{f} fog no", elapsed_time))
    
    # print(f"Traditional scheme: {time_taken_fog_increase}")

    # start_time = time.time()
    
    # fog_data_store = {i: [] for i in range(fog_nodes)}

    # threads = []

    # # Step 1_ECDSA: Simulate IoT devices sending data to fog nodes
    # for fog_node_index in range(fog_nodes):
    #     for device_index in range(devices_per_node):
    #         sig, pu_key, device_data = simulate_iot_data(fog_node_index, device_index)
    #         t = threading.Thread(target=send_data_to_fog_node, args=(fog_node_index, device_index, sig, pu_key, device_data, fog_data_store))
    #         threads.append(t)
    #         t.start()
    
    # for t in threads:
    #     t.join()

    # # Step 2: Aggregate data at fog nodes
    # aggregated_data_store = {}
    # for fog_node_index in range(fog_nodes):
    #     aggregated_data_store[fog_node_index] = aggregate_data(fog_node_index, fog_data_store)

    # Step 3: Upload aggregated data to Azure Blob Storage
    # upload_threads = []
    # for fog_node_index in range(fog_nodes):
    #     aggregated_data = aggregated_data_store[fog_node_index]
    #     t = threading.Thread(target=upload_to_azure, args=(fog_node_index, aggregated_data))
    #     upload_threads.append(t)
    #     t.start()

    # for t in upload_threads:
    #     t.join()

    # end_time = time.time()  # Record end time
    # elapsed_time = end_time - start_time  # Calculate elapsed time

    # if (not_verified_device):
    #     print(f"Not verified devices: ")
    #     for d in not_verified_device:
    #         print(d)

    # print(f"Total time taken: {elapsed_time} seconds")

if __name__ == "__main__":
    main()

