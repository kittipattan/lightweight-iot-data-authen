import threading
import json
import time
import secrets
from ecdsa import SigningKey, NIST256p 
from azure.storage.blob import BlobServiceClient, BlobClient, ContainerClient
import random
import string
from dotenv import load_dotenv
import os
from utils.measurement import measure_computation_cost

class IoTECDSA():
    def __init__(self, gid, id, data):
        self.gid = gid
        self.id = id
        self.data = data
        self.sk = SigningKey.generate(curve=NIST256p)
        self.vk = self.sk.get_verifying_key()
        
    def signMessage(self):
        return self.sk.sign(self.data.encode())
    
    def createPacket(self):
        return (self.data, self.signMessage(), self.vk)

class FogECDSA():
    def __init__(self, id):
        self.id = id
        self.iotData = {}

    def verifyMessage(self, message, signature, vk):
        if (vk.verify(signature, message.encode())):
            try:
                self.iotData[self.id].append(message)
            except:
                self.iotData[self.id] = [message]
    
    def recvPacket(self, packet):
        (msg, sig, vk) = packet
        self.verifyMessage(msg, sig, vk)
    
    def uploadToCloud(self, fog_nodes, devices_per_node, fog_id, gid):
        aggregated_data = {
            "fog_node_id": fog_id,
            "aggregated_data": self.iotData[gid],
        }
        try:
            load_dotenv()
            
            connect_str = os.getenv("AZURE_API")  # to add connection
            blob_service_client = BlobServiceClient.from_connection_string(connect_str)
            container_name = "iiot-data-authentication-to-cloud"
            blob_name = f"ecdsa/fog_no_{fog_nodes}/device_no_{devices_per_node}/ecdsa_aggregated_data_{gid}.json"
            
            # convert aggregated data to JSON
            data = json.dumps(aggregated_data)
            # print(f"\n{data}\n")
            
            # upload data
            blob_client = blob_service_client.get_blob_client(container=container_name, blob=blob_name)
            blob_client.upload_blob(data, overwrite=True)
            print(f"Uploaded aggregated data of fog node {gid} to Azure Blob Storage.")

        
        except Exception as e:
            print(f"Error uploading data for fog node: {e}")

def setup_scheme(fog_nodes, devices_per_node):
    for g in range(fog_nodes):
        fogs.append(FogECDSA(g+1))
        group = []

        # Add IoT members
        for i in range(1, devices_per_node + 1):
            id = (g * devices_per_node) + i
            gid = g + 1
            data = f"sample data from IoT device {id} {''.join(random.choices(string.ascii_letters,k=73))}"
            # data = f"sample data from IoT device {id}"

            iot = IoTECDSA(gid, id, data)

            group.append(iot)

        iots.append(group)  
        
def sendDataToFog(iots, fogs):
    for group, fog in zip(iots, fogs):
        for iot in group:
            fog.recvPacket(iot.createPacket())
        #     threads = []
        #     t = threading.Thread(target=lambda : fog.recvPacket(iot.createPacket()))
        #     threads.append(t)
        #     t.start()
    
        # for t in threads:
        #     t.join()

# Public data
curve = NIST256p
G = curve.generator
n = curve.order

fogs: FogECDSA = []
iots: IoTECDSA = []

# main function
def main():
    
    # measure IoT
    time_taken = []
    for d in [900]:

        # IoT Data
        fog_nodes = 1
        devices_per_node = d

        setup_scheme(fog_nodes, devices_per_node)
            
        # measure_computation_cost(sendDataToFog, "Data Authentication", 100, iots, fogs)
        start_time = time.time()
        sendDataToFog(iots, fogs)
        print(f"Data Authentication time taken: {(time.time() - start_time)*1000} ms")
        
        start_time = time.time()
        
        for group, fog in zip(iots, fogs):
            gid = fog.id
            fog.uploadToCloud(len(fogs), devices_per_node, fog.id, gid)
            
            end_time = time.time()

        print(f"Fog cloud uploading success within {end_time - start_time} s")
        time_taken.append((f"{d} devices", end_time - start_time))

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

