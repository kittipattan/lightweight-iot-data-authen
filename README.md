# A Secure and Lightweight IIoT Data Authentication using Fog-Assisted Cloud

Industrial Internet of Things (IIoT) generates a vast amount of data through sensors and devices within the industrial environments every day. In many cases, this data is sensitive and needs protection, but it is challenging due to the distribution and limited resources of IIoT devices. Existing works typically focus on designing encryption algorithms to protect the confidentiality of the data. However, many industrial sectors also require the data to be completely authentic due to the business requirements. Ensuring the authenticity, integrity and reliability of the IIoT data is therefore necessary. For this reason, we proposed a secure and lightweight authentication scheme for IIoT data using fog-assisted cloud. This proposed scheme adopts the ideas of group authentication, Non Interactive Zero-Knowledge Proof (NIZKP), and Physical Unclonable Function (PUF) in the authentication process between fog nodes, leader IIoT devices, and member IIoT devices. In the end, we demonstrated the implementation and conducted the experiments to evaluate the performance and effectiveness of our proposed scheme while maintaining lightweight resource usage.

## Requirement

We have used Python to implement the experiment of our proposed scheme, and the Python modules below are required to be installed

- ecpy
- secrets
- threading
- azure.storage.blob
- aes256
- base64
- psutil
- hashlib

## Experiment

If you want to try our experiment, you have to run these ```.py``` files

- [To measure execution time of single IoT device for each scheme](./single_iot.py)

- To measure execution time between IIoT devices and CSP for data authentication and transmission according to the number of fog nodes
    - [Our scheme](./cloud.py)
    - [Traditional scheme](./cloud_ecdsa.py)

#### Remark

This project is contributed to CSS451 Cloud Computing and CSS454 Network Security courses at Sirindhorn International Institute of Technology (SIIT), Curriculum year 2021