# A Secure and Lightweight IIoT Data Authentication using PUF-based and ZKP in IoT Fog-Assisted Cloud Environment

The Industrial Internet of Things (IIoT) generates a vast amount of data through sensors and devices within industrial environments. This data is often sensitive and requires protection, which is challenging due to the distributed nature and limited resources of IIoT devices. While existing approaches primarily focus on encryption algorithms to secure data confidentiality, many industrial sectors also demand data authenticity to meet rigorous security requirements. Thus, ensuring the authenticity, integrity, and reliability of IIoT data is crucial. However, most current authentication mechanisms are unsuitable for large-scale IoT data sharing due to their lack of scalability and failure to address the revocation of devices. To address these challenges, we propose a secure and lightweight authentication scheme for IIoT data with secure devices revocation support. We utilize Non-Interactive Zero-Knowledge Proof (NIZKP) and Physical Unclonable Functions (PUF)-based authentication for authenticating multiple devices within a group and the fog nodes. This approach minimizes communication costs while ensuring robust authentication in large-scale IIoT systems. In addition, we introduce algorithms for device revocation and discovery of rogue IoT devices. Finally, we implemented and evaluated our scheme, demonstrating its performance and effectiveness while maintaining lightweight resource usage.

## Requirement

To run the experiment, install the required Python modules/libraries

```
pip install -r requirement.txt
```

## Experiment

To try our experiment, run [main.py](./main.py)

- set number of `fog_nodes` and `devices_per_node` in the `main` function to measure execution time in each phase including:

1. System Initialization
    1. IIoT Devices Authentication and Key Exchange (Leader - IIoT Devices) using PUF-based authentication
    2. Group Authentication and Secure Channel Establishment (Leader - Fog node) using NIZKP
2. Data Authentication and Data Integrity Verification
    1. Data authentication
    2. Cloud uploading

## Related courses

This project is contributed to CSS451 Cloud Computing and CSS454 Network Security courses at Sirindhorn International Institute of Technology (SIIT), Curriculum year 2021