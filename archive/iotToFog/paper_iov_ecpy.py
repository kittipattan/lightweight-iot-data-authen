import random
import time
import timeit
import hashlib
from random import randint
from pairing_ecpy import EllipticCurve, hash_function, point_to_hash
from ecpy.curves import Curve

# Parameters (using the secp256k1 curve as an example)
curve = Curve.get_curve('secp256k1')
EC = EllipticCurve(curve)

q = curve.order
P = curve.generator

priK = random.randint(1000, 9999)
pubK = EC.point_multiplication(P, priK)

class Vehicle:
  def __init__(self, v_id):
    self.id = v_id
    self.r = random.randint(1000, 9999)
    self.r_prime = random.randint(1000, 9999)

class RSU:
  def __init__(self, rsu_id):
    self.id = rsu_id
    self.a = random.randint(1000, 9999)
    self.alpha = random.randint(1000, 9999)
    self.b = random.randint(1000, 9999)
    self.R_1 = EC.point_multiplication(P, self.alpha)
    self.R_2 = EC.point_multiplication(P, self.a * self.alpha)
    self.phi = EC.point_multiplication(P, self.alpha * self.b)

def register(v: Vehicle, rsu: RSU):
  R_v = EC.point_multiplication(P, v.r) 
  R_v_prime = EC.point_multiplication(R_v, v.r_prime)
  R_b = EC.point_multiplication(rsu.R_1, v.r)

  delta = EC.point_multiplication(rsu.phi, v.r)

  S = EC.point_multiplication(R_v_prime, rsu.alpha)
  S_1 = EC.point_multiplication(R_v_prime, rsu.alpha // rsu.a) 
  cert = EC.point_multiplication(EC.hash_to_point(f"{S}{v.id}"), rsu.a)
  ld = EC.point_multiplication(delta, (rsu.a // (rsu.alpha)**2))

  return (cert, ld)

def signing(v: Vehicle, rsu: RSU, message, cert, ld):
    S_prime = EC.point_multiplication(EC.point_multiplication(P, rsu.alpha), v.r * v.r_prime)

    K_1_point = EC.point_multiplication(cert, v.r * v.r_prime)
    K_1 = point_to_hash(cert) * v.r * v.r_prime
    Q_point = EC.hash_to_point(f"{S_prime}{v.id}")
    Q = hash_function(f"{S_prime}{v.id}")

    K_1_prime_point = EC.point_multiplication(Q_point, v.r * v.r_prime)
    K_1_prime = Q * v.r * v.r_prime
    ld_prime = EC.point_multiplication(ld, EC.mod_inverse(v.r))

    pid = (K_1, K_1_prime)

    K_1_inverse = EC.mod_inverse(K_1)
    hash_message = hash_function(message)
    sigma = EC.add_points(K_1_point, EC.point_multiplication(ld_prime, hash_message * K_1_inverse))
    # sigma = K_1 + (int.from_bytes(hash_function(message))*ld_prime) / K_1

    timestamp = time.time()
    
    # sign = (pid, sigma, K_1_prime, message, time.time())
    sign = (pid, sigma, K_1_prime_point, K_1_prime, message, timestamp)

    return sign

def batch_authentication(rsu: RSU, signs):
    total_sigma = None
    total_K_1_prime = None
    total_hash_message = None

    for sign in signs:
        (_, sigma, K_1_prime_point, K_1_prime, message, _) = sign
        if total_sigma is None:
          total_sigma = sigma
        else:
          total_sigma += sigma

        if total_K_1_prime is None:
          total_K_1_prime = K_1_prime_point
        else:
          total_K_1_prime += K_1_prime_point

        hash_message = EC.point_multiplication(EC.hash_to_point(message), EC.mod_inverse(K_1_prime))
        if total_hash_message is None:
          total_hash_message = hash_message
        else:
          total_hash_message += hash_message

    left = EC.bilinear_pairing(total_sigma, rsu.R_1)
    right = EC.bilinear_pairing(total_K_1_prime, rsu.R_2)
    right *= EC.bilinear_pairing(total_hash_message, pubK)

    return left == right

def main():
    
    v = Vehicle(1)
    rsu = RSU(1)

    cert, ld = register(v, rsu)

    r = 1
    n_vehicle = 10
    total_time_vehicle = 0
    total_time_rsu = 0

    for _ in range(r):
      message = "Hello, RSU!"

      start_time = timeit.default_timer()
      sign = signing(v, rsu, message, cert, ld)
      total_time_vehicle += timeit.default_timer() - start_time

      start_time = timeit.default_timer()
      batch_authentication(rsu, [sign for _ in range(n_vehicle)])
      total_time_rsu += timeit.default_timer() - start_time

    print(f"total time vehicle {((total_time_vehicle/r)*1000):.5f} ms, {r} rounds")
    print(f"total time rsu {((total_time_rsu/r)*1000):.5f} ms, {r} rounds")

# Run the main function
if __name__ == "__main__":
    main()
