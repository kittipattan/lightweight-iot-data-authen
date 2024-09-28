from sage.all import *
import hashlib
import time

def random_int():
   return randint(Integer(1000), Integer(9999))

p = Integer(199933)
curve = EllipticCurve(GF(p), [Integer(0), Integer(7)])

P = curve.random_point()
order = curve.order()

priK = random_int()
pubK = priK * P

def hash(bytes):
  hash_object = hashlib.sha256()
  hash_object.update(bytes)
  digest = int(hash_object.hexdigest(), 16)

  return digest

def H1(message):
  hash_int = hash(message)
  scalar = hash_int % order
  return scalar * P

def H2(point):
  return hash(bytes("mock", "utf-8"))

class Vehicle:
  def __init__(self, v_id):
    self.id = v_id;
    self.r = random_int()
    self.r_prime = random_int()

class RSU:
  def __init__(self, rsu_id):
    self.id = rsu_id
    self.a = random_int()
    self.alpha = random_int()
    self.R_1 = self.alpha * P 
    self.R_2 = self.a * self.alpha * P 
    self.phi = self.alpha * priK * P 

def register(v: Vehicle, rsu: RSU):
  R_v = v.r * P  
  R_v_prime = v.r_prime * R_v 
  R_b = v.r * rsu.R_1 

  delta = v.r * rsu.phi

  S = rsu.alpha * R_v_prime 
  S_1 = (rsu.alpha // rsu.a) * R_v_prime 

  cert = rsu.a * H1(bytes(f"{S}{v.id}", "utf-8")) 
  ld = (rsu.a // (rsu.alpha)**2) * delta

  return (cert, ld)

def signing(v: Vehicle, rsu: RSU, message, cert, ld):
  S_prime = v.r * v.r_prime * rsu.alpha * P

  K_1_point = v.r * v.r_prime * cert
  K_1 = H2(cert) * v.r * v.r_prime
  Q_point = H1(bytes(f"{S_prime}{v.id}", "utf-8"))
  Q = hash(bytes(f"{S_prime}{v.id}", "utf-8"))

  K_1_prime_point = v.r * v.r_prime * Q_point 
  K_1_prime = v.r * v.r_prime * Q 
  ld_prime = inverse_mod(1, p) * ld # change K_1 to 1 for mocking purpose

  pid = (K_1, K_1_prime)

  K_1_inverse = inverse_mod(1, p) # change K_1 to 1 for mocking purpose
  hash_message = hash(bytes(message, "utf-8"))
  sigma = K_1_point + (hash_message * ld_prime * K_1_inverse)

  timestamp = 0
  
  sign = (pid, sigma, K_1_prime_point, K_1_prime, message, timestamp)

  return sign

def batch_authentication(rsu: RSU, signs):
  total_sigma = None
  total_K_1_prime = None
  total_hash_message = None

  order_total_sigma = None
  order_total_K_1_prime = None
  order_total_hash_message = None

  for sign in signs:
      (_, sigma, K_1_prime_point, K_1_prime, message, _) = sign
      # print(sigma)
      # print(K_1_prime_point)
      # print(message)
      if total_sigma is None:
        total_sigma = sigma
        # order_total_sigma = total_sigma.order()
      else:
        total_sigma += sigma

      if total_K_1_prime is None:
        total_K_1_prime = K_1_prime_point
        # order_total_K_1_prime = total_K_1_prime.order()
      else:
        total_K_1_prime += K_1_prime_point

      hash_message = inverse_mod(1, p) * H1(bytes(message, "utf-8"))
      if total_hash_message is None:
        total_hash_message = hash_message
        # order_total_hash_message = total_hash_message.order()
      else:
        total_hash_message += hash_message

  order_total_sigma = total_sigma.order()
  order_total_K_1_prime = total_K_1_prime.order()
  order_total_hash_message = total_hash_message.order()

  left = total_sigma.tate_pairing(rsu.R_1, Integer(order_total_sigma), GF(Integer(order_total_sigma))(p).multiplicative_order())
  right = total_sigma.tate_pairing(rsu.R_2, Integer(order_total_K_1_prime), GF(Integer(order_total_K_1_prime))(p).multiplicative_order())
  right *= total_sigma.tate_pairing(pubK, Integer(order_total_hash_message), GF(Integer(order_total_hash_message))(p).multiplicative_order())

  return left == right

n_vehicle = 10

def run_signing():
  v = Vehicle(1)
  rsu = RSU(1)

  cert, ld = register(v, rsu)
  message = "Hello, RSU!"

  sign = signing(v, rsu, message, cert, ld)
  # batch_authentication(rsu, [sign for _ in range(n_vehicle)])
  
v = [Vehicle(1) for i in range(n_vehicle)]
rsu = RSU(1)

signs = []

for i in range(n_vehicle):
  cert, ld = register(v[i], rsu)
  message = "Hello, RSU!"

  sign = signing(v[i], rsu, message, cert, ld)
  signs.append(sign)

def run_batch_auth():
  batch_authentication(rsu, signs)

def test_tate():
  p = Integer(103); A = Integer(1); B = Integer(18); E = EllipticCurve(GF(p), [A, B])
  P = E(Integer(33), Integer(91)); n = P.order(); n
  k = GF(n)(p).multiplicative_order(); k
  Q = E(Integer(87), Integer(51))
  start = time.time()
  P.tate_pairing(Q, n, k)
  end = time.time()
  print(f"{(end - start)*1000:.5f} ms")

def test_weil():
  F = GF((Integer(2),Integer(5)), names=('a',)); (a,) = F._first_ngens(1)
  E = EllipticCurve(F, [Integer(0),Integer(0),Integer(1),Integer(1),Integer(1)])
  P = E(a**Integer(4) + Integer(1), a**Integer(3))
  Fx = GF((Integer(2), Integer(4)*Integer(5)), names=('b',)); (b,) = Fx._first_ngens(1)
  Ex = EllipticCurve(Fx, [Integer(0),Integer(0),Integer(1),Integer(1),Integer(1)])
  phi = Hom(F, Fx)(F.gen().minpoly().roots(Fx)[Integer(0)][Integer(0)])
  Px = Ex(phi(P.x()), phi(P.y()))
  O = Ex(Integer(0))
  Qx = Ex(b**Integer(19) + b**Integer(18) + b**Integer(16) + b**Integer(12) + b**Integer(10) + b**Integer(9) + b**Integer(8) + b**Integer(5) + b**Integer(3) + Integer(1),
          b**Integer(18) + b**Integer(13) + b**Integer(10) + b**Integer(8) + b**Integer(5) + b**Integer(4) + b**Integer(3) + b)
  start = time.time()
  Px.weil_pairing(Qx, Integer(41)) == b**Integer(19) + b**Integer(15) + b**Integer(9) + b**Integer(8) + b**Integer(6) + b**Integer(4) + b**Integer(3) + b**Integer(2) + Integer(1)
  Px.weil_pairing(Integer(17)*Px, Integer(41)) == Fx(Integer(1))
  Px.weil_pairing(O, Integer(41)) == Fx(Integer(1))
  end = time.time()
  print(f"{(end - start)*1000:.5f} ms")

def test():
  # inverse_mod(1, 11)
  P+P

def main():
  # print(f"signing: {timeit("run_signing()", number=Integer(1), repeat=Integer(1))}")
  # print(f"batch authentication: {timeit("run_batch_auth()", number=Integer(1), repeat=Integer(1))}")
  # print(f"test: {timeit("test()", number=Integer(100), repeat=Integer(1))}")
  start = time.time()
  run_batch_auth()
  end = time.time()
  print(f"{(end - start)*1000:.5f} ms")  

# Run the main function
if __name__ == "__main__":
  main()