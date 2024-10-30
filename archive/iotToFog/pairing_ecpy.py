from ecpy.curves import Curve, Point
from ecpy.keys import ECPublicKey, ECPrivateKey
import hashlib
import secrets
import timeit

# Define the elliptic curve using ECPy's built-in curves
curve = Curve.get_curve('Curve25519')  # You can change the curve to match your requirement
P = curve.generator
Q = ECPrivateKey(secrets.randbelow(curve.order), curve).get_public_key().W

class EllipticCurve:
    def __init__(self, curve):
        self.curve = curve

    def is_on_curve(self, P):
        """Check if a point P is on the curve."""
        if P is None:
            return True
        return self.curve.is_on_curve(P)

    def add_points(self, P, Q):
        """Add two points on the elliptic curve."""
        if P is None:
            return Q
        if Q is None:
            return P
        return P + Q

    def double_point(self, P):
        """Double a point on the elliptic curve."""
        return P * 2

    def mod_inverse(self, a):
        """Modular inverse calculation."""
        return pow(a, -1, self.curve.field)

    def hash_to_point(self, message):
        """Map a hash to a point on the elliptic curve (H1)."""
        h = hashlib.sha256(message.encode()).hexdigest()
        x = int(h, 16) % self.curve.field  # Ensure x is in the field

        while True:
            rhs = (x**3 + self.curve.a * x + self.curve.b) % self.curve.field
            y = pow(rhs, (self.curve.field + 1) // 4, self.curve.field)
            if (y**2) % self.curve.field == rhs:
                return Point(x, y, self.curve)
            x = (x + 1) % self.curve.field

    def point_multiplication(self, P, k):
        """Multiply a point P by scalar k."""
        return P * k
    
    def bilinear_pairing(self, P, Q):
      """Example bilinear pairing (depends on specific pairing algorithms)."""
      f = self.miller_loop(P, Q, self.curve.order)
      return pow(f, (self.curve.field - 1) // curve.order, self.curve.field)
    
    def line_func(self, P, R, Q):
        """Calculate the line function (used in Miller loop)."""
        if P is None or Q is None:
            return 1

        numerator = (Q.y - P.y) % self.curve.field
        denominator = (Q.x - P.x) % self.curve.field
        if denominator == 0:
            return 0

        lamb = (numerator * self.mod_inverse(denominator)) % self.curve.field
        return (R.y - lamb * (R.x - P.x) - P.y) % self.curve.field

    def miller_loop(self, P, Q, r):
        """Perform the Miller loop."""
        T = P
        f = 1
        bits = bin(r)[2:]

        for bit in bits[1:]:
            f = (f * f * self.line_func(T, T, Q)) % self.curve.field
            T = self.double_point(T)
            if bit == '1':
                f = (f * self.line_func(T, P, Q)) % self.curve.field
                T = self.add_points(T, P)
        return f

def hash_function(m):
    return int.from_bytes(hashlib.sha256(m.encode()).digest())

def point_to_hash(point):
    # H2: G2 → {0, 1}^n, where n is the bit size of the hash output
    x = point.x
    y = point.y
    return int.from_bytes(hashlib.sha256(f"{x}{y}".encode()).digest())

if __name__ == "__main__":
    c = EllipticCurve(curve)

    start = timeit.default_timer()
    c.bilinear_pairing(P, Q)
    print(f"{(timeit.default_timer() - start)*1000:.5f}")