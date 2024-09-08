import mysql.connector
import base64
from utils import hash_sha256
from measurement import measure_computation_cost

dummy = []  

def insertRows(n):
  # Connect to the MySQL database
  connection = mysql.connector.connect(
      host="localhost",
      user="root",
      password="root",
      database="RandomValueDB"
  )

  # Create a cursor object
  cursor = connection.cursor()

  # Delete all data from the table
  cursor.execute(f"DELETE FROM RandomValues;")

  # Insert n rows into the table
  for i in range(50001, 50001+n):
    hash_digest = hash_sha256(str(i))
    hash_base64 = base64.b64encode(hash_digest).decode('utf-8').rstrip('=')
    cursor.execute(f'INSERT INTO RandomValues (value) VALUES ("{hash_base64}");')

  # Commit and Close the connection
  connection.commit()
  connection.close()
  
def readTable():
  # Connect to the MySQL database
  connection = mysql.connector.connect(
      host="localhost",
      user="root",
      password="root",
      database="RandomValueDB"
  )

  # Create a cursor object
  cursor = connection.cursor()

  # Execute a query
  cursor.execute("SELECT id, value FROM RandomValues")

  # Fetch the results
  results = cursor.fetchall()

  # Close the connection
  connection.close()

  return results

def testDatabase(n):
  save = readTable()
  notFound = []

  for i, device in enumerate(dummy):
    hash_digest = hash_sha256(device)
    hash_base64 = base64.b64encode(hash_digest).decode('utf-8').rstrip('=')
    res_base64 = save[i][1]
    if hash_base64 != res_base64:
      notFound.append(i+1)
  
def main():
  global dummy

  n = 100     # no. of devices in a group

  # reset saved devices in the database
  insertRows(n)

  # reset the dummy data
  dummy = [str(i) for i in range(1, n+1)]

  # measure time taken
  measure_computation_cost(testDatabase, f"Database Detection: read and compare {n} devices from the database", 100, n)

if __name__ == "__main__":
  main()
