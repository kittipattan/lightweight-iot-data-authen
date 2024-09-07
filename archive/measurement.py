import time
import psutil
import os

def measure_computation_cost(func, name, round):

  print(f"""\n--------------------------------------------------------------------
START MEASURING '{name}'
--------------------------------------------------------------------\n""")

  # execution time, cpu usage, memory usage

  ### get started ###
  num_round = round
  p = psutil.Process(os.getpid())
  execution_time = 0
  cpu_usage = 0
  memory_used = 0

  for _ in range(num_round):
    start_time = time.time()
    cpu_before = p.cpu_percent()
    memory_before = p.memory_info().rss

    ### call function
    func()

    end_time = time.time()
    execution_time += (end_time - start_time)
    cpu_after = p.cpu_percent()
    cpu_usage += cpu_after - cpu_before
    memory_after = p.memory_info().rss
    memory_used += memory_after - memory_before

  print("===== Experiment Result =====\n")
  print(f"Execution Time: {(execution_time/num_round)*1000:.5f} ms")
  print("\n============ END ============\n")

  return