import time

def measure_computation_cost(func, name, round, *args, **kwargs):

  print(f"""\n--------------------------------------------------------------------
START MEASURING '{name}'
--------------------------------------------------------------------\n""")

  # execution time, cpu usage, memory usage

  ### get started ###
  num_round = round
  execution_time = 0

  for _ in range(num_round):
    start_time = time.time()

    ### call function
    func(*args, **kwargs)

    end_time = time.time()
    execution_time += (end_time - start_time)

  exec_time = (execution_time/num_round)*1000
  print("===== Experiment Result =====\n")
  print(f"Execution Time: {exec_time:.5f} ms")
  print("\n============ END ============\n")

  return exec_time