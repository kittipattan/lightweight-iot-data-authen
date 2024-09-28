import timeit

def measure_computation_cost(func, name, round, *args, **kwargs):

  print(f"""\n--------------------------------------------------------------------
START MEASURING '{name}' {round} rounds
--------------------------------------------------------------------\n""")

  # execution time, cpu usage, memory usage

  ### get started ###
  num_round = round
  execution_time = 0

  for _ in range(num_round):
    start_time = timeit.default_timer()

    ### call function
    func(*args, **kwargs)

    end_time = timeit.default_timer()
    execution_time += (end_time - start_time)
    # new_execution_time = end_time - start_time
    # if (new_execution_time > execution_time):
    #   execution_time = new_execution_time

  exec_time = (execution_time/num_round)*1000
  # exec_time = execution_time*1000
  print("===== Experiment Result =====\n")
  print(f"Execution Time: {exec_time:.5f} ms")
  print("\n============ END ============\n")

  return exec_time