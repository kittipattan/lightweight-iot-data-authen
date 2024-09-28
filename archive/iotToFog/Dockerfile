# Use the official SageMath image
FROM sagemath/sagemath:latest

# Set the working directory
WORKDIR /app

# Copy your Python script into the container
COPY pairing_sage.py /app/

# Run the Python script
CMD ["sage", "pairing_sage.py"]
