import time
from qiskit import QuantumCircuit, Aer, execute
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Define a quantum circuit with 2 qubits and 2 classical bits
quantum_circuit = QuantumCircuit(2, 2)

# Simulated supercomputers
supercomputer1 = {
    "name": "Supercomputer 1",
    "ip": "192.168.1.1",
}

supercomputer2 = {
    "name": "Supercomputer 2",
    "ip": "192.168.1.2",
}

# Function to send a quantum message
def send_quantum_message(circuit, message):
    for i, bit in enumerate(message):
        if bit == "1":
            circuit.x(i)  # Apply X gate to flip the qubit to |1> state

# Function to receive a quantum message
def receive_quantum_message(circuit):
    try:
        circuit.measure([0, 1], [0, 1])  # Measure qubits into classical bits
        simulator = Aer.get_backend('qasm_simulator')
        job = execute(circuit, simulator, shots=1)
        result = job.result()
        counts = result.get_counts()
        return next(iter(counts.keys()))  # Get the measured result as a binary string
    except Exception as e:
        print(f"An error occurred while receiving a quantum message: {e}")
        return None

# Function to send a message
def send_message(sender, receiver, message, key):
    try:
        print(f"{sender['name']} ({sender['ip']}) is sending a message to {receiver['name']} ({receiver['ip']}):")
        print(f"Message: {message}")
        time.sleep(1)  # Simulate message transmission delay
        print(f"Message from {sender['name']} has been received by {receiver['name']}")
    except Exception as e:
        print(f"An error occurred while sending a message: {e}")

# Generate RSA key pair (public and private keys)
key = RSA.generate(2048)

# Alice's plaintext message
message = b'This is a secret message.'

# Create a cipher object with Bob's public key for encryption
cipher_rsa = PKCS1_OAEP.new(key.publickey())

# Encrypt the message
encrypted_message = cipher_rsa.encrypt(message)

if __name__ == "__main__":
    try:
        # Simulate sending and receiving quantum messages
        send_quantum_message(quantum_circuit, "101")
        received_quantum_message = receive_quantum_message(quantum_circuit)
        if received_quantum_message is not None:
            print("Received quantum message:", received_quantum_message)

        # Simulate sending and receiving encrypted messages
        send_message(supercomputer1, supercomputer2, encrypted_message, key)
        
        # Bob receives the encrypted message

        # Create a cipher object with Bob's private key for decryption
        cipher_rsa = PKCS1_OAEP.new(key)

        # Decrypt the message
        decrypted_message = cipher_rsa.decrypt(encrypted_message)

        # Print the original message
        print("Original Message:", message.decode('utf-8'))
        print("Decrypted Message:", decrypted_message.decode('utf-8'))

    except KeyboardInterrupt:
        print("Execution interrupted by the user.")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
