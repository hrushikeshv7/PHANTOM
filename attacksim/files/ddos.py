import socket
   import threading
  
   # Configuration - ONLY use on systems you own or have explicit permission to test
   TARGET_IP = "127.0.0.1"  # Replace with target IP (e.g., your local server)
   TARGET_PORT = 80         # Replace with target port (e.g., 80 for HTTP, 443 for HTTPS)
   THREAD_COUNT = 100       # Number of concurrent threads
  
   def flood():
      """Function to send a stream of packets to the target."""
       while True:
           try:
               # Create a TCP socket
               s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
               # Set a timeout so the script doesn't hang
               s.settimeout(4)
               # Connect to the target
               s.connect((TARGET_IP, TARGET_PORT))
               # Send a generic payload
               s.send(b"GET / HTTP/1.1\r\nHost: localtest\r\n\r\n")
               # Close the connection
               s.close()
           except socket.error:
               # If the server is down or rejecting connections, ignore and retry
              pass
  
   def start_stress_test():
       print(f"Starting stress test on {TARGET_IP}:{TARGET_PORT} with {THREAD_COUNT}
      threads...")
       threads = []
       for i in range(THREAD_COUNT):
           t = threading.Thread(target=flood)
           t.daemon = True  # Allows script to exit even if threads are running
           threads.append(t)
           t.start()
  
       # Keep the main thread alive
       try:
           while True:
               pass
       except KeyboardInterrupt:
           print("\nStopping stress test.")
  
    if __name__ == "__main__":
