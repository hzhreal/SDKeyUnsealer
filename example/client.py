import socket

# a very simple python script to interact with SDKeyUnsealer

IP = ""
PORT = 0
TEST_FILE = ""

def chks(data: bytearray) -> bytes:
    sum = 0
    for byte in data:
        sum += byte
    sum &= 0xFF
    hex_str = hex(sum)[2:]
    return hex_str.encode()

def main(ip: str, port: int, data: bytes) -> None:
    sck = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    sck.connect((ip, port))
    sck.sendall(data)

    recv = sck.recv(1024)

    sck.close()

    print(recv)

    with open("dump.bin", "wb") as f:
        f.write(recv)

if __name__ == "__main__":
    with open(TEST_FILE, "rb") as f:
        data = f.read()
    sum = chks(bytearray(data))
    data += sum
    main(IP, PORT, data)