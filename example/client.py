import asyncio

# a very simple python script to interact with SDKeyUnsealer

IP = "192.168.10.198"
PORT = 9095
TEST_FILE = "STORM4.S.bin"
    
class SDKeyUnsealer():
    """Interact with SDKeyUnsealer if used."""
    def __init__(self, HOST: str, PORT: int, maxConnections: int = 5) -> None:
        self.HOST = HOST
        self.PORT = PORT
        self.semaphore = asyncio.Semaphore(maxConnections)
        
    DEC_KEY_LEN = 32
    CHKS_LEN = 2

    async def send_tcp_message_with_response(self, data: bytearray | bytes) -> bytes | str:
        writer = None
        async with self.semaphore:
            reader, writer = await asyncio.open_connection(self.HOST, self.PORT)
            writer.write(data)
            await writer.drain()
        
            response = await reader.read(1024)
            
            if writer is not None:
                writer.close()
                await writer.wait_closed()

            parsed_response = self.parse_response(response)
            return parsed_response
    
    async def upload_key(self, enc_key: bytearray) -> bytes | str:
        chks_val = self.chks(enc_key)
        enc_key.extend(chks_val)

        response = await self.send_tcp_message_with_response(enc_key)
        return response
      
    def parse_response(self, response: bytes) -> bytes | str:
        if len(response) == self.DEC_KEY_LEN + self.CHKS_LEN:
            # check if checksum is correct
            chks_val = self.chks(bytearray(response[:self.DEC_KEY_LEN]))
            response_chks = response[self.DEC_KEY_LEN:self.DEC_KEY_LEN + self.CHKS_LEN]

            if chks_val != response_chks:
                raise ValueError("Invalid checksum!")
            
            return response[:self.DEC_KEY_LEN]
      
        return response.decode("utf-8")

    @staticmethod
    def chks(data: bytearray) -> bytes:
        data_sum = 0
        for byte in data:
            data_sum += byte
            data_sum &= 0xFF
    
        data_hexstr = (hex(data_sum)[2:]).encode("utf-8")

        return data_hexstr

if __name__ == "__main__":
    ctx = SDKeyUnsealer(IP, PORT)

    with open(TEST_FILE, "rb") as f:
        enc_key = bytearray(f.read())

    dec_key = asyncio.run(ctx.upload_key(enc_key))
    if isinstance(dec_key, str):
        print(f"ERROR: {dec_key}")
        exit()

    with open(TEST_FILE + ".dec", "wb") as f:
        f.write(dec_key)