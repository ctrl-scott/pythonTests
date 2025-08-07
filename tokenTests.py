# Sources Used (MLA Format):
# 
# 1. Python Software Foundation. “uuid — UUID Objects According to RFC 4122.” 
#    Python 3.11.8 Documentation, https://docs.python.org/3/library/uuid.html. Accessed 7 Aug. 2025.
#
# 2. Python Software Foundation. “platform — Access to Underlying Platform’s Identifying Data.” 
#    Python 3.11.8 Documentation, https://docs.python.org/3/library/platform.html. Accessed 7 Aug. 2025.
#
# 3. Python Software Foundation. “socket — Low-Level Networking Interface.” 
#    Python 3.11.8 Documentation, https://docs.python.org/3/library/socket.html. Accessed 7 Aug. 2025.
#
# 4. Python Software Foundation. “time — Time Access and Conversions.” 
#    Python 3.11.8 Documentation, https://docs.python.org/3/library/time.html. Accessed 7 Aug. 2025.
#
# 5. PyJWT Documentation. PyJWT, https://pyjwt.readthedocs.io/en/stable/. Accessed 7 Aug. 2025.
#
# 6. OpenAI. ChatGPT, version 4o. Accessed 7 Aug. 2025. Prompted by the user to generate and document a Python-based 
#    machine-tokenization system using JWT. https://chat.openai.com/
# ***********
# While I understand the security concept of not trusting MAC addresses - this script is geared toward unique and real users of machines and other devices

import uuid
import platform
import socket
import jwt  # PyJWT
import time

# Your secret key (keep it secret!)
SECRET_KEY = "YourSuperSecretKeyHere"
ALGORITHM = "HS256"

def get_machine_info():
    """Gather unique machine and OS identifiers."""
    return {
        "mac_address": get_mac_address(),
        "hostname": socket.gethostname(),
        "os_platform": platform.system(),
        "os_version": platform.version(),
        "architecture": platform.machine(),
    }

def get_mac_address():
    """Returns the MAC address of the machine as a string."""
    mac = uuid.getnode()
    mac_address = ':'.join(['{:02x}'.format((mac >> ele) & 0xff)
                           for ele in range(40, -1, -8)])
    return mac_address

def generate_token():
    """Generates a JWT using machine-specific information."""
    machine_data = get_machine_info()

    payload = {
        "iat": int(time.time()),       # issued at
        "exp": int(time.time()) + 3600,  # expires in 1 hour
        "machine_info": machine_data,
        "device_id": str(uuid.uuid4()),  # Unique token/session/device id
    }

    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return token

if __name__ == "__main__":


    print("Just running the get machine info function")
    a = get_machine_info()
    print(a)
