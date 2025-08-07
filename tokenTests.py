# Sources:
# - "PyJWT Documentation." PyJWT, https://pyjwt.readthedocs.io/en/stable/
# - Python Software Foundation. “uuid — UUID objects according to RFC 4122.” Python 3.11.8 Documentation, https://docs.python.org/3/library/uuid.html
# - Python Software Foundation. “platform — Access to underlying platform’s identifying data.” Python 3.11.8 Documentation, https://docs.python.org/3/library/platform.html
# - Python Software Foundation. “socket — Low-level networking interface.” Python 3.11.8 Documentation, https://docs.python.org/3/library/socket.html
# - Python Software Foundation. “time — Time access and conversions.” Python 3.11.8 Documentation, https://docs.python.org/3/library/time.html

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