import platform

def get_system_info():
    system = platform.system()
    release = platform.release()

    return system, release