DEBUG = False

def print_debug(*args, **kwargs):
    global DEBUG
    if DEBUG:
        print('[DEBUG]', *args, **kwargs)

def set_debug(value):
    global DEBUG
    DEBUG = value