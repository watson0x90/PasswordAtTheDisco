def overlaps(bbox1, bbox2):
    x1, y1, w1, h1 = bbox1
    x2, y2, w2, h2 = bbox2
    return (x1 < x2 + w2 and x1 + w1 > x2 and y1 < y2 + h2 and y1 + h1 > y2)

def show_processing_animation(stop_event):
    """Display a fun spinning animation in the terminal until stopped."""
    import sys
    import time
    
    spinner = ['|', '/', '-', '\\']
    while not stop_event.is_set():
        for char in spinner:
            sys.stdout.write(f'\rProcessing domains... {char}')
            sys.stdout.flush()
            time.sleep(0.1)
    sys.stdout.write('\rProcessing domains... Done!    \n')
    sys.stdout.flush()