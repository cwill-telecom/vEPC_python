"""
Synchronization utilities

"""

import threading

class Sync:
    """Synchronization class"""
    
    @staticmethod
    def mux_init(mux):
        """Initialize mutex"""
        # In Python, this is handled by threading.Lock
        pass
    
    @staticmethod
    def mlock(mux):
        """Lock mutex"""
        mux.acquire()
    
    @staticmethod
    def munlock(mux):
        """Unlock mutex"""
        mux.release()

# Global instances
g_sync = Sync()