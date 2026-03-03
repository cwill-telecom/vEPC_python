"""
Telecom utilities for IMSI, PLMN, MME ID generation

"""

class Telecom:
    """Telecom utility class"""
    
    @staticmethod
    def get_plmn_id(mcc: int, mnc: int) -> int:
        """Get PLMN ID from MCC and MNC"""
        plmn = (mcc << 16) | mnc
        return plmn
    
    @staticmethod
    def get_mmei(mmegi: int, mmec: int) -> int:
        """Get MME identifier"""
        mmei = (mmegi << 16) | mmec
        return mmei
    
    @staticmethod
    def get_gummei(plmn_id: int, mmei: int) -> int:
        """Get GUMMEI (Globally Unique MME Identifier)"""
        gummei = (plmn_id << 16) | mmei
        return gummei
    
    @staticmethod
    def get_imsi(plmn_id: int, msisdn: int) -> int:
        """Get IMSI from PLMN ID and MSISDN"""
        imsi = (plmn_id << 32) | msisdn
        return imsi
    
    @staticmethod
    def get_guti(gummei: int, imsi: int) -> int:
        """Get GUTI (Globally Unique Temporary ID)"""
        guti = (gummei << 32) | imsi
        return guti

# Global instance
g_telecom = Telecom()