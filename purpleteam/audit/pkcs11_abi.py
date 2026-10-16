"""The PKCS#11 v2.40 definitions the driver needs: numbers, C structures and the signature of each call used.

Kept apart from the driver so the part that must match the specification exactly can be read, and checked against
a real module, on its own. ``CK_ULONG`` is ``unsigned long`` (``c_ulong``): 64-bit on Linux and macOS, which is
what this is verified on. The function list is the standard ``CK_FUNCTION_LIST`` in specification order; reading
a module's table in the wrong order would call the wrong function, so the order here is covered by the tests that
run against a real module.
"""

import ctypes
from ctypes import POINTER, c_char_p, c_ubyte, c_ulong, c_void_p

# Object, attribute and mechanism numbers from the PKCS#11 v2.40 specification.
CKO_PUBLIC_KEY, CKO_PRIVATE_KEY, CKK_EC, CKM_ECDSA, CKM_EC_KEY_PAIR_GEN = 2, 3, 3, 0x1041, 0x1040
CKA_CLASS, CKA_TOKEN, CKA_PRIVATE, CKA_LABEL, CKA_KEY_TYPE = 0x0, 0x1, 0x2, 0x3, 0x100
CKA_SENSITIVE, CKA_SIGN, CKA_VERIFY, CKA_EXTRACTABLE, CKA_EC_PARAMS, CKA_EC_POINT = 0x103, 0x108, 0x10A, 0x162, 0x180, 0x181
CKF_RW_SESSION, CKF_SERIAL_SESSION, CKU_USER, CKR_OK, CKR_ALREADY_INITIALIZED = 0x2, 0x4, 1, 0, 0x191
CKR_USER_ALREADY_LOGGED_IN = 0x100
RESULTS = {0x5: "CKR_GENERAL_ERROR", 0x30: "CKR_DEVICE_ERROR", 0x32: "CKR_DEVICE_REMOVED", 0x60: "CKR_KEY_HANDLE_INVALID",
            0x70: "CKR_MECHANISM_INVALID", 0xA0: "CKR_PIN_INCORRECT", 0xA4: "CKR_PIN_LOCKED", 0xB3: "CKR_SESSION_HANDLE_INVALID",
            0xE0: "CKR_TOKEN_NOT_PRESENT", 0x101: "CKR_USER_NOT_LOGGED_IN", 0x54: "CKR_FUNCTION_NOT_SUPPORTED"}
P256_PARAMS = (b"\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07", b"\x13\x0aprime256v1")  # OID, or the named-curve string
CALLS = ("C_Initialize C_Finalize C_GetInfo C_GetFunctionList C_GetSlotList C_GetSlotInfo C_GetTokenInfo "
          "C_GetMechanismList C_GetMechanismInfo C_InitToken C_InitPIN C_SetPIN C_OpenSession C_CloseSession "
          "C_CloseAllSessions C_GetSessionInfo C_GetOperationState C_SetOperationState C_Login C_Logout C_CreateObject "
          "C_CopyObject C_DestroyObject C_GetObjectSize C_GetAttributeValue C_SetAttributeValue C_FindObjectsInit "
          "C_FindObjects C_FindObjectsFinal C_EncryptInit C_Encrypt C_EncryptUpdate C_EncryptFinal C_DecryptInit "
          "C_Decrypt C_DecryptUpdate C_DecryptFinal C_DigestInit C_Digest C_DigestUpdate C_DigestKey C_DigestFinal "
          "C_SignInit C_Sign C_SignUpdate C_SignFinal C_SignRecoverInit C_SignRecover C_VerifyInit C_Verify "
          "C_VerifyUpdate C_VerifyFinal C_VerifyRecoverInit C_VerifyRecover C_DigestEncryptUpdate "
          "C_DecryptDigestUpdate C_SignEncryptUpdate C_DecryptVerifyUpdate C_GenerateKey C_GenerateKeyPair").split()


class Version(ctypes.Structure):
    _fields_ = [("major", c_ubyte), ("minor", c_ubyte)]


class FunctionList(ctypes.Structure):
    _fields_ = [("version", Version)] + [(name, c_void_p) for name in CALLS]


class Attribute(ctypes.Structure):
    _fields_ = [("type", c_ulong), ("value", c_void_p), ("length", c_ulong)]


class Mechanism(ctypes.Structure):
    _fields_ = [("mechanism", c_ulong), ("parameter", c_void_p), ("length", c_ulong)]


class TokenInfo(ctypes.Structure):
    _fields_ = [("label", c_ubyte * 32), ("manufacturer", c_ubyte * 32), ("model", c_ubyte * 16),
                ("serial", c_ubyte * 16), ("flags", c_ulong), ("max_sessions", c_ulong), ("sessions", c_ulong),
                ("max_rw_sessions", c_ulong), ("rw_sessions", c_ulong), ("max_pin", c_ulong), ("min_pin", c_ulong),
                ("public_total", c_ulong), ("public_free", c_ulong), ("private_total", c_ulong),
                ("private_free", c_ulong), ("hardware", Version), ("firmware", Version), ("time", c_ubyte * 16)]


PROTOTYPES = {  # return type is always CK_RV; these are the argument types of each call used
    "C_Initialize": [c_void_p], "C_Finalize": [c_void_p],
    "C_GetSlotList": [c_ubyte, POINTER(c_ulong), POINTER(c_ulong)], "C_GetTokenInfo": [c_ulong, POINTER(TokenInfo)],
    "C_OpenSession": [c_ulong, c_ulong, c_void_p, c_void_p, POINTER(c_ulong)], "C_CloseSession": [c_ulong],
    "C_Login": [c_ulong, c_ulong, c_char_p, c_ulong], "C_Logout": [c_ulong],
    "C_FindObjectsInit": [c_ulong, POINTER(Attribute), c_ulong],
    "C_FindObjects": [c_ulong, POINTER(c_ulong), c_ulong, POINTER(c_ulong)], "C_FindObjectsFinal": [c_ulong],
    "C_GetAttributeValue": [c_ulong, c_ulong, POINTER(Attribute), c_ulong],
    "C_SignInit": [c_ulong, POINTER(Mechanism), c_ulong],
    "C_Sign": [c_ulong, c_char_p, c_ulong, c_void_p, POINTER(c_ulong)],
    "C_GenerateKeyPair": [c_ulong, POINTER(Mechanism), POINTER(Attribute), c_ulong, POINTER(Attribute), c_ulong,
                          POINTER(c_ulong), POINTER(c_ulong)],
}
