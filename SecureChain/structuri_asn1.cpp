#pragma warning(disable : 4996)
#include "structuri_asn1.h"

// PubKeyMac: = Sequence {
//   PubKeyName: PrintableString
//   MACKey: OCTET STRING
//   MACValue: OCTET STRING
// }
ASN1_SEQUENCE(PubKeyMac) = {
    ASN1_SIMPLE(PubKeyMac, PubKeyName, ASN1_PRINTABLESTRING),
    ASN1_SIMPLE(PubKeyMac, MACKey, ASN1_OCTET_STRING),
    ASN1_SIMPLE(PubKeyMac, MACValue, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(PubKeyMac)

IMPLEMENT_ASN1_FUNCTIONS(PubKeyMac);

// SymElements: = Sequence {
//   SymElementsID: Integer
//   SymKey: OCTET STRING
//   IV: OCTET STRING
// }
ASN1_SEQUENCE(SymElements) = {
    ASN1_SIMPLE(SymElements, SymElementsID, ASN1_INTEGER),
    ASN1_SIMPLE(SymElements, SymKey, ASN1_OCTET_STRING),
    ASN1_SIMPLE(SymElements, IV, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(SymElements)

IMPLEMENT_ASN1_FUNCTIONS(SymElements);

// Transaction: = Sequence {
//   TransactionID: Integer
//   Subject: Printable String
//   SenderID: Integer
//   ReceiverID: Integer
//   SymElementsID: Integer
//   EncryptedData: OCTET STRING
//   TransactionSign: OCTET STRING
// }

ASN1_SEQUENCE(Transaction) = {
    ASN1_SIMPLE(Transaction, TransactionID, ASN1_INTEGER),
    ASN1_SIMPLE(Transaction, Subject, ASN1_PRINTABLESTRING),
    ASN1_SIMPLE(Transaction, SenderID, ASN1_INTEGER),
    ASN1_SIMPLE(Transaction, ReceiverID, ASN1_INTEGER),
    ASN1_SIMPLE(Transaction, SymElementsID, ASN1_INTEGER),
    ASN1_SIMPLE(Transaction, EncryptedData, ASN1_OCTET_STRING),
    ASN1_SIMPLE(Transaction, TransactionSign, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(Transaction)

IMPLEMENT_ASN1_FUNCTIONS(Transaction);