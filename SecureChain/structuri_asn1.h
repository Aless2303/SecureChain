#ifndef STRUCTURI_ASN1_H
#define STRUCTURI_ASN1_H

#include <openssl/asn1.h>
#include <openssl/asn1t.h>

// PubKeyMac: = Sequence {
//   PubKeyName: PrintableString
//   MACKey: OCTET STRING
//   MACValue: OCTET STRING
// }
typedef struct PubKeyMac {
    ASN1_PRINTABLESTRING* PubKeyName;
    ASN1_OCTET_STRING* MACKey;
    ASN1_OCTET_STRING* MACValue;
} PubKeyMac;

DECLARE_ASN1_FUNCTIONS(PubKeyMac);

// SymElements: = Sequence {
//   SymElementsID: Integer
//   SymKey: OCTET STRING
//   IV: OCTET STRING
// }
typedef struct SymElements {
    ASN1_INTEGER* SymElementsID;
    ASN1_OCTET_STRING* SymKey;
    ASN1_OCTET_STRING* IV;
} SymElements;

DECLARE_ASN1_FUNCTIONS(SymElements);

// Transaction: = Sequence {
//   TransactionID: Integer
//   Subject: Printable String
//   SenderID: Integer
//   ReceiverID: Integer
//   SymElementsID: Integer
//   EncryptedData: OCTET STRING
//   TransactionSign: OCTET STRING
// }
typedef struct Transaction {
    ASN1_INTEGER* TransactionID;
    ASN1_PRINTABLESTRING* Subject;
    ASN1_INTEGER* SenderID;
    ASN1_INTEGER* ReceiverID;
    ASN1_INTEGER* SymElementsID;
    ASN1_OCTET_STRING* EncryptedData;
    ASN1_OCTET_STRING* TransactionSign;
} Transaction;

DECLARE_ASN1_FUNCTIONS(Transaction);

#endif