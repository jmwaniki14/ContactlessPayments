# ContactlessPayments
JAVACARD development in JCIDE for verification of secure transactions.

Card 1
Card Number: 123456 (Hex: 31 32 33 34 35 36)
PIN: 1234 (Hex: 31 32 33 34)

Card 2
Card Number: 789012 (Hex: 37 38 39 30 31 32)
PIN: 5678 (Hex: 35 36 37 38)

TESTING IN APDU:
Card 1
CLA:00
INS:B1
P1:00
P2:00
LC:0A
LE:10
DATA:31 32 33 34 35 36 31 32 33 34

Card 2
CLA:00
INS:B1
P1:00
P2:00
LC:0A
LE:10
DATA:37 38 39 30 31 32 35 36 37 38


-----NOTES---
CLA - Class byte
INS - Instruction for verifying the PIN
P1 - Parameter 1, often used for specifying additional details
P2 - Parameter 2, often used for specifying additional details
Lc - Length of command data, which includes the card number and PIN
LE - Expected length of the response
DATA -represents the card number followed by the PIN

NB:
JavaCard does not support the String class and its methods, can only use byte arrays as shown above and in the code.


--------ENCRYPTION AND DECRYPTION-------
The code provided implements encryption and decryption functionalities 
using the AES (Advanced Encryption Standard) algorithm in the context of a JavaCard application.
----->>>ENCRYPTION
Initialization:
An AES key (aesKey) is created and initialized with a predefined key (ENCRYPTION_KEY).
A Cipher instance (aesCipher) is initialized in AES-128-ECB (Electronic Codebook) mode.

Encrypt Method:
Input: The method takes a byte array (input) that represents the data to be encrypted.
Encryption Process:
The doFinal method of the aesCipher object is called with the input data. This method performs the encryption.
The encrypted data is stored in the output array.
Output: The method returns the output byte array containing the encrypted data.

The encrypted code block is:
public byte[] encrypt(final byte[] input) {
    final byte[] output = new byte[input.length];
    try {
        aesCipher.doFinal(input, (short)0, (short)input.length, output, (short)0);
    } catch (final Exception e) {
        ISOException.throwIt(ISO7816.SW_UNKNOWN);
    }
    return output;
}


------>>>>DECRYPTION
Initialization:
The same AES key (aesKey) is used for decryption.
The aesCipher instance is reinitialized in decryption mode.

Decrypt Method:
Input: The method takes a byte array (input) that represents the data to be decrypted.
Decryption Process:
The init method of the aesCipher object is called to set it to decryption mode.
The doFinal method of the aesCipher object is called with the encrypted input data. This method performs the decryption.
The decrypted data is stored in the output array.
Output: The method returns the output byte array containing the decrypted data.

Decryption code block:
public byte[] decrypt(final byte[] input) {
    final byte[] output = new byte[input.length];
    try {
        aesCipher.init(aesKey, Cipher.MODE_DECRYPT);
        aesCipher.doFinal(input, (short)0, (short)input.length, output, (short)0);
    } catch (final Exception e) {
        ISOException.throwIt(ISO7816.SW_UNKNOWN);
    }
    return output;
}


JAVACARD APPLICATION SECURITY
In this JavaCard application, the encryption and decryption methods are used to handle sensitive data securely.

1. When the handleEncryption method is called, it takes the data from the APDU command, 
encrypts it using the encrypt method, and sends the encrypted data back as a response.

code block:
private void handleEncryption(final APDU apdu) {
    final byte[] buffer = apdu.getBuffer();
    final short lc = (short) (buffer[ISO7816.OFFSET_LC] & 0xFF);
    final byte[] dataToEncrypt = new byte[lc];
    Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, dataToEncrypt, (short) 0, lc);

    final byte[] encryptedData = encrypt(dataToEncrypt);

    apdu.setOutgoing();
    apdu.setOutgoingLength((short) encryptedData.length);
    apdu.sendBytesLong(encryptedData, (short) 0, (short) encryptedData.length);
}


2. The verifyPin method uses the encryption functionality to securely verify the PIN associated with a card number.
It compares the encrypted PIN stored on the card with the encrypted PIN provided in the APDU command to ensure they match.

code block:
public boolean verifyPin(final byte[] cardNumber, final byte[] pin) {
    final short numCards = 2;
    final short cardNumberLen = 6;
    final short pinLen = 4;

    for (short i = 0; i < numCards; i++) {
        final byte[] storedCardNumber = new byte[cardNumberLen];
        Util.arrayCopy(cardNumbers, (short)(i * cardNumberLen), storedCardNumber, (short)0, cardNumberLen);

        if (Util.arrayCompare(storedCardNumber, (short)0, cardNumber, (short)0, cardNumberLen) == 0) {
            final byte[] storedPin = new byte[pinLen];
            Util.arrayCopy(pins, (short)(i * pinLen), storedPin, (short)0, pinLen);
            return Util.arrayCompare(storedPin, (short)0, pin, (short)0, pinLen) == 0;
        }
    }
    return false;
}



VERIFICATION RESPONSES FOR TRANSACTIONS
This below code block has been implemented to determine whether the transaction should proceed or be rejected.

1. If the PIN is valid:
if (isValid) {
    byte[] successMessage = new byte[] {
        (byte)'P', (byte)'I', (byte)'N', (byte)' ', (byte)'V', (byte)'E', (byte)'R', (byte)'I', (byte)'F', (byte)'I', (byte)'E', (byte)'D', 
        (byte)' ', (byte)'S', (byte)'U', (byte)'C', (byte)'C', (byte)'E', (byte)'S', (byte)'S', (byte)'F', (byte)'U', (byte)'L', (byte)'L', 
        (byte)'Y', (byte)'!', (byte)' ', (byte)'T', (byte)'R', (byte)'A', (byte)'N', (byte)'S', (byte)'A', (byte)'C', (byte)'T', (byte)'I', 
        (byte)'O', (byte)'N', (byte)' ', (byte)'H', (byte)'A', (byte)'S', (byte)' ', (byte)'B', (byte)'E', (byte)'E', (byte)'N', (byte)' ', 
        (byte)'C', (byte)'O', (byte)'M', (byte)'P', (byte)'L', (byte)'E', (byte)'T', (byte)'E', (byte)'D', (byte)'.'
    };
    sendResponse(apdu, (short) 0x9000, successMessage);
}

The message, when converted to text, reads: "PIN VERIFIED SUCCESSFULLY! TRANSACTION HAS BEEN COMPLETED."
The sendResponse method is then called with an APDU status word of 0x9000 
(which typically indicates success in ISO/IEC 7816-4) and the successMessage



2. If the PIN is not valid:

else {
    byte[] failureMessage = new byte[] {
        (byte)'I', (byte)'N', (byte)'V', (byte)'A', (byte)'L', (byte)'I', (byte)'D', (byte)' ', (byte)'P', (byte)'I', (byte)'N', (byte)' ', 
        (byte)'O', (byte)'R', (byte)' ', (byte)'C', (byte)'A', (byte)'R', (byte)'D', (byte)' ', (byte)'N', (byte)'U', (byte)'M', (byte)'B', 
        (byte)'E', (byte)'R', (byte)'!', (byte)' ', (byte)'T', (byte)'R', (byte)'A', (byte)'N', (byte)'S', (byte)'A', (byte)'C', (byte)'T', 
        (byte)'I', (byte)'O', (byte)'N', (byte)' ', (byte)'D', (byte)'E', (byte)'C', (byte)'L', (byte)'I', (byte)'N', (byte)'E', (byte)'D', 
        (byte)'!'
    };
    sendResponse(apdu, (short) 0x6300, failureMessage);
}

The message, when converted to text, reads: "INVALID PIN OR CARD NUMBER! TRANSACTION DECLINED!"
The sendResponse method is called with an APDU status word of 0x6300 
(which indicates a warning or failure) and the failureMessage.
