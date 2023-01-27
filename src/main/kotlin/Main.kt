import java.io.File
import java.math.BigInteger
import java.security.*
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import javax.crypto.Cipher
import kotlin.math.ln

fun main() {
    val message = "YERZHAN"
    println("Original Message: $message")

    val keyPair = generateKeyPair()
    savePublicKeys(keyPair.public as RSAPublicKey)
    savePrivateKeys(keyPair.private as RSAPrivateKey)

    val encryptedMessage = encrypt(message, keyPair.public)
    println("Encrypted Message: $encryptedMessage")

    val encryptedMessageAsCharArray = encryptedMessage.toString().toCharArray()
    var encryptedMessageAsNumbers = ""
    print("Encrypted Message as Numbers: ")
    for (character in encryptedMessageAsCharArray) {
        encryptedMessageAsNumbers+="{${character.code}} "
    }
    println(encryptedMessageAsNumbers)

    val decryptedMessage = decrypt(encryptedMessage, keyPair.private)
    println("Decrypted Message: $decryptedMessage")

    val decryptedMessageAsCharArray = decryptedMessage.toCharArray()
    var decryptedMessageAsNumbers = ""
    print("Decrypted Message as Numbers: ")
    for (character in decryptedMessageAsCharArray) {
        decryptedMessageAsNumbers+="{${character.code}} "
    }
    println(decryptedMessageAsNumbers)

    //EDS Part
    val digest = MessageDigest.getInstance("SHA-256")
    val hashedMessage = digest.digest(message.toByteArray())
    val hashValueOfMessage = BigInteger(1,hashedMessage)
    val d : BigInteger? = (keyPair.private as RSAPrivateKey).privateExponent
    val n : BigInteger? = (keyPair.private as RSAPrivateKey).modulus
    var signature = hashValueOfMessage.modPow(d, n)
    signature++
    println("Signature:                   $signature")
    val e : BigInteger? = (keyPair.public as RSAPublicKey).publicExponent
    val verifiedHashValue = signature.modPow(e, n)
    println("Verified/Checked Hash Value: $verifiedHashValue")
    println("Hash Value of Message:       $hashValueOfMessage")
    if(verifiedHashValue == hashValueOfMessage){
        println("Signature is valid")
    }else{
        println("Signature is invalid")
    }
}
fun savePublicKeys(publicKey : RSAPublicKey) {
    val result : String = "n: ${publicKey.modulus}\n" +
            "e: ${publicKey.publicExponent}\n\n"
    File("publicKeys.txt").appendText(result)
}
fun savePrivateKeys(privateKey : RSAPrivateKey) {
    val result : String = "n: ${privateKey.modulus}\n" +
            "d: ${privateKey.privateExponent}\n\n"
    File("privateKeys.txt").appendText(result)
}
fun generateKeyPair(): KeyPair {
    val keyGen = KeyPairGenerator.getInstance("RSA")
    keyGen.initialize(512)
    return keyGen.genKeyPair()
}

fun encrypt(message: String, publicKey: PublicKey): ByteArray {
    val cipher = Cipher.getInstance("RSA")
    cipher.init(Cipher.ENCRYPT_MODE, publicKey)
    return cipher.doFinal(message.toByteArray())
}

fun decrypt(encryptedMessage: ByteArray, privateKey: PrivateKey): String {
    val cipher = Cipher.getInstance("RSA")
    cipher.init(Cipher.DECRYPT_MODE, privateKey)
    return String(cipher.doFinal(encryptedMessage))
}


