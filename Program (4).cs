using System;
using System.Security.Cryptography;
using System.Text;

class Program
{
    static void Main()
    {
        Console.WriteLine("Choose an encryption method :");
        Console.WriteLine("1. AES");
        Console.WriteLine("2. RSA");
        Console.WriteLine("3. TripleDES");

        int choice = int.Parse(Console.ReadLine());

        Console.WriteLine("Enter the text to encrypt :");
        string inputText = Console.ReadLine();

        switch (choice)
        {
            case 1:
                Console.WriteLine("Enter the AES key in Base64 format:");
                string aesKeyBase64 = Console.ReadLine();
                string encryptedAES = EncryptAES(inputText, Convert.FromBase64String(aesKeyBase64));
                Console.WriteLine($"Encrypted text : {encryptedAES}");

                string decryptedAES = DecryptAES(encryptedAES, Convert.FromBase64String(aesKeyBase64));
                Console.WriteLine($"Decrypted text : {decryptedAES}");
                break;

            case 2:
                RSAParameters rsaKey = GenerateRSAKey();
                string publicKey = Convert.ToBase64String(rsaKey.Modulus);
                string privateKey = Convert.ToBase64String(rsaKey.D);

                Console.WriteLine($"Public RSA key : {publicKey}");
                Console.WriteLine($"Private RSA key : {privateKey}");

                string encryptedRSA = EncryptRSA(inputText, rsaKey);
                Console.WriteLine($"Encrypted text : {encryptedRSA}");

                string decryptedRSA = DecryptRSA(encryptedRSA, rsaKey);
                Console.WriteLine($"Decrypted text : {decryptedRSA}");
                break;

            case 3:
                Console.WriteLine("Enter the TripleDES key in Base64 format:");
                string tripleDesKeyBase64 = Console.ReadLine();
                string encryptedTripleDES = EncryptTripleDES(inputText, Convert.FromBase64String(tripleDesKeyBase64));
                Console.WriteLine($"Encrypted text : {encryptedTripleDES}");

                string decryptedTripleDES = DecryptTripleDES(encryptedTripleDES, Convert.FromBase64String(tripleDesKeyBase64));
                Console.WriteLine($"Decrypted text : {decryptedTripleDES}");
                break;

            default:
                Console.WriteLine("Encryption method not recognized");
                break;
        }
    }

    static string EncryptAES(string plainText, byte[] key)
    {
        using (Aes aesAlg = Aes.Create())
        {
            aesAlg.Key = key;
            aesAlg.Mode = CipherMode.CBC;
            aesAlg.Padding = PaddingMode.PKCS7;

            aesAlg.GenerateIV();
            byte[] iv = aesAlg.IV;

            ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, iv);

            byte[] plainTextBytes = Encoding.UTF8.GetBytes(plainText);
            byte[] cipherTextBytes;

            using (MemoryStream msEncrypt = new MemoryStream())
            {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    csEncrypt.Write(plainTextBytes, 0, plainTextBytes.Length);
                    csEncrypt.FlushFinalBlock();
                }

                cipherTextBytes = msEncrypt.ToArray();
            }

            byte[] encryptedBytesWithIv = new byte[iv.Length + cipherTextBytes.Length];
            Buffer.BlockCopy(iv, 0, encryptedBytesWithIv, 0, iv.Length);
            Buffer.BlockCopy(cipherTextBytes, 0, encryptedBytesWithIv, iv.Length, cipherTextBytes.Length);

            return Convert.ToBase64String(encryptedBytesWithIv);
        }
    }

    static string DecryptAES(string cipherText, byte[] key)
    {
        try
        {
            byte[] encryptedBytesWithIv = Convert.FromBase64String(cipherText);

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.Mode = CipherMode.CBC;
                aesAlg.Padding = PaddingMode.PKCS7;

                byte[] iv = new byte[aesAlg.IV.Length];
                byte[] encryptedText = new byte[encryptedBytesWithIv.Length - iv.Length];

                Buffer.BlockCopy(encryptedBytesWithIv, 0, iv, 0, iv.Length);
                Buffer.BlockCopy(encryptedBytesWithIv, iv.Length, encryptedText, 0, encryptedText.Length);

                aesAlg.IV = iv;

                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                byte[] decryptedTextBytes;

                using (MemoryStream msDecrypt = new MemoryStream(encryptedText))
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    decryptedTextBytes = new byte[encryptedText.Length];
                    csDecrypt.Read(decryptedTextBytes, 0, decryptedTextBytes.Length);
                }

                return Encoding.UTF8.GetString(decryptedTextBytes);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"AES Decryption Error: {ex.Message}");
            return null;
        }
    }

    static RSAParameters GenerateRSAKey()
    {
        using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(2048))
        {
            return rsa.ExportParameters(true);
        }
    }

    static string EncryptRSA(string plainText, RSAParameters publicKey)
    {
        try
        {
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(publicKey);

                byte[] plainTextBytes = Encoding.UTF8.GetBytes(plainText);
                byte[] cipherTextBytes = rsa.Encrypt(plainTextBytes, false);

                return Convert.ToBase64String(cipherTextBytes);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"RSA Encryption Error: {ex.Message}");
            return null;
        }
    }

    static string DecryptRSA(string cipherText, RSAParameters privateKey)
    {
        try
        {
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
            {
                rsa.ImportParameters(privateKey);

                byte[] cipherTextBytes = Convert.FromBase64String(cipherText);
                byte[] decryptedBytes = rsa.Decrypt(cipherTextBytes, false);

                return Encoding.UTF8.GetString(decryptedBytes);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"RSA Decryption Error: {ex.Message}");
            return null;
        }
    }

    static string EncryptTripleDES(string plainText, byte[] key)
    {
        using (TripleDESCryptoServiceProvider desAlg = new TripleDESCryptoServiceProvider())
        {
            desAlg.Key = key;
            desAlg.Mode = CipherMode.CBC;
            desAlg.Padding = PaddingMode.PKCS7;

            desAlg.GenerateIV();
            byte[] iv = desAlg.IV;

            ICryptoTransform encryptor = desAlg.CreateEncryptor(desAlg.Key, iv);

            byte[] plainTextBytes = Encoding.UTF8.GetBytes(plainText);
            byte[] cipherTextBytes;

            using (MemoryStream msEncrypt = new MemoryStream())
            {
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    csEncrypt.Write(plainTextBytes, 0, plainTextBytes.Length);
                    csEncrypt.FlushFinalBlock();
                }

                cipherTextBytes = msEncrypt.ToArray();
            }

            byte[] encryptedBytesWithIv = new byte[iv.Length + cipherTextBytes.Length];
            Buffer.BlockCopy(iv, 0, encryptedBytesWithIv, 0, iv.Length);
            Buffer.BlockCopy(cipherTextBytes, 0, encryptedBytesWithIv, iv.Length, cipherTextBytes.Length);

            return Convert.ToBase64String(encryptedBytesWithIv);
        }
    }

    static string DecryptTripleDES(string cipherText, byte[] key)
    {
        try
        {
            byte[] encryptedBytesWithIv = Convert.FromBase64String(cipherText);

            using (TripleDESCryptoServiceProvider desAlg = new TripleDESCryptoServiceProvider())
            {
                desAlg.Key = key;
                desAlg.Mode = CipherMode.CBC;
                desAlg.Padding = PaddingMode.PKCS7;

                byte[] iv = new byte[desAlg.IV.Length];
                byte[] encryptedText = new byte[encryptedBytesWithIv.Length - iv.Length];

                Buffer.BlockCopy(encryptedBytesWithIv, 0, iv, 0, iv.Length);
                Buffer.BlockCopy(encryptedBytesWithIv, iv.Length, encryptedText, 0, encryptedText.Length);

                desAlg.IV = iv;

                ICryptoTransform decryptor = desAlg.CreateDecryptor(desAlg.Key, desAlg.IV);

                byte[] decryptedTextBytes;

                using (MemoryStream msDecrypt = new MemoryStream(encryptedText))
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    decryptedTextBytes = new byte[encryptedText.Length];
                    csDecrypt.Read(decryptedTextBytes, 0, decryptedTextBytes.Length);
                }

                return Encoding.UTF8.GetString(decryptedTextBytes);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"TripleDES Decryption Error: {ex.Message}");
            return null;
        }
    }
}