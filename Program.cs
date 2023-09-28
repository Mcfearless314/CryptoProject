using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

public class SecretMessage
{
    public byte[] Nonce { init; get; }
    public byte[] Tag { init; get; }
    public byte[] Salt { init; get; }
    public byte[] Cipher { init; get; }
}

class Program
{
    static void Main(string[] args)
    {
        bool breakFlag = true;

        while (breakFlag)
        {
            Console.WriteLine("Select an option:");
            Console.WriteLine("1. Encrypt and save a message to a file");
            Console.WriteLine("2. Read and decrypt a message from a file");
            Console.WriteLine("3. Nevermind, I have no need for secrets");

            string option = Console.ReadLine();

            switch (option)
            {
                case "1":
                    EncryptAndSaveMessage();
                    break;
                case "2":
                    ReadAndDecryptFromFile();
                    break;
                case "3":
                    breakFlag = false;
                    break;
                default:
                    Console.WriteLine("Invalid option. Please choose 1, 2, or 3.");
                    break;
            }
        }
    }

    static void EncryptAndSaveMessage()
    {
        Console.Write("Enter your very very secret key: ");
        string passphrase = Console.ReadLine();

        Console.Write("Enter the message you wish to make ultra secret: ");
        string message = Console.ReadLine();
        Console.Write("Where shall we save this very special ultra secret message: ");
        string outputFile = Console.ReadLine();

        using (Rfc2898DeriveBytes keyDerivation = new Rfc2898DeriveBytes(passphrase, salt: new byte[8], iterations: 10000))
        {
            byte[] key = keyDerivation.GetBytes(16); 

            byte[] nonce = new byte[12];

            using (AesGcm aesGcm = new AesGcm(key))
            {
                byte[] encryptedMessage = new byte[message.Length];
                byte[] authenticationTag = new byte[16];

                aesGcm.Encrypt(nonce, Encoding.UTF8.GetBytes(message), encryptedMessage, authenticationTag);

                using (FileStream fileStream = File.Create(outputFile))
                {
                    fileStream.Write(nonce);
                    fileStream.Write(authenticationTag);
                    fileStream.Write(encryptedMessage);
                }
            }

            Console.WriteLine("Your secret is stored safely in: " + outputFile);
        }
    }

    static void ReadAndDecryptFromFile()
    {
        Console.Write("Enter the very very secret key: ");
        string passphrase = Console.ReadLine();

        Console.Write("Which file do wish to know the secrets of: ");
        string inputFile = Console.ReadLine();

        using (Rfc2898DeriveBytes keyDerivation = new Rfc2898DeriveBytes(passphrase, salt: new byte[8], iterations: 10000))
        {
            byte[] key = keyDerivation.GetBytes(16);

            byte[] receivedNonce = new byte[12];

            try
            {
                using (AesGcm aesGcm = new AesGcm(key))
                using (FileStream fileStream = File.OpenRead(inputFile))
                {
                    byte[] receivedAuthenticationTag = new byte[16];
                    byte[] encryptedMessage = new byte[fileStream.Length - 28]; 

                    fileStream.Read(receivedNonce, 0, 12);
                    fileStream.Read(receivedAuthenticationTag, 0, 16);
                    fileStream.Read(encryptedMessage, 0, encryptedMessage.Length);

                    byte[] decryptedMessage = new byte[encryptedMessage.Length];
                    aesGcm.Decrypt(receivedNonce, encryptedMessage, receivedAuthenticationTag, decryptedMessage);

                    string decryptedText = Encoding.UTF8.GetString(decryptedMessage);
                    Console.WriteLine("Decrypted Message:");
                    Console.WriteLine(decryptedText);
                }
            }
            catch (FileNotFoundException)
            {
                Console.WriteLine("Odd... There is nothing here???");
            }
            catch (Exception)
            {
                Console.WriteLine("Decryption failed. You gave the wrong secret key! Or the file is corrupted... Who knows?");
            }
        }
    }
}
