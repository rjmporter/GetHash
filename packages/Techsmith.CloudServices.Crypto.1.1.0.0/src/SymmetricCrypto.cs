using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Techsmith.CloudServices.Crypto
{
   public class SymmetricCrypto
   {
      private readonly EncryptionKey _key;
      public SymmetricCrypto( EncryptionKey key )
      {
         _key = key;
      }

      public string Encrypt( string toEncrypt )
      {
         using ( SymmetricAlgorithm encryptionAlgorithm = new RijndaelManaged() )
         {
            encryptionAlgorithm.Key = _key.KeyBytes;
            encryptionAlgorithm.GenerateIV();

            using ( var memoryStream = new MemoryStream() )
            {
               using ( var cryptoStream = new CryptoStream( memoryStream, encryptionAlgorithm.CreateEncryptor(), CryptoStreamMode.Write ) )
               {
                  byte[] bytesToEncrypt = Encoding.UTF8.GetBytes( toEncrypt );
                  cryptoStream.Write( bytesToEncrypt, 0, bytesToEncrypt.Length );
               }

               byte[] encryptedValue = memoryStream.ToArray();
               byte[] encryptedValueAndInitializationVector = encryptedValue.Concat( encryptionAlgorithm.IV ).ToArray();

               return Convert.ToBase64String( encryptedValueAndInitializationVector );
            }
         }
      }

      public string Decrypt( string toDecrypt )
      {
         byte[] decryptBytes = Convert.FromBase64String( toDecrypt );
         int initializationVectorLength = 16;
         int encryptedBytesLength = decryptBytes.Length - initializationVectorLength;
         byte[] initializationVector = decryptBytes.Skip( encryptedBytesLength ).ToArray();

         byte[] encryptedBytes = decryptBytes.Take( encryptedBytesLength ).ToArray();

         using ( SymmetricAlgorithm encryptionAlgorithm = new RijndaelManaged() )
         {
            encryptionAlgorithm.Key = _key.KeyBytes;
            encryptionAlgorithm.IV = initializationVector;

            using ( var memoryStream = new MemoryStream( encryptedBytes ) )
            {
               using ( var cryptoStream = new CryptoStream( memoryStream, encryptionAlgorithm.CreateDecryptor(), CryptoStreamMode.Read ) )
               {
                  using ( var streamReader = new StreamReader( cryptoStream, Encoding.UTF8 ) )
                  {
                     return streamReader.ReadToEnd();
                  }
               }
            }
         }
      }
   }
}
