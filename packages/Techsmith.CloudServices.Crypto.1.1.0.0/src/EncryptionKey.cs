using System;

namespace Techsmith.CloudServices.Crypto
{
   public class EncryptionKey
   {
      public EncryptionKey( byte[] key )
      {
         KeyBytes = key;
      }

      public EncryptionKey( string key )
      {
         KeyBytes = Convert.FromBase64String( key );
      }

      public byte[] KeyBytes
      {
         get;
         private set;
      }
   }
}
