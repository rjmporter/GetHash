using System;

namespace Techsmith.CloudServices.Crypto
{
   public class InitializationVector
   {
      public InitializationVector( byte[] key )
      {
         InitializationVectorBytes = key;
      }

      public InitializationVector( string key )
      {
         InitializationVectorBytes = Convert.FromBase64String( key );
      }

      public byte[] InitializationVectorBytes
      {
         get;
         private set;
      }
   }
}
