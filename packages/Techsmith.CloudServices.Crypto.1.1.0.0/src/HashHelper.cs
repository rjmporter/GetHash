using System;
using System.Security.Cryptography;
using System.Text;

namespace Techsmith.CloudServices.Crypto
{
   public static class HashHelper
   {
      public static string HashStringWithSHA512( string str )
      {
         using ( var sha512Hash = new SHA512Managed() )
         {
            byte[] byteBuffer = Encoding.Unicode.GetBytes( str );
            byte[] hashedBytes = sha512Hash.ComputeHash( byteBuffer );
            return BitConverter.ToString( hashedBytes );
         }
      }
   }
}
