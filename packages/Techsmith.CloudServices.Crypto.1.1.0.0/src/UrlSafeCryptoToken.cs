using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.Specialized;

namespace Techsmith.CloudServices.Crypto
{
   public class UrlSafeCryptoToken : CryptoToken
   {
      private static readonly string SafePlusSign = "-";
      private static readonly string SafeSlash = "_";
      private static readonly string PlusSign = "+";
      private static readonly string Slash = "/";

      [Obsolete( "This constructor is obsolete, IntitializationVector is now Randomized" )]
      public UrlSafeCryptoToken( string urlSafeTokenString, EncryptionKey encryptionKey, InitializationVector initializationVector )
         : base( ConvertUrlSafeTokenStringToNormalCryptoTokenString( urlSafeTokenString ), encryptionKey, initializationVector )
      {
      }

      public UrlSafeCryptoToken( string urlSafeTokenString, EncryptionKey encryptionKey )
         : base( ConvertUrlSafeTokenStringToNormalCryptoTokenString( urlSafeTokenString ), encryptionKey )
      {
      }

      public UrlSafeCryptoToken( NameValueCollection nameValueCollection, EncryptionKey encryptionKey, DateTime expiration ) :
         base( nameValueCollection, encryptionKey, expiration )
      {
      }

      public UrlSafeCryptoToken( IDictionary<string, string> dictionary, EncryptionKey encryptionKey, DateTime expiration ) :
         base( dictionary, encryptionKey, expiration )
      {
      }

      private static string ConvertUrlSafeTokenStringToNormalCryptoTokenString( string urlSafeTokenString )
      {
         return urlSafeTokenString.Replace( SafePlusSign, PlusSign ).Replace( SafeSlash, Slash );
      }

      private static string ConvertCryptoTokenStringToUrlSafeTokenString( string cryptoTokenString )
      {
         return cryptoTokenString.Replace( PlusSign, SafePlusSign ).Replace( Slash, SafeSlash );
      }

      public override string GetEncryptedToken()
      {
         var baseEncryptedString = base.GetEncryptedToken();
         return ConvertCryptoTokenStringToUrlSafeTokenString( baseEncryptedString );
      }
   }
}
