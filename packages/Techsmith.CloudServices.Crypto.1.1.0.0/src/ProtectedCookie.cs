using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Web;
using Microsoft.IdentityModel.Web;

namespace Techsmith.CloudServices.Crypto
{
   public static class CookieNames
   {
      public static string Message = "msg";
   }

   // from http://www.leastprivilege.com/ProtectingCookiesOnceAndForAll.aspx
   public class ProtectedCookie : IProtectedCookie
   {
      private readonly List<CookieTransform> _transforms;
      private readonly ChunkedCookieHandler _handler = new ChunkedCookieHandler();

      // RSA protection (load balanced)
      public ProtectedCookie( X509Certificate2 protectionCertificate )
      {
         _transforms = new List<CookieTransform>
                       {
                          new DeflateCookieTransform(), new RsaSignatureCookieTransform( protectionCertificate ),
                          new RsaEncryptionCookieTransform( protectionCertificate )
                       };
      }

      public void Write( string name, string value, DateTime expirationTime )
      {
         byte[] encodedBytes = EncodeCookieValue( value );

         _handler.Write( encodedBytes, name, expirationTime );
      }

      public void Write( string name, string value, DateTime expirationTime, string domain, string path )
      {
         byte[] encodedBytes = EncodeCookieValue( value );

         _handler.Write( encodedBytes, name, path, domain, expirationTime, true, true, HttpContext.Current );
      }

      public string Read( string name )
      {
         byte[] bytes = _handler.Read( name );

         if ( bytes == null || bytes.Length == 0 )
         {
            return null;
         }

         return DecodeCookieValue( bytes );
      }

      public void Delete( string name )
      {
         _handler.Delete( name );
      }

      protected virtual byte[] EncodeCookieValue( string value )
      {
         byte[] bytes = Encoding.UTF8.GetBytes( value );
         byte[] buffer = bytes;

         foreach ( CookieTransform transform in _transforms )
         {
            buffer = transform.Encode( buffer );
         }

         return buffer;
      }

      protected virtual string DecodeCookieValue( byte[] bytes )
      {
         byte[] buffer = bytes;

         for ( int i = _transforms.Count; i > 0; i-- )
         {
            buffer = _transforms[i - 1].Decode( buffer );
         }

         return Encoding.UTF8.GetString( buffer );
      }
   }
}