using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Dynamic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using Newtonsoft.Json;

namespace Techsmith.CloudServices.Crypto
{
   public class CryptoToken
   {
      private bool _isValid = true;
      private EncryptionKey _encryptionKey;

      public DateTime ExpirationDate
      {
         get;
         private set;
      }

      public bool IsValidAndUnexpired
      {
         get
         {
            return _isValid && !IsExpired();
         }
      }

      public IDictionary<string, string> DictionaryContents
      {
         get;
         private set;
      }


      private bool IsExpired()
      {
         if ( DateTime.UtcNow > ExpirationDate )
         {
            return true;
         }

         return false;
      }

      public CryptoToken( NameValueCollection nameValueCollection, EncryptionKey encryptionKey, DateTime expiration )
      {
         DictionaryContents = BuildDictionaryFromNameValueCollection( nameValueCollection );

         _encryptionKey = encryptionKey;
         ExpirationDate = expiration;
      }

      public CryptoToken( IDictionary<string, string> dictionary, EncryptionKey encryptionKey, DateTime expiration )
      {
         DictionaryContents = new Dictionary<string, string>( dictionary );

         _encryptionKey = encryptionKey;
         ExpirationDate = expiration;
      }

      public CryptoToken( string encryptedToken, EncryptionKey encryptionKey, InitializationVector initializationVector = null )
      {
         _encryptionKey = encryptionKey;

         if ( !string.IsNullOrEmpty( encryptedToken ) )
         {
            var encryptor = new SymmetricCrypto( _encryptionKey );
            string plainTokenText = string.Empty;

            try
            {
               if ( initializationVector != null )
               {
                  byte[] encryptedValue = Convert.FromBase64String( encryptedToken );
                  byte[] encryptedValueAndInitializationVector = encryptedValue.Concat( initializationVector.InitializationVectorBytes ).ToArray();
                  plainTokenText = encryptor.Decrypt( Convert.ToBase64String( encryptedValueAndInitializationVector )  );
               }
               else
               {
                  plainTokenText = encryptor.Decrypt( encryptedToken );
               }
      
            }
            catch ( CryptographicException )
            {
               _isValid = false;
               // CryptoException generally indicates the enc key/padding was wrong and that probably means someone (evil) tried to make up a crypto token.
            }
            catch ( FormatException )
            {
               _isValid = false;
               // FormatException indicates that the encrypted string value provided by the user was not a Base64-encoded string
            }
            catch ( ArgumentNullException )
            {
               _isValid = false;
               // ArgumentNullException indicates that something went wrong when trying to read the Cryptographic token likely due to the length being incorrect.
            }

            if ( _isValid )
            {
                  DictionaryContents = JsonConvert.DeserializeObject<Dictionary<string, string>>( plainTokenText );

                  if ( DictionaryContents.Keys.Contains( "expirationdate" ) )
                  {
                     ExpirationDate = new DateTime( Int64.Parse( DictionaryContents["expirationdate"].ToString() ) );
                     DictionaryContents.Remove( "expirationdate" );
                  }
            }
         }
      }

      private static Dictionary<string, string> BuildDictionaryFromNameValueCollection( NameValueCollection nameValueCollection )
      {
         return nameValueCollection.Cast<string>().Select( s => new
                                                                  {
                                                                     Key = s,
                                                                     Value = nameValueCollection[s]
                                                                  } ).ToDictionary( p => p.Key, p => p.Value );
      }

      private static NameValueCollection BuildNameValueCollectionFromDictionary(IEnumerable<KeyValuePair<string, string>> dictionary)
      {
         var nameValuePairs = new NameValueCollection();

         if ( dictionary != null )
         {
            foreach ( var kvp in dictionary )
            {
               nameValuePairs.Add( kvp.Key.ToString(), kvp.Value.ToString() );
            }
         }

         return nameValuePairs;
      }

      public virtual string GetEncryptedToken()
      {
         var tokenText = new StringBuilder();

         if ( DictionaryContents != null && DictionaryContents.Count > 0 )
         {
            if ( !DictionaryContents.Keys.Contains("expirationdate") )
            {
               DictionaryContents.Add("expirationdate", ExpirationDate.Ticks.ToString());
            }
            tokenText = new StringBuilder( JsonConvert.SerializeObject( DictionaryContents ) );
         }

         var encryptor = new SymmetricCrypto( _encryptionKey );
         return encryptor.Encrypt( tokenText.ToString() );
      }

      public virtual string GetLinkWithTokenAsOnlyQueryStringParameter( UriBuilder uriBase, string parameterName )
      {
         return uriBase.Uri + "?" + parameterName + "=" + HttpUtility.UrlEncode( GetEncryptedToken() );
      }

      public NameValueCollection GetNameValuePairs()
      {
         return BuildNameValueCollectionFromDictionary( DictionaryContents );
      }

      public IDictionary<string, string> GetDictionaryContents()
      {
         return DictionaryContents;
      }

      public dynamic GetJsonObject()
      {
         var dynamicToReturn = new ExpandoObject();
         foreach ( var dictionaryEntry in DictionaryContents )
         {
            ( (ICollection<KeyValuePair<string, object>>) dynamicToReturn ).Add( new KeyValuePair<string, object>( dictionaryEntry.Key, dictionaryEntry.Value ) );
         }

         return dynamicToReturn;
      }
   }
}