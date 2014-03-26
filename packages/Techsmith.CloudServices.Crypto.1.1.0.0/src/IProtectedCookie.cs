using System;

namespace Techsmith.CloudServices.Crypto
{
   public interface IProtectedCookie
   {
      void Write(string name, string value, DateTime expirationTime);
      void Write(string name, string value, DateTime expirationTime, string domain, string path);
      string Read(string name);
      void Delete(string name);
   }
}
