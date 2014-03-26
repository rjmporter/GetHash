<%@ WebHandler Language="C#" Class="hashstuff" %>
using System.Web;
using Techsmith.CloudServices.Crypto;

public class hashstuff : IHttpHandler {
    
    public void ProcessRequest (HttpContext context) {
        context.Response.ContentType = "application/json";
        var newSecret = context.Request["client_secret"] + context.Request["techsmith_id"];
        context.Response.Write(string.Format("{{\r\n'client_secret':'{0}'\r\n}}",  HashHelper.HashStringWithSHA512(newSecret)));
        context.Response.Flush();
        context.Response.Close();
    }

    public bool IsReusable {
        get {
            return false;
        }
    }
}