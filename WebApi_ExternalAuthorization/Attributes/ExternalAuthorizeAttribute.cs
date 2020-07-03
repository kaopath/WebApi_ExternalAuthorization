using System;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc.Filters;
using Newtonsoft.Json.Linq;
using WebApi_ExternalAuthorization.Consts;
using WebApi_ExternalAuthorization.Dtos;

namespace WebApi_ExternalAuthorization.Attributes
{
    public class ExternalAuthorizeAttribute : Attribute, IAsyncActionFilter
    {
        public async Task OnActionExecutionAsync(
            ActionExecutingContext context,
            ActionExecutionDelegate next)
        {
            ExternalLoginDto info = null;
            foreach (var argument in context.ActionArguments.Values.Where(v => v is ExternalLoginDto || v is string))
            {
                if (argument is ExternalLoginDto)
                {
                    info = argument as ExternalLoginDto;
                }
            }
            if (info == null)
            {
                throw new Exception("Parameter missing.");
            }

            if (string.IsNullOrEmpty(info.ProviderAccessToken))
            {
                throw new Exception("Provider token empty or null");
            }

            await VerifyExternalAccessToken(info);

            var resultContext = await next();
        }

        private async Task VerifyExternalAccessToken(ExternalLoginDto info)
        {
            if (string.IsNullOrEmpty(info.ProviderAccessToken))
            {
                throw new Exception("NoProviderAccessTokenSuplied");
            }

            if (string.IsNullOrEmpty(info.ProviderKey))
            {
                throw new Exception("NoProviderUserIdSuplied");
            }

            string verifyTokenEndPoint;
            bool isValid = false;
            if (info.ProviderType == ExternalLoginProviderType.Facebook)
            {
                //You can get it from here: https://developers.facebook.com/tools/accesstoken/
                //More about debug_tokn here: http://stackoverflow.com/questions/16641083/how-does-one-get-the-app-access-token-for-debug-token-inspection-on-facebook
                var appToken = "";// _configService.GetValue<string>("Authentication:Facebook:AppToken");
                verifyTokenEndPoint = string.Format("https://graph.facebook.com/debug_token?input_token={0}&access_token={1}", info.ProviderAccessToken, appToken);
            }
            else if (info.ProviderType == ExternalLoginProviderType.Google)
            {
                verifyTokenEndPoint = string.Format("https://oauth2.googleapis.com/tokeninfo?id_token={0}", info.ProviderAccessToken);
            }
            else
            {
                throw new Exception("NotSupportedExternalProvider");
            }

            var client = new HttpClient();
            var uri = new Uri(verifyTokenEndPoint);
            HttpResponseMessage response;
            try
            {
                response = await client.GetAsync(uri);
            }
            catch (Exception ex)
            {
                throw new Exception(string.Format("ErrorDuringValidatingExternalProvider_ErrorDetail{0}", ex.Message));
            }

            if (response.IsSuccessStatusCode)
            {
                var content = await response.Content.ReadAsStringAsync();

                if (string.IsNullOrEmpty(content))
                {
                    throw new Exception("ProviderUrlReturnedNoResult");
                }

                JObject jObj = (JObject)Newtonsoft.Json.JsonConvert.DeserializeObject(content);


                if (info.ProviderType == ExternalLoginProviderType.Facebook)
                {
                    //if (string.Equals(_configService.GetValue<string>("Authentication:Facebook:AppId"), (string)jObj.SelectToken("data.app_id"), StringComparison.OrdinalIgnoreCase))
                    //{
                    //    if (string.Equals(userId, (string)jObj.SelectToken("data.user_id"), StringComparison.OrdinalIgnoreCase))
                    //    {
                    //        isValid = true;
                    //    }
                    //}
                }
                else if (info.ProviderType == ExternalLoginProviderType.Google)
                {
                    if (string.Equals(info.ProviderKey, (string)jObj.SelectToken("sub"), StringComparison.OrdinalIgnoreCase) &&
                        ((string)jObj.SelectToken("iss")).Contains("accounts.google.com", StringComparison.OrdinalIgnoreCase))
                    {

                        if (!string.Equals(info.Email, (string)jObj.SelectToken("email"), StringComparison.OrdinalIgnoreCase))
                        {
                            throw new Exception("EmailShouldNotBeModifiedWhichComingFromAProviderLikeGoogleFacebookEtc");
                        }

                        if (!(bool)jObj.SelectToken("email_verified"))
                        {
                            throw new Exception("PleaseUseAnAlreadyConfirmedEmailWhichComingFromAProviderLikeGoogleFacebookEtc");
                        }
                        isValid = true;
                    }
                }

            }
            if (!isValid)
            {
                throw new Exception(string.Format("ProviderUserIsNotAuthorized_AccessTokenLengthIs{0}", info.ProviderAccessToken.Length));
            }
        }
    }
}
