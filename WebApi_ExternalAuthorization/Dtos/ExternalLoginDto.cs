using System;
using WebApi_ExternalAuthorization.Consts;

namespace WebApi_ExternalAuthorization.Dtos
{
    public class ExternalLoginDto
    {
        public string ProviderAccessToken { get; set; }
        public string ProviderKey { get; set; }
        public ExternalLoginProviderType ProviderType { get; set; }
        public string Email { get; set; }
    }
}
