using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using Microsoft.Owin.Security.Paipai.Provider;

namespace Microsoft.Owin.Security.Paipai
{
    public class PaipaiAccountAuthenticationOptions : AuthenticationOptions
    {
        public PaipaiAccountAuthenticationOptions()
            : base(Constants.DefaultAuthenticationType)
        {
            Caption = Constants.DefaultAuthenticationType;
            CallbackPath = new PathString("/signin-7A77630B");
            AuthenticationMode = AuthenticationMode.Passive;
            DefaultCallBack = string.Format("/Account/ExternalLoginCallback");
            Visibled = false;
        }
        /// <summary>
        /// 是否前台显示
        /// </summary>
        public bool Visibled { get; set; }

        /// <summary>
        /// 显示名称
        /// </summary>
        public string Caption
        {
            get { return Description.Caption; }
            set { Description.Caption = value; }
        }

        /// <summary>
        /// The application client ID assigned by the Jd authentication service.
        /// </summary>
        public string AppKey { get; set; }

        /// <summary>
        /// The application client secret assigned by the Jd authentication service.
        /// </summary>
        public string Secret { get; set; }



        /// <summary>
        /// The request path within the application's base path where the user-agent will be returned.
        /// The middleware will process this request when it arrives.
        /// Default value is "/signin-7A77630B".
        /// </summary>
        public PathString CallbackPath { get; set; }

        /// <summary>
        /// Gets or sets the name of another authentication middleware which will be responsible for actually issuing a user <see cref="System.Security.Claims.ClaimsIdentity"/>.
        /// </summary>
        public string SignInAsAuthenticationType { get; set; }

        /// <summary>
        /// Gets or sets the <see cref="IPaipaiAccountAuthenticationProvider"/> used to handle authentication events.
        /// </summary>
        public IPaipaiAccountAuthenticationProvider Provider { get; set; }

        /// <summary>
        /// Gets or sets the type used to secure data handled by the middleware.
        /// </summary>
        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }

        public string DefaultCallBack { get; set; }
    }
}
