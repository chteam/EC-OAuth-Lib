
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Claims;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;

namespace Microsoft.Owin.Security.Jd.Provider
{
    /// <summary>
    /// Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.
    /// </summary>
    public class JdAccountAuthenticatedContext : BaseContext
    {
        /// <summary>
        /// Initializes a <see cref="JdAccountAuthenticatedContext"/>
        /// </summary>
        /// <param name="context">The OWIN environment</param>
        /// <param name="accessToken">Access token</param>
        /// <param name="refreshToken">refresh_token</param>
        /// <param name="expires">Seconds until expiration</param>
        /// <param name="uid">京东UID</param>
        /// <param name="userNick">京东user_nick</param>
        public JdAccountAuthenticatedContext(IOwinContext context,string accessToken, 
            string refreshToken, string expires,string uid,string userNick)
            : base(context)
        {
            
          
         
            AccessToken = accessToken;
            RefreshToken = refreshToken;

            int expiresValue;
            if (Int32.TryParse(expires, NumberStyles.Integer, CultureInfo.InvariantCulture, out expiresValue))
            {
                ExpiresIn = TimeSpan.FromSeconds(expiresValue);
            }



            Id = uid;//userId.ToString();

            Name = userNick;



        }

        /// <summary>
        /// Gets the access token provided by the Jd authenication service
        /// </summary>
        public string AccessToken { get; private set; }

        /// <summary>
        /// Gets the refresh token provided by Jd authentication service
        /// </summary>
        /// <remarks>
        /// Refresh token is only available when wl.offline_access is request.
        /// Otherwise, it is null.
        /// </remarks>
        public string RefreshToken { get; private set; }

        /// <summary>
        /// Gets the Jd access token expiration time
        /// </summary>
        public TimeSpan? ExpiresIn { get; set; }

        /// <summary>
        /// Gets the Jd Account user ID
        /// </summary>
        public string Id { get; private set; }

        /// <summary>
        /// Gets the user name
        /// </summary>
        public string Name { get; private set; }

 
 

        /// <summary>
        /// Gets the <see cref="ClaimsIdentity"/> representing the user
        /// </summary>
        public ClaimsIdentity Identity { get; set; }

        /// <summary>
        /// Gets or sets a property bag for common authentication properties
        /// </summary>
        public AuthenticationProperties Properties { get; set; }
 
    }
}
