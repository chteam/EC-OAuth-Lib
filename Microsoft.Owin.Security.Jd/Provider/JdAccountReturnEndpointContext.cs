
using Microsoft.Owin.Security.Provider;

namespace Microsoft.Owin.Security.Jd.Provider
{
    /// <summary>
    /// Provides context information to middleware providers.
    /// </summary>
    public class JdAccountReturnEndpointContext : ReturnEndpointContext
    {
        /// <summary>
        /// Initializes a new <see cref="JdAccountReturnEndpointContext"/>.
        /// </summary>
        /// <param name="context">OWIN environment</param>
        /// <param name="ticket">The authentication ticket</param>
        public JdAccountReturnEndpointContext(
            IOwinContext context,
            AuthenticationTicket ticket)
            : base(context, ticket)
        {
        }
    }
}
