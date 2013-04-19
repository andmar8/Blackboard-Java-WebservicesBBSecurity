/*
    Blackboard WebServices Security
    Copyright (C) 2011-2013 Andrew Martin, Newcastle University

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package bbws.util.security;

//bbws
import bbws.util.security.properties.WebServiceProperties;

//java
import java.net.URI;

public abstract class DefaultWSSecurity implements WSSecurityUtil
{
    protected WebServiceProperties wsp;
    protected long oauthRequestTimeout; //seconds

    protected Boolean usingSSL(URI baseuri)
    {
        return baseuri.getScheme().matches("https");
    }

    /**
     *
     * @param provider
     * @param requestMethod
     * @param resource - The resource is the name of the method being called
     */
    protected void authenticateRequest(Provider provider,String requestMethod,String resource) throws Exception
    {
        if(!provider.validateOAuth(requestMethod,resource))
        {
            System.err.println("Access Denied: "+resource);
            throw new Exception("Access Denied");
        }
    }

    /**
     * Checks if a user is using ssl if they must be; also checks
     * if the method is set to be useable
     * @param requestUsesSSL
     * @param mag
     * @param methodName
     * @throws WebApplicationException
     */
    protected void authoriseMethodUse(Boolean requestUsesSSL,String mag,String methodName) throws Exception
    {
        //If we're not using ssl and the method requires it OR the method is not accessible, then disallow access
        if((!requestUsesSSL&&wsp.doesMethodRequireSSL(mag,methodName))||!this.wsp.isMethodAccessible(mag,methodName))
        {
            System.err.println("Access Denied: "+methodName+" for "+mag);
            throw new Exception("UNAUTHORIZED");
        }
    }
}
