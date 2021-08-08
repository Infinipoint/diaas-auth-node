<!--
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2020 ForgeRock AS.
-->
# Infinipoint DIaaS (Device-Identity-as-a-Service)

A Infinipoint DIaaS authentication node for ForgeRock's [Identity Platform][forgerock_platform] 7.0.0 and above. 
This node allows including device identity and security posture check as part of the ForgeRock authentication flow.


**Installation**

Copy the .jar file from the ../target directory into the ../web-container/webapps/openam/WEB-INF/lib directory where AM is deployed.  Restart the web container to pick up the new node.  The node will then appear in the authentication trees components palette.


**To Build**

The code in this repository has binary dependencies that live in the ForgeRock maven repository. Maven can be configured to authenticate to this repository by following the following [ForgeRock Knowledge Base Article](https://backstage.forgerock.com/knowledge/kb/article/a74096897).

**USAGE**

To configure the node in Infinipoint console, open "Identity Providers" ("Device Identitiy" -> "Configuration" -> "Identity Providers" tab) and select "Forgerock".

Provide "Client ID", "Redirect URI" and click "Create Integration":
![ScreenShot](./images/inf-conf-a.png)

On successful integration, the "Client Secret" and "Realm Alias" are generated:
![ScreenShot](./images/inf-conf-b.png)

Configure your authentication tree using the Infinipoint DIaaS authentication node, for example:

![ScreenShot](./images/auth-tree.png)

To configure the node, copy 'Client ID', 'Client Secret' and 'Realm Alias' from Infinipoint's console.

![ScreenShot](./images/config.png)

When redirected to Infinipoint, device posture is checked and presented to user:

![ScreenShot](./images/issues.png)
In case of no issues found or device posture approved:

![ScreenShot](./images/approved.png)


**Downstream Nodes Attributes**

This plugin doesn't set any special attributes for downstream nodes.



**Disclaimer**
        
The sample code described herein is provided on an "as is" basis, without warranty of any kind, to the fullest extent permitted by law. ForgeRock does not warrant or guarantee the individual success developers may have in implementing the sample code on their development platforms or in production configurations.

ForgeRock does not warrant, guarantee or make any representations regarding the use, results of use, accuracy, timeliness or completeness of any data or information relating to the sample code. ForgeRock disclaims all warranties, expressed or implied, and in particular, disclaims all warranties of merchantability, and warranties related to the code, or any service or software related thereto.

ForgeRock shall not be liable for any direct, indirect or consequential damages or costs of any type arising out of any action taken by you or others related to the sample code.

[forgerock_platform]: https://www.forgerock.com/platform/  
