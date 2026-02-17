import { getEnvironmentVariable } from "./env";

const clientId = getEnvironmentVariable("VITE_MICROSOFT_OAUTH_CLIENT_ID");
const tenantId = getEnvironmentVariable("VITE_MICROSOFT_OAUTH_TENANT_ID");

export const microsoftOAuthConfiguration = {
  auth: {
    clientId,
    ...(tenantId && {
      authority: `https://login.microsoftonline.com/${tenantId}/`
    })
  }
};
