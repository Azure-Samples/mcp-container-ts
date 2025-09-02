targetScope = 'subscription'

@minLength(1)
@maxLength(64)
@description('Name of the environment that can be used as part of naming resource convention')
param environmentName string

@minLength(1)
@description('Primary location for all resources')
param location string

@description('The JWT audience for auth.')
@secure()
param jwtAudience string
@description('The JWT issuer for auth.')
@secure()
param jwtIssuer string
@description('The JWT expiry for auth.')
@secure()
param jwtExpiry string
@description('The JWT secret for auth.')
@secure()
param jwtSecret string
@description('The JWT token for auth.')
@secure()
param jwtToken string

param mcpServerIngressPort int = 3000

param mcpContainerTsExists bool

// Tags that should be applied to all resources.
// 
// Note that 'azd-service-name' tags should be applied separately to service host resources.
// Example usage:
//   tags: union(tags, { 'azd-service-name': <service name in azure.yaml> })
var tags = {
  'azd-env-name': environmentName
}

// Organize resources in a resource group
resource rg 'Microsoft.Resources/resourceGroups@2021-04-01' = {
  name: 'rg-${environmentName}'
  location: location
  tags: tags
}

module resources 'resources.bicep' = {
  scope: rg
  name: 'resources'
  params: {
    location: location
    tags: tags
    mcpContainerTsExists: mcpContainerTsExists
    jwtAudience: jwtAudience
    jwtIssuer: jwtIssuer
    jwtExpiry: jwtExpiry
    jwtSecret: jwtSecret
    jwtToken: jwtToken
    mcpServerIngressPort: mcpServerIngressPort
  }
}

// ------------------
//    OUTPUT
// ------------------
output AZURE_CONTAINER_REGISTRY_ENDPOINT string = resources.outputs.AZURE_CONTAINER_REGISTRY_ENDPOINT
output AZURE_RESOURCE_MCP_CONTAINER_TS_ID string = resources.outputs.AZURE_RESOURCE_MCP_CONTAINER_TS_ID
output APPLICATIONINSIGHTS_CONNECTION_STRING string = resources.outputs.APPLICATIONINSIGHTS_CONNECTION_STRING
