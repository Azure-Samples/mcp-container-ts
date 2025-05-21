targetScope = 'subscription'

@minLength(1)
@maxLength(64)
@description('Name of the environment that can be used as part of naming resource convention')
param environmentName string

@minLength(1)
@description('Primary location for all resources')
param location string

param mcpContainerTsExists bool

// ------------------
//    PARAMETERS APIM
// ------------------

@description('The name of the API Management service instance')
param apiManagementServiceName string = 'apimservice${uniqueString(resourceGroup().id)}'

@description('The pricing tier of this API Management service')
param apim_sku string = 'Basicv2'
param apim_location string = 'uksouth'

@description('The path for the API in the API Management service')
param APIPath string = 'aca-api-path'

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
  }
}
// ------------------
//    RESOURCES APIM
// ------------------

resource apiManagementService 'Microsoft.ApiManagement/service@2024-06-01-preview' = {
  name: apiManagementServiceName
  location: apim_location
  sku: {
    name: apim_sku
    capacity: 1
  }
  properties: {
    publisherEmail: 'noreply@microsoft.com'
    publisherName: 'Microsoft'
  }
  identity: {
    type: 'SystemAssigned'
  }
}

// Creation subscription key for the APIM service
resource apimSubscription 'Microsoft.ApiManagement/service/subscriptions@2024-06-01-preview' = {
  name: 'apim-subscription-key'
  parent: apiManagementService
  properties: {
    allowTracing: true
    displayName: 'Demo-Subscription-Key'
    scope: '/apis'
    state: 'active'
  }
}


module acaAPIModule './apim-api/api.bicep' = {
  name: 'acaAPIModule'
  params: {
    apimServiceName: apiManagementService.name
    APIPath: APIPath
    APIServiceURL: 'https://apim-rocks.azure-api.net/weather' //This should be the URL of the aca endpoint that you want to expose through APIM
  }
}


// ------------------
//    OUTPUT
// ------------------
output AZURE_CONTAINER_REGISTRY_ENDPOINT string = resources.outputs.AZURE_CONTAINER_REGISTRY_ENDPOINT
output AZURE_RESOURCE_MCP_CONTAINER_TS_ID string = resources.outputs.AZURE_RESOURCE_MCP_CONTAINER_TS_ID
