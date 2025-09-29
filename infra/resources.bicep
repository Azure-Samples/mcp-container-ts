@description('The location used for all deployed resources')
param location string = resourceGroup().location

@description('Tags that will be applied to all resources')
param tags object = {}

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

var abbrs = loadJsonContent('./abbreviations.json')
var resourceToken = uniqueString(subscription().id, resourceGroup().id, location)

// Monitor application with Azure Monitor
module monitoring 'br/public:avm/ptn/azd/monitoring:0.1.0' = {
  name: 'monitoring'
  params: {
    logAnalyticsName: '${abbrs.operationalInsightsWorkspaces}${resourceToken}'
    applicationInsightsName: '${abbrs.insightsComponents}${resourceToken}'
    applicationInsightsDashboardName: '${abbrs.portalDashboards}${resourceToken}'
    location: location
    tags: tags
  }
}

// Container registry
module containerRegistry 'br/public:avm/res/container-registry/registry:0.1.1' = {
  name: 'registry'
  params: {
    name: '${abbrs.containerRegistryRegistries}${resourceToken}'
    location: location
    tags: tags
    publicNetworkAccess: 'Enabled'
    roleAssignments:[
      {
        principalId: mcpContainerTsIdentity.outputs.principalId
        principalType: 'ServicePrincipal'
        roleDefinitionIdOrName: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '7f951dda-4ed3-4680-a7ca-43fe172d538d')
      }
    ]
  }
}

// Container apps environment
module containerAppsEnvironment 'br/public:avm/res/app/managed-environment:0.4.5' = {
  name: 'container-apps-environment'
  params: {
    logAnalyticsWorkspaceResourceId: monitoring.outputs.logAnalyticsWorkspaceResourceId
    name: '${abbrs.appManagedEnvironments}${resourceToken}'
    location: location
    zoneRedundant: false
  }
}

module mcpContainerTsIdentity 'br/public:avm/res/managed-identity/user-assigned-identity:0.2.1' = {
  name: 'mcpContainerTsidentity'
  params: {
    name: '${abbrs.managedIdentityUserAssignedIdentities}mcpContainerTs-${resourceToken}'
    location: location
  }
}

module mcpContainerTsFetchLatestImage './modules/fetch-container-image.bicep' = {
  name: 'mcpContainerTs-fetch-image'
  params: {
    exists: mcpContainerTsExists
    name: 'mcp-container-ts'
  }
}

module mcpContainerTs 'br/public:avm/res/app/container-app:0.16.0' = {
  name: 'mcpContainerTs'
  params: {
    name: 'mcp-container-ts'
    ingressTargetPort: mcpServerIngressPort
    scaleSettings: {
      minReplicas: 1
      maxReplicas: 10
    }
    secrets: [
      {
        name: 'jwt-audience'
        value: jwtAudience
      }
      {
        name: 'jwt-issuer'
        value: jwtIssuer
      }
      {
        name: 'jwt-expiry'
        value: jwtExpiry
      }
      {
        name: 'jwt-secret'
        value: jwtSecret
      }
      {
        name: 'jwt-token'
        value: jwtToken
      }
    ]
    containers: [
      {
        image: mcpContainerTsFetchLatestImage.outputs.?containers[?0].?image ?? 'mcr.microsoft.com/azuredocs/containerapps-helloworld:latest'
        name: 'main'
        resources: {
          cpu: json('0.5')
          memory: '1.0Gi'
        }
        env: [
          {
            name: 'APPLICATIONINSIGHTS_CONNECTION_STRING'
            value: monitoring.outputs.applicationInsightsConnectionString
          }
          {
            name: 'AZURE_CLIENT_ID'
            value: mcpContainerTsIdentity.outputs.clientId
          }
          {
            name: 'PORT'
            value: '${mcpServerIngressPort}'
          }
          {
            name: 'JWT_AUDIENCE'
            secretRef: 'jwt-audience'
          }
          {
            name: 'JWT_ISSUER'
            secretRef: 'jwt-issuer'
          }
          {
            name: 'JWT_EXPIRY'
            secretRef: 'jwt-expiry'
          }
          {
            name: 'JWT_SECRET'
            secretRef: 'jwt-secret'
          }
          {
            name: 'JWT_TOKEN'
            secretRef: 'jwt-token'
          }
          {
            name: 'DEBUG'
            value: '*'
          }
        ]
      }
    ]
    managedIdentities:{
      systemAssigned: false
      userAssignedResourceIds: [mcpContainerTsIdentity.outputs.resourceId]
    }
    registries:[
      {
        server: containerRegistry.outputs.loginServer
        identity: mcpContainerTsIdentity.outputs.resourceId
      }
    ]
    environmentResourceId: containerAppsEnvironment.outputs.resourceId
    location: location
    tags: union(tags, { 'azd-service-name': 'mcp-container-ts' })
  }
}

output AZURE_CONTAINER_REGISTRY_ENDPOINT string = containerRegistry.outputs.loginServer
output AZURE_RESOURCE_MCP_CONTAINER_TS_ID string = mcpContainerTs.outputs.resourceId
output APPLICATIONINSIGHTS_CONNECTION_STRING string = monitoring.outputs.applicationInsightsConnectionString
