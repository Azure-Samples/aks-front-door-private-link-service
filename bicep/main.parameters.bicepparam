using './main.bicep'

param aksClusterNetworkPlugin = 'azure'

param aksClusterNetworkPolicy = 'azure'

param aksClusterPodCidr = '192.168.0.0/16'

param aksClusterServiceCidr = '172.16.0.0/16'

param aksClusterDnsServiceIP = '172.16.0.10'

param aksClusterDockerBridgeCidr = '172.17.0.1/16'

param aksClusterOutboundType = 'userAssignedNATGateway'

param aksClusterKubernetesVersion = '1.24.0'

param aksClusterAdminUsername = 'azadmin'

param aksClusterSshPublicKey = '<ssh-public-key>'

param aadProfileManaged = true

param aadProfileEnableAzureRBAC = true

param aadProfileAdminGroupObjectIDs = [
  '<admins-aad-security-group-object-id>'
]

param systemAgentPoolName = 'system'

param systemAgentPoolVmSize = 'Standard_D4s_v3'

param systemAgentPoolOsDiskSizeGB = 80

param systemAgentPoolAgentCount = 3

param systemAgentPoolMaxCount = 5

param systemAgentPoolMinCount = 3

param systemAgentPoolNodeTaints = [
  'CriticalAddonsOnly=true:NoSchedule'
]

param userAgentPoolName = 'user'

param userAgentPoolVmSize = 'Standard_D4s_v3'

param userAgentPoolOsDiskSizeGB = 80

param userAgentPoolAgentCount = 3

param userAgentPoolMaxCount = 5

param userAgentPoolMinCount = 3

param enableVnetIntegration = true

param virtualNetworkAddressPrefixes = '10.0.0.0/8'

param systemAgentPoolSubnetName = 'SystemSubnet'

param systemAgentPoolSubnetAddressPrefix = '10.240.0.0/16'

param userAgentPoolSubnetName = 'UserSubnet'

param userAgentPoolSubnetAddressPrefix = '10.241.0.0/16'

param podSubnetName = 'PodSubnet'

param podSubnetAddressPrefix = '10.242.0.0/16'

param apiServerSubnetName = 'ApiServerSubnet'

param apiServerSubnetAddressPrefix = '10.243.0.0/27'

param vmSubnetName = 'VmSubnet'

param vmSubnetAddressPrefix = '10.243.1.0/24'

param bastionSubnetAddressPrefix = '10.243.2.0/24'

param logAnalyticsSku = 'PerGB2018'

param logAnalyticsRetentionInDays = 60

param vmName = 'TestVm'

param vmSize = 'Standard_F4s_v2'

param imagePublisher = 'Canonical'

param imageOffer = '0001-com-ubuntu-server-jammy'

param imageSku = '22_04-lts-gen2'

param authenticationType = 'sshPublicKey'

param vmAdminUsername = 'azadmin'

param vmAdminPasswordOrKey = '<ssh-public-key>'

param diskStorageAccounType = 'Premium_LRS'

param numDataDisks = 1

param osDiskSize = 50

param dataDiskSize = 50

param dataDiskCaching = 'ReadWrite'

param aksClusterEnablePrivateCluster = false

param aksEnablePrivateClusterPublicFQDN = false

param podIdentityProfileEnabled = false

param keyVaultObjectIds = [
  '<aad-security-group-or-account-object-id>'
]

param openServiceMeshEnabled = true

param kedaEnabled = true

param daprEnabled = true

param fluxGitOpsEnabled = true

param verticalPodAutoscalerEnabled = true

param deploymentScriptUri = 'https://paolosalvatori.blob.core.windows.net/scripts/install-helm-charts-and-app.sh'

param blobCSIDriverEnabled = true

param diskCSIDriverEnabled = true

param fileCSIDriverEnabled = true

param snapshotControllerEnabled = true

param defenderSecurityMonitoringEnabled = true

param imageCleanerEnabled = true

param imageCleanerIntervalHours = 24

param nodeRestrictionEnabled = true

param workloadIdentityEnabled = true

param oidcIssuerProfileEnabled = true

param hostName = 'httpbin.local'

param namespace = 'httpbin'