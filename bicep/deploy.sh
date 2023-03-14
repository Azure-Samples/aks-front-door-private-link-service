#!/bin/bash

# Template
template="main.bicep"
parameters="main.parameters.json"

# AKS cluster name
prefix="<Azure-Resource-Name-Prefix>"
aksName="${prefix}Aks"
validateTemplate=1
useWhatIf=0
update=1
installExtensions=0

# Name and location of the resource group for the Azure Kubernetes Service (AKS) cluster
resourceGroupName="${prefix}RG"
location="westeurope"
deploymentName="main"

# Subscription id, subscription name, and tenant id of the current subscription
subscriptionId=$(az account show --query id --output tsv)
subscriptionName=$(az account show --query name --output tsv)
tenantId=$(az account show --query tenantId --output tsv)

# Install aks-preview Azure extension
if [[ $installExtensions == 1 ]]; then
  echo "Checking if [aks-preview] extension is already installed..."
  az extension show --name aks-preview &>/dev/null

  if [[ $? == 0 ]]; then
    echo "[aks-preview] extension is already installed"

    # Update the extension to make sure you have the latest version installed
    echo "Updating [aks-preview] extension..."
    az extension update --name aks-preview &>/dev/null
  else
    echo "[aks-preview] extension is not installed. Installing..."

    # Install aks-preview extension
    az extension add --name aks-preview 1>/dev/null

    if [[ $? == 0 ]]; then
      echo "[aks-preview] extension successfully installed"
    else
      echo "Failed to install [aks-preview] extension"
      exit
    fi
  fi

  # Registering AKS feature extensions
  aksExtensions=(
    "PodSecurityPolicyPreview"
    "KubeletDisk"
    "AKS-KedaPreview"
    "RunCommandPreview"
    "EnablePodIdentityPreview "
    "UserAssignedIdentityPreview"
    "EnablePrivateClusterPublicFQDN"
    "PodSubnetPreview"
    "EnableOIDCIssuerPreview"
    "EnableWorkloadIdentityPreview"
    "EnableImageCleanerPreview"
    "AKS-VPAPreview"
    "AzureOverlayPreview"
    "KubeProxyConfigurationPreview"
  )
  ok=0
  registeringExtensions=()
  for aksExtension in ${aksExtensions[@]}; do
    echo "Checking if [$aksExtension] extension is already registered..."
    extension=$(az feature list -o table --query "[?contains(name, 'Microsoft.ContainerService/$aksExtension') && @.properties.state == 'Registered'].{Name:name}" --output tsv)
    if [[ -z $extension ]]; then
      echo "[$aksExtension] extension is not registered."
      echo "Registering [$aksExtension] extension..."
      az feature register --name $aksExtension --namespace Microsoft.ContainerService
      registeringExtensions+=("$aksExtension")
      ok=1
    else
      echo "[$aksExtension] extension is already registered."
    fi
  done
  echo $registeringExtensions
  delay=1
  for aksExtension in ${registeringExtensions[@]}; do
    echo -n "Checking if [$aksExtension] extension is already registered..."
    while true; do
      extension=$(az feature list -o table --query "[?contains(name, 'Microsoft.ContainerService/$aksExtension') && @.properties.state == 'Registered'].{Name:name}" --output tsv)
      if [[ -z $extension ]]; then
        echo -n "."
        sleep $delay
      else
        echo "."
        break
      fi
    done
  done

  if [[ $ok == 1 ]]; then
    echo "Refreshing the registration of the Microsoft.ContainerService resource provider..."
    az provider register --namespace Microsoft.ContainerService
    echo "Microsoft.ContainerService resource provider registration successfully refreshed"
  fi
fi

# Get the last Kubernetes version available in the region
kubernetesVersion=$(az aks get-versions --location $location --query "orchestrators[?isPreview==false].orchestratorVersion | sort(@) | [-1]" --output tsv)

if [[ -n $kubernetesVersion ]]; then
  echo "Successfully retrieved the last Kubernetes version [$kubernetesVersion] supported by AKS in [$location] Azure region"
else
  echo "Failed to retrieve the last Kubernetes version supported by AKS in [$location] Azure region"
  exit
fi

# Check if the resource group already exists
echo "Checking if [$resourceGroupName] resource group actually exists in the [$subscriptionName] subscription..."

az group show --name $resourceGroupName &>/dev/null

if [[ $? != 0 ]]; then
  echo "No [$resourceGroupName] resource group actually exists in the [$subscriptionName] subscription"
  echo "Creating [$resourceGroupName] resource group in the [$subscriptionName] subscription..."

  # Create the resource group
  az group create --name $resourceGroupName --location $location 1>/dev/null

  if [[ $? == 0 ]]; then
    echo "[$resourceGroupName] resource group successfully created in the [$subscriptionName] subscription"
  else
    echo "Failed to create [$resourceGroupName] resource group in the [$subscriptionName] subscription"
    exit
  fi
else
  echo "[$resourceGroupName] resource group already exists in the [$subscriptionName] subscription"
fi

# Create AKS cluster if does not exist
echo "Checking if [$aksName] aks cluster actually exists in the [$resourceGroupName] resource group..."

az aks show --name $aksName --resource-group $resourceGroupName &>/dev/null
notExists=$?

if [[ $notExists != 0 || $update == 1 ]]; then

  if [[ $notExists != 0 ]]; then
    echo "No [$aksName] aks cluster actually exists in the [$resourceGroupName] resource group"
  else
    echo "[$aksName] aks cluster already exists in the [$resourceGroupName] resource group. Updating the cluster..."
  fi

  # Delete any existing role assignments for the user-defined managed identity of the AKS cluster
  # in case you are re-deploying the solution in an existing resource group
  echo "Retrieving the list of role assignments on [$resourceGroupName] resource group..."
  assignmentIds=$(az role assignment list \
    --scope "/subscriptions/${subscriptionId}/resourceGroups/${resourceGroupName}" \
    --query [].id \
    --output tsv \
    --only-show-errors)

  if [[ -n $assignmentIds ]]; then
    echo "[${#assignmentIds[@]}] role assignments have been found on [$resourceGroupName] resource group"
    for assignmentId in ${assignmentIds[@]}; do
      if [[ -n $assignmentId ]]; then
        az role assignment delete --ids $assignmentId

        if [[ $? == 0 ]]; then
          assignmentName=$(echo $assignmentId | awk -F '/' '{print $NF}')
          echo "[$assignmentName] role assignment on [$resourceGroupName] resource group successfully deleted"
        fi
      fi
    done
  else
    echo "No role assignment actually exists on [$resourceGroupName] resource group"
  fi

  # Get the kubelet managed identity used by the AKS cluster
  echo "Retrieving the kubelet identity from the [$aksName] AKS cluster..."
  clientId=$(az aks show \
    --name $aksName \
    --resource-group $resourceGroupName \
    --query identityProfile.kubeletidentity.clientId \
    --output tsv 2>/dev/null)

  if [[ -n $clientId ]]; then
    # Delete any role assignment to kubelet managed identity on any ACR in the resource group
    echo "kubelet identity of the [$aksName] AKS cluster successfully retrieved"
    echo "Retrieving the list of ACR resources in the [$resourceGroupName] resource group..."
    acrIds=$(az acr list \
      --resource-group $resourceGroupName \
      --query [].id \
      --output tsv)

    if [[ -n $acrIds ]]; then
      echo "[${#acrIds[@]}] ACR resources have been found in [$resourceGroupName] resource group"
      for acrId in ${acrIds[@]}; do
        if [[ -n $acrId ]]; then
          acrName=$(echo $acrId | awk -F '/' '{print $NF}')
          echo "Retrieving the list of role assignments on [$acrName] ACR..."
          assignmentIds=$(az role assignment list \
            --scope "$acrId" \
            --query [].id \
            --output tsv \
            --only-show-errors)

          if [[ -n $assignmentIds ]]; then
            echo "[${#assignmentIds[@]}] role assignments have been found on [$acrName] ACR"
            for assignmentId in ${assignmentIds[@]}; do
              if [[ -n $assignmentId ]]; then
                az role assignment delete --ids $assignmentId

                if [[ $? == 0 ]]; then
                  assignmentName=$(echo $assignmentId | awk -F '/' '{print $NF}')
                  echo "[$assignmentName] role assignment on [$acrName] ACR successfully deleted"
                fi
              fi
            done
          else
            echo "No role assignment actually exists on [$acrName] ACR"
          fi
        fi
      done
    else
      echo "No ACR actually exists in [$resourceGroupName] resource group"
    fi
  else
    echo "No kubelet identity exists for the [$aksName] AKS cluster"
  fi

  # Validate the Bicep template
  if [[ $validateTemplate == 1 ]]; then
    if [[ $useWhatIf == 1 ]]; then
      # Execute a deployment What-If operation at resource group scope.
      echo "Previewing changes deployed by [$template] Bicep template..."
      az deployment group what-if \
        --resource-group $resourceGroupName \
        --template-file $template \
        --parameters $parameters \
        --parameters prefix=$prefix \
        location=$location \
        aksClusterKubernetesVersion=$kubernetesVersion

      if [[ $? == 0 ]]; then
        echo "[$template] Bicep template validation succeeded"
      else
        echo "Failed to validate [$template] Bicep template"
        exit
      fi
    else
      # Validate the Bicep template
      echo "Validating [$template] Bicep template..."
      output=$(az deployment group validate \
        --resource-group $resourceGroupName \
        --template-file $template \
        --parameters $parameters \
        --parameters prefix=$prefix \
        location=$location \
        aksClusterKubernetesVersion=$kubernetesVersion)

      if [[ $? == 0 ]]; then
        echo "[$template] Bicep template validation succeeded"
      else
        echo "Failed to validate [$template] Bicep template"
        echo $output
        exit
      fi
    fi
  fi

  # Deploy the Bicep template
  echo "Deploying [$template] Bicep template..."
  az deployment group create \
    --name $deploymentName \
    --resource-group $resourceGroupName \
    --only-show-errors \
    --template-file $template \
    --parameters $parameters \
    --parameters prefix=$prefix \
    location=$location \
    aksClusterKubernetesVersion=$kubernetesVersion 1>/dev/null

  if [[ $? == 0 ]]; then
    echo "[$template] Bicep template successfully provisioned"
  else
    echo "Failed to provision the [$template] Bicep template"
    exit
  fi
else
  echo "[$aksName] aks cluster already exists in the [$resourceGroupName] resource group"
fi

# Create AKS cluster if does not exist
echo "Checking if [$aksName] aks cluster actually exists in the [$resourceGroupName] resource group..."

az aks show --name $aksName --resource-group $resourceGroupName &>/dev/null

if [[ $? != 0 ]]; then
  echo "No [$aksName] aks cluster actually exists in the [$resourceGroupName] resource group"
  exit
fi

# Get the user principal name of the current user
echo "Retrieving the user principal name of the current user from the [$tenantId] Azure AD tenant..."
userPrincipalName=$(az account show --query user.name --output tsv)
if [[ -n $userPrincipalName ]]; then
  echo "[$userPrincipalName] user principal name successfully retrieved from the [$tenantId] Azure AD tenant"
else
  echo "Failed to retrieve the user principal name of the current user from the [$tenantId] Azure AD tenant"
  exit
fi

# Retrieve the objectId of the user in the Azure AD tenant used by AKS for user authentication
echo "Retrieving the objectId of the [$userPrincipalName] user principal name from the [$tenantId] Azure AD tenant..."
userObjectId=$(az ad user show --id $userPrincipalName --query id --output tsv 2>/dev/null)

if [[ -n $userObjectId ]]; then
  echo "[$userObjectId] objectId successfully retrieved for the [$userPrincipalName] user principal name"
else
  echo "Failed to retrieve the objectId of the [$userPrincipalName] user principal name"
  exit
fi

# Retrieve the resource id of the AKS cluster
echo "Retrieving the resource id of the [$aksName] AKS cluster..."
aksClusterId=$(az aks show \
  --name "$aksName" \
  --resource-group "$resourceGroupName" \
  --query id \
  --output tsv 2>/dev/null)

if [[ -n $aksClusterId ]]; then
  echo "Resource id of the [$aksName] AKS cluster successfully retrieved"
else
  echo "Failed to retrieve the resource id of the [$aksName] AKS cluster"
  exit
fi

# Assign Azure Kubernetes Service RBAC Cluster Admin role to the current user
role="Azure Kubernetes Service RBAC Cluster Admin"
echo "Checking if [$userPrincipalName] user has been assigned to [$role] role on the [$aksName] AKS cluster..."
current=$(az role assignment list \
  --assignee $userObjectId \
  --scope $aksClusterId \
  --query "[?roleDefinitionName=='$role'].roleDefinitionName" \
  --output tsv 2>/dev/null)

if [[ $current == "Owner" ]] || [[ $current == "Contributor" ]] || [[ $current == "$role" ]]; then
  echo "[$userPrincipalName] user is already assigned to the [$current] role on the [$aksName] AKS cluster"
else
  echo "[$userPrincipalName] user is not assigned to the [$role] role on the [$aksName] AKS cluster"
  echo "Assigning the [$userPrincipalName] user to the [$role] role on the [$aksName] AKS cluster..."

  az role assignment create \
    --role "$role" \
    --assignee $userObjectId \
    --scope $aksClusterId \
    --only-show-errors 1>/dev/null

  if [[ $? == 0 ]]; then
    echo "[$userPrincipalName] user successfully assigned to the [$role] role on the [$aksName] AKS cluster"
  else
    echo "Failed to assign the [$userPrincipalName] user to the [$role] role on the [$aksName] AKS cluster"
    exit
  fi
fi

# Assign Azure Kubernetes Service Cluster Admin Role role to the current user
role="Azure Kubernetes Service Cluster Admin Role"
echo "Checking if [$userPrincipalName] user has been assigned to [$role] role on the [$aksName] AKS cluster..."
current=$(az role assignment list \
  --assignee $userObjectId \
  --scope $aksClusterId \
  --query "[?roleDefinitionName=='$role'].roleDefinitionName" \
  --output tsv 2>/dev/null)

if [[ $current == "Owner" ]] || [[ $current == "Contributor" ]] || [[ $current == "$role" ]]; then
  echo "[$userPrincipalName] user is already assigned to the [$current] role on the [$aksName] AKS cluster"
else
  echo "[$userPrincipalName] user is not assigned to the [$role] role on the [$aksName] AKS cluster"
  echo "Assigning the [$userPrincipalName] user to the [$role] role on the [$aksName] AKS cluster..."

  az role assignment create \
    --role "$role" \
    --assignee $userObjectId \
    --scope $aksClusterId \
    --only-show-errors 1>/dev/null

  if [[ $? == 0 ]]; then
    echo "[$userPrincipalName] user successfully assigned to the [$role] role on the [$aksName] AKS cluster"
  else
    echo "Failed to assign the [$userPrincipalName] user to the [$role] role on the [$aksName] AKS cluster"
    exit
  fi
fi

# Get the FQDN of the Azure Front Door endpoint
azureFrontDoorEndpointFqdn=$(az deployment group show \
	--name $deploymentName \
	--resource-group $resourceGroupName \
	--query properties.outputs.frontDoorEndpointFqdn.value \
	--output tsv)

if [[ -n $azureFrontDoorEndpointFqdn ]]; then
	echo "FQDN of the Azure Front Door endpoint: $azureFrontDoorEndpointFqdn"
else
	echo "Failed to get the FQDN of the Azure Front Door endpoint"
	exit -1
fi

# Get the private link service name
privateLinkServiceName=$(az deployment group show \
	--name $deploymentName \
	--resource-group $resourceGroupName \
	--query properties.outputs.privateLinkServiceName.value \
	--output tsv)

if [[ -z $privateLinkServiceName ]]; then
	echo "Failed to get the private link service name"
	exit -1
fi

# Get the resource id of the Private Endpoint Connection
privateEndpointConnectionId=$(az network private-endpoint-connection list \
	--name $privateLinkServiceName \
	--resource-group $resourceGroupName \
	--type Microsoft.Network/privateLinkServices \
	--query [0].id \
	--output tsv)

if [[ -n $privateEndpointConnectionId ]]; then
	echo "Resource id of the Private Endpoint Connection: $privateEndpointConnectionId"
else
	echo "Failed to get the resource id of the Private Endpoint Connection"
	exit -1
fi

# Approve the private endpoint connection
echo "Approving [$privateEndpointConnectionId] private endpoint connection ID..."
az network private-endpoint-connection approve \
	--name $privateLinkServiceName \
	--resource-group $resourceGroupName \
	--id $privateEndpointConnectionId \
	--description "Approved" 1>/dev/null

if [[ $? == 0 ]]; then
	echo "[$privateEndpointConnectionId] private endpoint connection ID successfully approved"
else
	echo "Failed to approve [$privateEndpointConnectionId] private endpoint connection ID"
	exit -1
fi
