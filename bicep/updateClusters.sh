#!/bin/bash

clusters=("MiaAks" "SallyAks" "EdwardAks" "KaluaAks" "BabosbirdAks" "SethAks")
resourceGroupNames=("MiaRG" "SallyRG" "EdwardRG" "KaluaRG" "BabosbirdRG" "SethRG")

for ((i = 0; i < ${#clusters[@]}; i++)); do
  az aks update --resource-group ${resourceGroupNames[$i]} --name ${clusters[$i]} --enable-vpa
done
